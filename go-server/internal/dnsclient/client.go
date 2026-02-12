package dnsclient

import (
        "context"
        "encoding/json"
        "fmt"
        "io"
        "log/slog"
        "net"
        "net/http"
        "net/url"
        "sort"
        "strings"
        "sync"
        "time"

        "github.com/miekg/dns"
)

type ResolverConfig struct {
        Name string
        IP   string
        DoH  string
}

var DefaultResolvers = []ResolverConfig{
        {Name: "Cloudflare", IP: "1.1.1.1", DoH: "https://cloudflare-dns.com/dns-query"},
        {Name: "Google", IP: "8.8.8.8", DoH: "https://dns.google/resolve"},
        {Name: "Quad9", IP: "9.9.9.9"},
        {Name: "OpenDNS", IP: "208.67.222.222"},
}

const (
        UserAgent       = "DNSTool-DomainSecurityAudit/1.0 (+https://dnstool.it-help.tech)"
        dohGoogleURL    = "https://dns.google/resolve"
        defaultTimeout  = 2 * time.Second
        defaultLifetime = 4 * time.Second
        consensusWait   = 5 * time.Second
)

type ConsensusResult struct {
        Records         []string            `json:"records"`
        Consensus       bool                `json:"consensus"`
        ResolverCount   int                 `json:"resolver_count"`
        Discrepancies   []string            `json:"discrepancies"`
        ResolverResults map[string][]string `json:"resolver_results"`
}

type RecordWithTTL struct {
        Records []string
        TTL     *uint32
}

type ADFlagResult struct {
        ADFlag       bool    `json:"ad_flag"`
        Validated    bool    `json:"validated"`
        ResolverUsed *string `json:"resolver_used"`
        Error        *string `json:"error"`
}

type Client struct {
        resolvers  []ResolverConfig
        httpClient *http.Client
        timeout    time.Duration
        lifetime   time.Duration

        cacheMu  sync.RWMutex
        cache    map[string]cacheEntry
        cacheTTL time.Duration
        cacheMax int
}

type cacheEntry struct {
        data      []string
        timestamp time.Time
}

type Option func(*Client)

func WithResolvers(r []ResolverConfig) Option {
        return func(c *Client) { c.resolvers = r }
}

func WithHTTPClient(h *http.Client) Option {
        return func(c *Client) { c.httpClient = h }
}

func WithTimeout(t time.Duration) Option {
        return func(c *Client) { c.timeout = t }
}

func WithCacheTTL(t time.Duration) Option {
        return func(c *Client) { c.cacheTTL = t }
}

func New(opts ...Option) *Client {
        c := &Client{
                resolvers: DefaultResolvers,
                httpClient: &http.Client{
                        Timeout: 10 * time.Second,
                        Transport: &http.Transport{
                                MaxIdleConns:        20,
                                IdleConnTimeout:     30 * time.Second,
                                DisableKeepAlives:   false,
                                MaxIdleConnsPerHost: 5,
                        },
                },
                timeout:  defaultTimeout,
                lifetime: defaultLifetime,
                cache:    make(map[string]cacheEntry),
                cacheTTL: 30 * time.Second,
                cacheMax: 5000,
        }
        for _, o := range opts {
                o(c)
        }
        return c
}

func (c *Client) cacheGet(key string) ([]string, bool) {
        c.cacheMu.RLock()
        defer c.cacheMu.RUnlock()
        entry, ok := c.cache[key]
        if !ok {
                return nil, false
        }
        if time.Since(entry.timestamp) > c.cacheTTL {
                return nil, false
        }
        return entry.data, true
}

func (c *Client) cacheSet(key string, data []string) {
        c.cacheMu.Lock()
        defer c.cacheMu.Unlock()
        c.cache[key] = cacheEntry{data: data, timestamp: time.Now()}
        if len(c.cache) > c.cacheMax {
                cutoff := time.Now().Add(-c.cacheTTL)
                for k, v := range c.cache {
                        if v.timestamp.Before(cutoff) {
                                delete(c.cache, k)
                        }
                }
        }
}

func dnsTypeFromString(recordType string) (uint16, error) {
        switch strings.ToUpper(recordType) {
        case "A":
                return dns.TypeA, nil
        case "AAAA":
                return dns.TypeAAAA, nil
        case "MX":
                return dns.TypeMX, nil
        case "TXT":
                return dns.TypeTXT, nil
        case "NS":
                return dns.TypeNS, nil
        case "CNAME":
                return dns.TypeCNAME, nil
        case "CAA":
                return dns.TypeCAA, nil
        case "SOA":
                return dns.TypeSOA, nil
        case "SRV":
                return dns.TypeSRV, nil
        case "TLSA":
                return dns.TypeTLSA, nil
        case "DNSKEY":
                return dns.TypeDNSKEY, nil
        case "DS":
                return dns.TypeDS, nil
        case "RRSIG":
                return dns.TypeRRSIG, nil
        case "NSEC":
                return dns.TypeNSEC, nil
        case "NSEC3":
                return dns.TypeNSEC3, nil
        case "PTR":
                return dns.TypePTR, nil
        default:
                return 0, fmt.Errorf("unsupported record type: %s", recordType)
        }
}

func rrToString(rr dns.RR) string {
        switch v := rr.(type) {
        case *dns.A:
                return v.A.String()
        case *dns.AAAA:
                return v.AAAA.String()
        case *dns.MX:
                return fmt.Sprintf("%d %s", v.Preference, v.Mx)
        case *dns.TXT:
                return strings.Join(v.Txt, "")
        case *dns.NS:
                return v.Ns
        case *dns.CNAME:
                return v.Target
        case *dns.CAA:
                return fmt.Sprintf("%d %s \"%s\"", v.Flag, v.Tag, v.Value)
        case *dns.SOA:
                return fmt.Sprintf("%s %s %d %d %d %d %d", v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
        case *dns.SRV:
                return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target)
        case *dns.TLSA:
                return fmt.Sprintf("%d %d %d %s", v.Usage, v.Selector, v.MatchingType, v.Certificate)
        case *dns.DNSKEY:
                return v.String()
        case *dns.DS:
                return v.String()
        case *dns.RRSIG:
                return v.String()
        default:
                hdr := rr.Header()
                full := rr.String()
                prefix := hdr.String()
                return strings.TrimPrefix(full, prefix)
        }
}

func (c *Client) QueryDNS(ctx context.Context, recordType, domain string) []string {
        if domain == "" || recordType == "" {
                return nil
        }

        cacheKey := fmt.Sprintf("%s:%s", strings.ToUpper(recordType), strings.ToLower(domain))
        if cached, ok := c.cacheGet(cacheKey); ok {
                return cached
        }

        results := c.dohQuery(ctx, domain, recordType)
        if len(results) > 0 {
                c.cacheSet(cacheKey, results)
                return results
        }

        for _, resolver := range c.resolvers {
                results = c.udpQuery(ctx, domain, recordType, resolver.IP)
                if len(results) > 0 {
                        c.cacheSet(cacheKey, results)
                        return results
                }
        }

        return nil
}

func (c *Client) QueryDNSWithTTL(ctx context.Context, recordType, domain string) RecordWithTTL {
        if domain == "" || recordType == "" {
                return RecordWithTTL{}
        }

        result := c.dohQueryWithTTL(ctx, domain, recordType)
        if len(result.Records) > 0 {
                return result
        }

        for _, resolver := range c.resolvers {
                result = c.udpQueryWithTTL(ctx, domain, recordType, resolver.IP)
                if len(result.Records) > 0 {
                        return result
                }
        }

        return RecordWithTTL{}
}

func (c *Client) querySingleResolver(ctx context.Context, domain, recordType, resolverIP string) (string, []string, string) {
        qtype, err := dnsTypeFromString(recordType)
        if err != nil {
                return resolverIP, nil, err.Error()
        }

        fqdn := dns.Fqdn(domain)
        msg := new(dns.Msg)
        msg.SetQuestion(fqdn, qtype)
        msg.RecursionDesired = true

        dnsClient := &dns.Client{
                Net:     "udp",
                Timeout: c.timeout,
        }

        r, _, err := dnsClient.ExchangeContext(ctx, msg, net.JoinHostPort(resolverIP, "53"))
        if err != nil {
                return resolverIP, nil, err.Error()
        }

        if r.Rcode == dns.RcodeNameError {
                return resolverIP, nil, "NXDOMAIN"
        }

        var results []string
        for _, rr := range r.Answer {
                s := rrToString(rr)
                if s != "" {
                        results = append(results, s)
                }
        }
        sort.Strings(results)
        return resolverIP, results, ""
}

func (c *Client) QueryWithConsensus(ctx context.Context, recordType, domain string) ConsensusResult {
        if domain == "" || recordType == "" {
                return ConsensusResult{Consensus: true}
        }

        type resolverResult struct {
                name    string
                results []string
                err     string
        }

        ch := make(chan resolverResult, len(c.resolvers))
        ctx2, cancel := context.WithTimeout(ctx, consensusWait)
        defer cancel()

        for _, r := range c.resolvers {
                go func(resolver ResolverConfig) {
                        _, results, errStr := c.querySingleResolver(ctx2, domain, recordType, resolver.IP)
                        ch <- resolverResult{name: resolver.Name, results: results, err: errStr}
                }(r)
        }

        resolverResults := make(map[string][]string)
        for i := 0; i < len(c.resolvers); i++ {
                select {
                case rr := <-ch:
                        if rr.err == "" {
                                resolverResults[rr.name] = rr.results
                        } else {
                                slog.Debug("resolver error", "resolver", rr.name, "record_type", recordType, "domain", domain, "error", rr.err)
                        }
                case <-ctx2.Done():
                        break
                }
        }

        if len(resolverResults) == 0 {
                dohResults := c.dohQuery(ctx, domain, recordType)
                return ConsensusResult{
                        Records:         dohResults,
                        Consensus:       true,
                        ResolverCount:   boolToInt(len(dohResults) > 0),
                        ResolverResults: map[string][]string{"DoH": dohResults},
                }
        }

        consensusRecords, allSame, discrepancies := findConsensus(resolverResults)
        if !allSame {
                slog.Warn("DNS discrepancy", "domain", domain, "record_type", recordType, "discrepancies", discrepancies)
        }

        return ConsensusResult{
                Records:         consensusRecords,
                Consensus:       allSame,
                ResolverCount:   len(resolverResults),
                Discrepancies:   discrepancies,
                ResolverResults: resolverResults,
        }
}

func findConsensus(resolverResults map[string][]string) (records []string, allSame bool, discrepancies []string) {
        resultSets := make(map[string]int)
        for _, results := range resolverResults {
                key := strings.Join(results, "|")
                resultSets[key]++
        }

        var mostCommonKey string
        var mostCommonCount int
        for key, count := range resultSets {
                if count > mostCommonCount {
                        mostCommonKey = key
                        mostCommonCount = count
                }
        }

        if mostCommonKey != "" {
                records = strings.Split(mostCommonKey, "|")
                if len(records) == 1 && records[0] == "" {
                        records = nil
                }
        }

        allSame = len(resultSets) <= 1
        if !allSame {
                for name, results := range resolverResults {
                        key := strings.Join(results, "|")
                        if key != mostCommonKey {
                                discrepancies = append(discrepancies, fmt.Sprintf("%s returned different results: %v", name, results))
                        }
                }
        }
        return
}

func (c *Client) ValidateResolverConsensus(ctx context.Context, domain string) map[string]any {
        criticalTypes := []string{"A", "MX", "NS", "TXT"}
        result := map[string]any{
                "consensus_reached":    true,
                "resolvers_queried":    len(c.resolvers),
                "checks_performed":     0,
                "discrepancies":        []string{},
                "per_record_consensus": map[string]any{},
        }

        type checkResult struct {
                recordType string
                consensus  ConsensusResult
                err        error
        }

        ch := make(chan checkResult, len(criticalTypes))
        ctx2, cancel := context.WithTimeout(ctx, 8*time.Second)
        defer cancel()

        for _, rt := range criticalTypes {
                go func(recordType string) {
                        cr := c.QueryWithConsensus(ctx2, recordType, domain)
                        ch <- checkResult{recordType: recordType, consensus: cr}
                }(rt)
        }

        perRecord := make(map[string]any)
        var allDisc []string
        checksPerformed := 0
        consensusReached := true

        for i := 0; i < len(criticalTypes); i++ {
                select {
                case cr := <-ch:
                        checksPerformed++
                        perRecord[cr.recordType] = map[string]any{
                                "consensus":      cr.consensus.Consensus,
                                "resolver_count": cr.consensus.ResolverCount,
                                "discrepancies":  cr.consensus.Discrepancies,
                        }
                        if !cr.consensus.Consensus {
                                consensusReached = false
                                for _, d := range cr.consensus.Discrepancies {
                                        allDisc = append(allDisc, fmt.Sprintf("%s: %s", cr.recordType, d))
                                }
                        }
                case <-ctx2.Done():
                        break
                }
        }

        result["consensus_reached"] = consensusReached
        result["checks_performed"] = checksPerformed
        result["discrepancies"] = allDisc
        result["per_record_consensus"] = perRecord
        return result
}

func (c *Client) CheckDNSSECADFlag(ctx context.Context, domain string) ADFlagResult {
        result := ADFlagResult{}
        validatingResolvers := []string{"8.8.8.8", "1.1.1.1"}

        for _, resolverIP := range validatingResolvers {
                fqdn := dns.Fqdn(domain)
                msg := new(dns.Msg)
                msg.SetQuestion(fqdn, dns.TypeA)
                msg.RecursionDesired = true
                msg.SetEdns0(4096, true)

                dnsClient := &dns.Client{
                        Net:     "udp",
                        Timeout: 3 * time.Second,
                }

                r, _, err := dnsClient.ExchangeContext(ctx, msg, net.JoinHostPort(resolverIP, "53"))
                if err != nil {
                        if isNXDomain(r) {
                                errStr := "Domain not found"
                                result.Error = &errStr
                                return result
                        }
                        slog.Debug("AD flag check failed", "resolver", resolverIP, "error", err)
                        continue
                }

                if r.Rcode == dns.RcodeNameError {
                        errStr := "Domain not found"
                        result.Error = &errStr
                        return result
                }

                if len(r.Answer) == 0 {
                        msg2 := new(dns.Msg)
                        msg2.SetQuestion(fqdn, dns.TypeSOA)
                        msg2.RecursionDesired = true
                        msg2.SetEdns0(4096, true)
                        r2, _, err2 := dnsClient.ExchangeContext(ctx, msg2, net.JoinHostPort(resolverIP, "53"))
                        if err2 == nil {
                                r = r2
                        }
                }

                if r.MsgHdr.AuthenticatedData {
                        result.ADFlag = true
                        result.Validated = true
                        result.ResolverUsed = &resolverIP
                        return result
                }
                result.ADFlag = false
                result.Validated = false
                result.ResolverUsed = &resolverIP
                return result
        }

        errStr := "Could not verify AD flag"
        result.Error = &errStr
        return result
}

func (c *Client) ExchangeContext(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
        resolverAddr := net.JoinHostPort(c.resolvers[0].IP, "53")
        return c.exchangeWithFallback(ctx, msg, resolverAddr)
}

func (c *Client) exchangeWithFallback(ctx context.Context, msg *dns.Msg, resolverAddr string) (*dns.Msg, error) {
        udpClient := &dns.Client{Net: "udp", Timeout: c.timeout}
        r, _, err := udpClient.ExchangeContext(ctx, msg, resolverAddr)
        if err == nil {
                return r, nil
        }

        slog.Debug("UDP query failed, falling back to TCP", "resolver", resolverAddr, "error", err)
        tcpClient := &dns.Client{Net: "tcp", Timeout: c.timeout}
        r, _, err = tcpClient.ExchangeContext(ctx, msg, resolverAddr)
        return r, err
}

func (c *Client) QuerySpecificResolver(ctx context.Context, recordType, domain, resolverIP string) ([]string, error) {
        qtype, err := dnsTypeFromString(recordType)
        if err != nil {
                return nil, err
        }

        fqdn := dns.Fqdn(domain)
        msg := new(dns.Msg)
        msg.SetQuestion(fqdn, qtype)
        msg.RecursionDesired = false

        resolverAddr := net.JoinHostPort(resolverIP, "53")
        r, err := c.exchangeWithFallback(ctx, msg, resolverAddr)
        if err != nil {
                return nil, err
        }

        if r.Rcode == dns.RcodeNameError {
                return nil, nil
        }

        var results []string
        for _, rr := range r.Answer {
                s := rrToString(rr)
                if s != "" {
                        results = append(results, s)
                }
        }
        return results, nil
}

func (c *Client) QueryWithTTLFromResolver(ctx context.Context, recordType, domain, resolverIP string) RecordWithTTL {
        qtype, err := dnsTypeFromString(recordType)
        if err != nil {
                return RecordWithTTL{}
        }

        fqdn := dns.Fqdn(domain)
        msg := new(dns.Msg)
        msg.SetQuestion(fqdn, qtype)
        msg.RecursionDesired = false

        resolverAddr := net.JoinHostPort(resolverIP, "53")
        r, err := c.exchangeWithFallback(ctx, msg, resolverAddr)
        if err != nil {
                return RecordWithTTL{}
        }

        if r.Rcode == dns.RcodeNameError {
                return RecordWithTTL{}
        }

        var results []string
        var ttl *uint32
        for _, rr := range r.Answer {
                s := rrToString(rr)
                if s != "" {
                        results = append(results, s)
                        if ttl == nil {
                                t := rr.Header().Ttl
                                ttl = &t
                        }
                }
        }
        return RecordWithTTL{Records: results, TTL: ttl}
}

func (c *Client) dohQuery(ctx context.Context, domain, recordType string) []string {
        result := c.dohQueryWithTTL(ctx, domain, recordType)
        return result.Records
}

type dohResponse struct {
        Status int `json:"Status"`
        Answer []struct {
                Data string `json:"data"`
                TTL  uint32 `json:"TTL"`
        } `json:"Answer"`
}

func (c *Client) dohQueryWithTTL(ctx context.Context, domain, recordType string) RecordWithTTL {
        req, err := http.NewRequestWithContext(ctx, "GET", dohGoogleURL, nil)
        if err != nil {
                return RecordWithTTL{}
        }

        q := url.Values{}
        q.Set("name", domain)
        q.Set("type", strings.ToUpper(recordType))
        req.URL.RawQuery = q.Encode()
        req.Header.Set("Accept", "application/dns-json")
        req.Header.Set("User-Agent", UserAgent)

        resp, err := c.httpClient.Do(req)
        if err != nil {
                slog.Debug("DoH query failed", "domain", domain, "type", recordType, "error", err)
                return RecordWithTTL{}
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
                return RecordWithTTL{}
        }

        body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
        if err != nil {
                return RecordWithTTL{}
        }

        return parseDohResponse(body, recordType)
}

func parseDohResponse(body []byte, recordType string) RecordWithTTL {
        var data dohResponse
        if json.Unmarshal(body, &data) != nil {
                return RecordWithTTL{}
        }

        if data.Status != 0 {
                return RecordWithTTL{}
        }

        if len(data.Answer) == 0 {
                return RecordWithTTL{}
        }

        var results []string
        var ttl *uint32
        seen := make(map[string]bool)
        for _, answer := range data.Answer {
                rd := strings.TrimSpace(answer.Data)
                if rd == "" {
                        continue
                }
                if strings.ToUpper(recordType) == "TXT" {
                        rd = strings.Trim(rd, "\"")
                }
                if !seen[rd] {
                        results = append(results, rd)
                        seen[rd] = true
                }
                if ttl == nil {
                        t := answer.TTL
                        ttl = &t
                }
        }

        return RecordWithTTL{Records: results, TTL: ttl}
}

func (c *Client) udpQuery(ctx context.Context, domain, recordType, resolverIP string) []string {
        result := c.udpQueryWithTTL(ctx, domain, recordType, resolverIP)
        return result.Records
}

func (c *Client) udpQueryWithTTL(ctx context.Context, domain, recordType, resolverIP string) RecordWithTTL {
        qtype, err := dnsTypeFromString(recordType)
        if err != nil {
                return RecordWithTTL{}
        }

        fqdn := dns.Fqdn(domain)
        msg := new(dns.Msg)
        msg.SetQuestion(fqdn, qtype)
        msg.RecursionDesired = true

        dnsClient := &dns.Client{
                Net:     "udp",
                Timeout: c.timeout,
        }

        r, _, err := dnsClient.ExchangeContext(ctx, msg, net.JoinHostPort(resolverIP, "53"))
        if err != nil {
                return RecordWithTTL{}
        }

        if r.Rcode == dns.RcodeNameError {
                return RecordWithTTL{}
        }

        var results []string
        var ttl *uint32
        for _, rr := range r.Answer {
                s := rrToString(rr)
                if s != "" {
                        results = append(results, s)
                        if ttl == nil {
                                t := rr.Header().Ttl
                                ttl = &t
                        }
                }
        }

        return RecordWithTTL{Records: results, TTL: ttl}
}

func isNXDomain(r *dns.Msg) bool {
        return r != nil && r.Rcode == dns.RcodeNameError
}

func boolToInt(b bool) int {
        if b {
                return 1
        }
        return 0
}
