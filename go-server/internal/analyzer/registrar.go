package analyzer

import (
        "context"
        "encoding/json"
        "fmt"
        "log/slog"
        "net"
        "regexp"
        "strings"
        "time"

        "dnstool/go-server/internal/dnsclient"
)

var (
        registrarRe  = regexp.MustCompile(`(?im)^(?:registrar|sponsoring registrar|registrar[- ]name)\s*:\s*(.+)$`)
        registrantRe = regexp.MustCompile(`(?im)^(?:registrant organization|registrant name|registrant)\s*:\s*(.+)$`)
)

var directRDAPEndpoints = map[string]string{
        "com":   "https://rdap.verisign.com/com/v1/",
        "net":   "https://rdap.verisign.com/net/v1/",
        "org":   "https://rdap.publicinterestregistry.net/rdap/",
        "io":    "https://rdap.nic.io/",
        "dev":   "https://rdap.nic.google/",
        "app":   "https://rdap.nic.google/",
        "uk":    "https://rdap.nominet.uk/uk/",
        "eu":    "https://rdap.eu/",
        "nl":    "https://rdap.sidn.nl/rdap/",
        "au":    "https://rdap.auda.org.au/rdap/",
        "cc":    "https://rdap.verisign.com/cc/v1/",
        "tv":    "https://rdap.verisign.com/tv/v1/",
        "xyz":   "https://rdap.centralnic.com/xyz/",
        "co":    "https://rdap.nic.co/",
        "me":    "https://rdap.nic.me/",
        "ai":    "https://rdap.nic.ai/",
        "tech":  "https://rdap.centralnic.com/tech/",
        "site":  "https://rdap.centralnic.com/site/",
        "store": "https://rdap.centralnic.com/store/",
        "info":  "https://rdap.afilias.net/rdap/info/",
        "biz":   "https://rdap.nic.biz/",
        "mobi":  "https://rdap.nic.mobi/",
        "name":  "https://rdap.verisign.com/name/v1/",
        "pro":   "https://rdap.nic.pro/",
        "cloud": "https://rdap.centralnic.com/cloud/",
        "online":"https://rdap.centralnic.com/online/",
        "live":  "https://rdap.centralnic.com/live/",
        "space": "https://rdap.centralnic.com/space/",
        "fun":   "https://rdap.centralnic.com/fun/",
        "top":   "https://rdap.nic.top/",
}

var whoisServers = map[string]string{
        "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
        "org": "whois.pir.org", "io": "whois.nic.io",
        "dev": "whois.nic.google", "app": "whois.nic.google",
        "co": "whois.nic.co", "me": "whois.nic.me",
        "uk": "whois.nic.uk", "us": "whois.nic.us",
        "ca": "whois.cira.ca", "au": "whois.auda.org.au",
        "de": "whois.denic.de", "fr": "whois.nic.fr",
        "nl": "whois.sidn.nl", "eu": "whois.eu",
        "it": "whois.nic.it", "ch": "whois.nic.ch",
        "se": "whois.iis.se", "pl": "whois.dns.pl",
        "xyz": "whois.nic.xyz", "tech": "whois.nic.tech",
        "site": "whois.nic.site", "store": "whois.nic.store",
        "info": "whois.afilias.net", "biz": "whois.nic.biz",
        "mobi": "whois.nic.mobi", "pro": "whois.nic.pro",
        "cloud": "whois.nic.cloud", "online": "whois.nic.online",
        "live": "whois.nic.live", "space": "whois.nic.space",
        "top": "whois.nic.top",
}

var nsRegistrarPatterns = map[string]string{
        "gandi.net":             "Gandi SAS",
        "ovh.net":               "OVHcloud",
        "ovh.com":               "OVHcloud",
        "domaincontrol.com":     "GoDaddy",
        "registrar-servers.com": "Namecheap",
        "name-services.com":     "Enom / Tucows",
        "ionos.com":             "IONOS",
        "ui-dns.com":            "IONOS",
        "ui-dns.de":             "IONOS",
        "strato.de":             "Strato",
        "hetzner.com":           "Hetzner",
        "inwx.de":               "INWX",
        "porkbun.com":           "Porkbun",
        "dynadot.com":           "Dynadot",
        "squarespace.com":       "Squarespace Domains",
        "wixdns.net":            "Wix",
        "wordpress.com":         "WordPress.com",
        "aruba.it":              "Aruba S.p.A.",
        "infomaniak.ch":         "Infomaniak",
        "hostpoint.ch":          "Hostpoint",
        "bluehost.com":          "Bluehost",
        "dreamhost.com":         "DreamHost",
}

var whoisRestrictedIndicators = []string{
        "not authorised", "not authorized", "access denied",
        "authorization required", "ip address used to perform",
        "exceeded the established limit", "access restricted",
        "query rate limit exceeded", "too many queries",
}

func (a *Analyzer) GetRegistrarInfo(ctx context.Context, domain string) map[string]any {
        slog.Info("Getting registrar info", "domain", domain)

        if cached, ok := a.RDAPCache.Get(domain); ok {
                slog.Info("RDAP cache hit", "domain", domain)
                cached["cache_hit"] = true
                return cached
        }

        result := a.getRegistrarInfoUncached(ctx, domain)

        if result["status"] == "success" {
                a.RDAPCache.Set(domain, result)
        }

        return result
}

func buildRestrictedResult(restricted bool, restrictedTLD string) map[string]any {
        if !restricted {
                return map[string]any{
                        "status":    "error",
                        "source":    nil,
                        "registrar": nil,
                        "message":   "Registry data unavailable (RDAP/WHOIS services unreachable or rate-limited)",
                }
        }

        restrictedRegistries := map[string]string{
                "es": "Red.es (Spain)", "br": "Registro.br (Brazil)",
                "kr": "KISA (South Korea)", "cn": "CNNIC (China)", "ru": "RIPN (Russia)",
        }
        registryName := restrictedRegistries[restrictedTLD]
        if registryName == "" {
                registryName = fmt.Sprintf(".%s registry", restrictedTLD)
        }
        return map[string]any{
                "status":                  "restricted",
                "source":                  "WHOIS",
                "registrar":               nil,
                "registry_restricted":     true,
                "registry_restricted_tld": restrictedTLD,
                "message":                 fmt.Sprintf("%s restricts public WHOIS/RDAP access — registrar data requires authorized IP", registryName),
        }
}

func (a *Analyzer) getRegistrarInfoUncached(ctx context.Context, domain string) map[string]any {
        if result := a.tryRDAPLookup(ctx, domain); result != nil {
                return result
        }

        whoisResult, restricted, restrictedTLD := a.whoisLookup(ctx, domain)
        if whoisResult != "" {
                return map[string]any{"status": "success", "source": "WHOIS", "registrar": whoisResult, "confidence": ConfidenceObservedMap(MethodWHOIS)}
        }

        if result := a.tryParentZoneLookup(ctx, domain); result != nil {
                return result
        }

        return a.tryNSInference(ctx, domain, restricted, restrictedTLD)
}

func (a *Analyzer) tryRDAPLookup(ctx context.Context, domain string) map[string]any {
        rdapResult := a.rdapLookup(ctx, domain)
        if rdapResult == nil {
                return nil
        }
        registrar := extractRegistrarFromRDAP(rdapResult)
        if registrar == "" || isDigits(registrar) {
                return nil
        }
        regStr := formatRegistrarWithRegistrant(registrar, extractRegistrantFromRDAP(rdapResult))
        return map[string]any{"status": "success", "source": "RDAP", "registrar": regStr, "confidence": ConfidenceObservedMap(MethodRDAP)}
}

func formatRegistrarWithRegistrant(registrar, registrant string) string {
        if registrant != "" {
                return registrar + fmt.Sprintf(" (Registrant: %s)", registrant)
        }
        return registrar
}

func (a *Analyzer) tryParentZoneLookup(ctx context.Context, domain string) map[string]any {
        parentZone := dnsclient.FindParentZone(a.DNS, ctx, domain)
        if parentZone == "" || parentZone == domain {
                return nil
        }
        parentResult := a.GetRegistrarInfo(ctx, parentZone)
        if parentResult["status"] == "success" {
                parentResult["subdomain_of"] = parentZone
                return parentResult
        }
        return nil
}

func (a *Analyzer) tryNSInference(ctx context.Context, domain string, restricted bool, restrictedTLD string) map[string]any {
        parentZone := dnsclient.FindParentZone(a.DNS, ctx, domain)
        lookupDomain := domain
        if parentZone != "" && parentZone != domain {
                lookupDomain = parentZone
        }

        nsResult := a.inferRegistrarFromNS(ctx, lookupDomain)
        if nsResult != nil {
                if lookupDomain != domain {
                        nsResult["subdomain_of"] = lookupDomain
                }
                if restricted {
                        nsResult["registry_restricted"] = true
                        nsResult["registry_restricted_tld"] = restrictedTLD
                }
                return nsResult
        }

        return buildRestrictedResult(restricted, restrictedTLD)
}

func (a *Analyzer) rdapLookup(ctx context.Context, domain string) map[string]any {
        tld := getTLD(domain)

        endpoint := directRDAPEndpoints[tld]
        if endpoint == "" {
                endpoints, ok := a.IANARDAPMap[tld]
                if ok && len(endpoints) > 0 {
                        endpoint = endpoints[0]
                } else {
                        endpoint = "https://rdap.org/"
                }
        }

        providerName := "rdap:" + tld
        if a.Telemetry.InCooldown(providerName) {
                slog.Info("RDAP provider in cooldown, skipping", "provider", providerName)
                return nil
        }

        rdapURL := fmt.Sprintf("%s/domain/%s", strings.TrimRight(endpoint, "/"), domain)
        slog.Info("RDAP lookup", "url", rdapURL)

        start := time.Now()
        resp, err := a.HTTP.Get(ctx, rdapURL)
        if err != nil {
                a.Telemetry.RecordFailure(providerName, err.Error())
                slog.Warn("RDAP lookup failed", "error", err)
                return nil
        }

        body, err := a.HTTP.ReadBody(resp, 1<<20)
        if err != nil {
                a.Telemetry.RecordFailure(providerName, err.Error())
                return nil
        }

        if resp.StatusCode >= 400 {
                a.Telemetry.RecordFailure(providerName, fmt.Sprintf("HTTP %d", resp.StatusCode))
                return nil
        }

        var data map[string]any
        if json.Unmarshal(body, &data) != nil {
                a.Telemetry.RecordFailure(providerName, "invalid JSON")
                return nil
        }

        if _, hasError := data["errorCode"]; hasError {
                a.Telemetry.RecordFailure(providerName, "RDAP error response")
                return nil
        }

        a.Telemetry.RecordSuccess(providerName, time.Since(start))
        return data
}

func extractRegistrarFromRDAP(data map[string]any) string {
        entities, ok := data["entities"].([]any)
        if !ok {
                return ""
        }
        return findRegistrarEntity(entities)
}

func findRegistrarEntity(entities []any) string {
        for _, e := range entities {
                entity, ok := e.(map[string]any)
                if !ok {
                        continue
                }
                if !entityHasRole(entity, "registrar") {
                        if result := findRegistrarInSubEntities(entity); result != "" {
                                return result
                        }
                        continue
                }
                if name := extractFNFromVCard(entity); name != "" {
                        return name
                }
                if name := extractEntityName(entity); name != "" {
                        return name
                }
                if result := findRegistrarInSubEntities(entity); result != "" {
                        return result
                }
        }
        return ""
}

func findRegistrarInSubEntities(entity map[string]any) string {
        subEntities, ok := entity["entities"].([]any)
        if !ok {
                return ""
        }
        return findRegistrarEntity(subEntities)
}

func extractEntityName(entity map[string]any) string {
        if name, ok := entity["name"].(string); ok && name != "" && !isDigits(name) {
                return name
        }
        if handle, ok := entity["handle"].(string); ok && handle != "" && !isDigits(handle) {
                return handle
        }
        return ""
}

func extractRegistrantFromRDAP(data map[string]any) string {
        entities, ok := data["entities"].([]any)
        if !ok {
                return ""
        }
        return findRegistrantEntity(entities)
}

var redactedValues = map[string]bool{
        "redacted": true, "data protected": true,
        "not disclosed": true, "withheld": true,
}

func findRegistrantEntity(entities []any) string {
        for _, e := range entities {
                entity, ok := e.(map[string]any)
                if !ok {
                        continue
                }
                if !entityHasRole(entity, "registrant") {
                        if result := findRegistrantInSubEntities(entity); result != "" {
                                return result
                        }
                        continue
                }
                if name := extractFNFromVCard(entity); name != "" && !redactedValues[strings.ToLower(name)] {
                        return name
                }
                if result := findRegistrantInSubEntities(entity); result != "" {
                        return result
                }
        }
        return ""
}

func findRegistrantInSubEntities(entity map[string]any) string {
        subEntities, ok := entity["entities"].([]any)
        if !ok {
                return ""
        }
        return findRegistrantEntity(subEntities)
}

func entityHasRole(entity map[string]any, role string) bool {
        roles, ok := entity["roles"].([]any)
        if !ok {
                return false
        }
        for _, r := range roles {
                if strings.ToLower(fmt.Sprint(r)) == role {
                        return true
                }
        }
        return false
}

func extractFNFromVCard(entity map[string]any) string {
        vcard, ok := entity["vcardArray"].([]any)
        if !ok || len(vcard) != 2 {
                return ""
        }
        items, ok := vcard[1].([]any)
        if !ok {
                return ""
        }
        for _, item := range items {
                arr, ok := item.([]any)
                if !ok || len(arr) < 4 {
                        continue
                }
                if fmt.Sprint(arr[0]) == "fn" {
                        return fmt.Sprint(arr[3])
                }
        }
        return ""
}

func (a *Analyzer) whoisLookup(ctx context.Context, domain string) (string, bool, string) {
        tld := getTLD(domain)
        server, ok := whoisServers[tld]
        if !ok {
                return "", false, ""
        }

        conn, err := net.DialTimeout("tcp", server+":43", 5*time.Second)
        if err != nil {
                return "", false, ""
        }
        defer conn.Close()
        conn.SetDeadline(time.Now().Add(10 * time.Second))

        _, err = conn.Write([]byte(domain + "\r\n"))
        if err != nil {
                return "", false, ""
        }

        var buf [8192]byte
        var response []byte
        for {
                n, err := conn.Read(buf[:])
                if n > 0 {
                        response = append(response, buf[:n]...)
                }
                if err != nil {
                        break
                }
                if len(response) > 32768 {
                        break
                }
        }

        output := string(response)

        if isWhoisRestricted(output) {
                return "", true, tld
        }

        registrar := parseWhoisRegistrar(output)
        registrant := parseWhoisRegistrant(output)

        return formatWhoisResult(registrar, registrant)
}

func isWhoisRestricted(output string) bool {
        if len(strings.TrimSpace(output)) < 50 {
                return true
        }
        outputLower := strings.ToLower(output)
        for _, indicator := range whoisRestrictedIndicators {
                if strings.Contains(outputLower, indicator) {
                        return true
                }
        }
        return false
}

func parseWhoisRegistrar(output string) string {
        m := registrarRe.FindStringSubmatch(output)
        if m == nil {
                return ""
        }
        val := strings.TrimSpace(m[1])
        if val == "" || strings.HasPrefix(strings.ToLower(val), "http") || strings.ToLower(val) == "not available" {
                return ""
        }
        return val
}

func parseWhoisRegistrant(output string) string {
        m := registrantRe.FindStringSubmatch(output)
        if m == nil {
                return ""
        }
        val := strings.TrimSpace(m[1])
        if val == "" || redactedValues[strings.ToLower(val)] {
                return ""
        }
        return val
}

func formatWhoisResult(registrar, registrant string) (string, bool, string) {
        if registrar != "" && registrant != "" {
                return fmt.Sprintf("%s (Registrant: %s)", registrar, registrant), false, ""
        }
        if registrar != "" {
                return registrar, false, ""
        }
        if registrant != "" {
                return registrant, false, ""
        }
        return "", false, ""
}

func (a *Analyzer) inferRegistrarFromNS(ctx context.Context, domain string) map[string]any {
        nsRecords := a.DNS.QueryDNS(ctx, "NS", domain)
        if len(nsRecords) == 0 {
                return nil
        }

        nsStr := strings.ToLower(strings.Join(nsRecords, " "))

        for pattern, registrarName := range nsRegistrarPatterns {
                if strings.Contains(nsStr, pattern) {
                        slog.Info("Inferred registrar from NS", "registrar", registrarName, "pattern", pattern, "domain", domain)
                        return map[string]any{
                                "status":      "success",
                                "source":      "NS inference",
                                "registrar":   registrarName,
                                "ns_inferred": true,
                                "caveat":      "Inferred from nameserver records — indicates DNS hosting provider, which for integrated registrars typically matches the registrar.",
                                "confidence":  ConfidenceInferredMap(MethodNSInference),
                        }
                }
        }

        return nil
}

func getTLD(domain string) string {
        parts := strings.Split(domain, ".")
        if len(parts) > 1 {
                return parts[len(parts)-1]
        }
        return domain
}

func isDigits(s string) bool {
        for _, c := range s {
                if c < '0' || c > '9' {
                        return false
                }
        }
        return len(s) > 0
}
