// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "context"
        "encoding/json"
        "fmt"
        "log/slog"
        "sort"
        "strings"
        "sync"
        "time"
)

type ctEntry struct {
        NameValue    string `json:"name_value"`
        CommonName   string `json:"common_name"`
        NotBefore    string `json:"not_before"`
        NotAfter     string `json:"not_after"`
        IssuerName   string `json:"issuer_name"`
        SerialNumber string `json:"serial_number"`
}

var commonSubdomainProbes = []string{
        "www", "www2", "www3", "web", "m", "mobile",
        "mail", "email", "webmail", "smtp", "pop", "imap", "mx", "mx1", "mx2", "relay", "mta",
        "autodiscover", "autoconfig", "owa", "exchange",
        "ftp", "sftp", "ssh",
        "vpn", "remote", "gateway", "gw",
        "api", "app", "apps", "portal",
        "admin", "panel", "cpanel", "dashboard", "manage", "management",
        "server", "server1", "server2",
        "blog", "news", "wiki", "docs", "doc", "help", "support", "kb", "faq",
        "shop", "store", "billing", "pay", "payment", "checkout", "invoice",
        "sso", "auth", "login", "id", "accounts", "account", "signup", "register",
        "dev", "staging", "test", "demo", "sandbox", "beta", "preview", "uat", "stage",
        "cdn", "static", "assets", "media", "img", "images",
        "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
        "cloud", "host",
        "db", "database", "sql", "mysql", "postgres",
        "monitor", "status", "grafana", "prometheus", "nagios", "zabbix",
        "git", "gitlab", "github", "repo", "bitbucket",
        "ci", "jenkins", "build", "deploy",
        "calendar", "cal", "meet", "video", "chat", "conference",
        "crm", "erp", "hr",
        "intranet", "internal", "corp",
        "proxy", "lb", "loadbalancer",
        "secure", "ssl", "tls",
        "files", "download", "backup", "share",
        "forum", "community",
        "office", "work", "connect",
        "analytics", "metrics", "logs", "tracking",
        "search", "es", "elastic",
        "cache", "redis", "memcached",
        "queue", "mq", "rabbitmq",
        "s3", "storage", "bucket",
        "map", "maps", "geo",
        "confluence", "jira", "ticket", "tickets",
        "slack", "teams", "zoom",
        "reports", "report",
        "screen", "schedule", "booking", "appointments",
        "dnstool", "tools", "tool",
        "client", "clients", "partner", "partners",
        "training", "learn", "lms", "academy",
        "inventory", "orders", "catalog",
        "notify", "notifications", "alerts",
        "print", "printer", "scan",
        "backup1", "backup2", "archive",
        "voip", "sip", "phone", "pbx", "tel",
        "mdm", "devices",
        "proxy1", "proxy2", "edge",
        "waf", "firewall",
}

func (a *Analyzer) DiscoverSubdomains(ctx context.Context, domain string) map[string]any {
        result := map[string]any{
                "status":            "success",
                "subdomains":        []map[string]any{},
                "unique_subdomains": 0,
                "total_certs":       0,
                "source":            "Certificate Transparency + DNS Intelligence",
                "caveat":            "Subdomains discovered via CT logs (RFC 6962), DNS probing of common service names, and CNAME chain traversal.",
                "current_count":     "0",
                "expired_count":     "0",
                "cname_count":       0.0,
                "providers_found":   0.0,
        }

        if cached, ok := a.getCTCache(domain); ok {
                result["unique_subdomains"] = len(cached)
                result["ct_source"] = "cache"

                currentCount := 0
                expiredCount := 0
                cnameCount := 0
                for _, sd := range cached {
                        if isCurrent, ok := sd["is_current"].(bool); ok && isCurrent {
                                currentCount++
                        } else {
                                expiredCount++
                        }
                        if _, hasCname := sd["cname_target"]; hasCname {
                                cnameCount++
                        }
                }
                result["current_count"] = fmt.Sprintf("%d", currentCount)
                result["expired_count"] = fmt.Sprintf("%d", expiredCount)
                result["cname_count"] = float64(cnameCount)

                sorted := sortSubdomainsSmartOrder(cached)
                applySubdomainDisplayCap(result, sorted, currentCount)
                return result
        }

        ctProvider := "ct:crt.sh"
        var ctEntries []ctEntry
        ctAvailable := true

        if a.Telemetry.InCooldown(ctProvider) {
                slog.Info("CT provider in cooldown, skipping", "domain", domain)
                ctAvailable = false
        } else {
                ctCtx, ctCancel := context.WithTimeout(context.Background(), 30*time.Second)
                defer ctCancel()
                ctURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
                start := time.Now()
                resp, err := a.SlowHTTP.Get(ctCtx, ctURL)
                if err != nil {
                        a.Telemetry.RecordFailure(ctProvider, err.Error())
                        slog.Warn("CT log query failed", "domain", domain, "error", err, "elapsed_ms", time.Since(start).Milliseconds())
                        ctAvailable = false
                } else {
                        body, err := a.HTTP.ReadBody(resp, 10<<20)
                        if err != nil {
                                a.Telemetry.RecordFailure(ctProvider, err.Error())
                                ctAvailable = false
                        } else if resp.StatusCode != 200 {
                                a.Telemetry.RecordFailure(ctProvider, fmt.Sprintf("HTTP %d", resp.StatusCode))
                                ctAvailable = false
                        } else {
                                a.Telemetry.RecordSuccess(ctProvider, time.Since(start))
                                if json.Unmarshal(body, &ctEntries) != nil {
                                        ctAvailable = false
                                }
                        }
                }
        }

        dedupedEntries := deduplicateCTEntries(ctEntries)
        if ctAvailable {
                result["total_certs"] = len(ctEntries)
                result["unique_certs"] = len(dedupedEntries)
        }

        wildcardInfo := detectWildcardCerts(dedupedEntries, domain)
        if wildcardInfo != nil {
                result["wildcard_certs"] = wildcardInfo
        }

        if ctAvailable {
                result["ca_summary"] = buildCASummary(dedupedEntries)
        }

        subdomainSet := make(map[string]map[string]any)

        if ctAvailable {
                processCTEntries(ctEntries, domain, subdomainSet)
        }

        dnsProbed := a.probeCommonSubdomains(ctx, domain, subdomainSet)
        result["cname_discovered_count"] = 0.0

        var subdomains []map[string]any
        currentCount := 0
        expiredCount := 0
        cnameCount := 0

        for _, sd := range subdomainSet {
                subdomains = append(subdomains, sd)
                if isCurrent, ok := sd["is_current"].(bool); ok && isCurrent {
                        currentCount++
                } else {
                        expiredCount++
                }
                if _, hasCname := sd["cname_target"]; hasCname {
                        cnameCount++
                }
        }

        result["cname_count"] = float64(cnameCount)

        if len(subdomains) > 0 {
                a.enrichSubdomainsV2(ctx, domain, subdomains)
        }

        currentCount = 0
        expiredCount = 0
        for _, sd := range subdomains {
                if isCurrent, ok := sd["is_current"].(bool); ok && isCurrent {
                        currentCount++
                } else {
                        expiredCount++
                }
        }
        result["current_count"] = fmt.Sprintf("%d", currentCount)
        result["expired_count"] = fmt.Sprintf("%d", expiredCount)

        subdomains = sortSubdomainsSmartOrder(subdomains)

        a.setCTCache(domain, subdomains)

        result["unique_subdomains"] = len(subdomains)
        result["ct_source"] = "live"
        _ = dnsProbed

        applySubdomainDisplayCap(result, subdomains, currentCount)

        return result
}

func sortSubdomainsSmartOrder(subdomains []map[string]any) []map[string]any {
        var current, historical []map[string]any
        for _, sd := range subdomains {
                if isCur, ok := sd["is_current"].(bool); ok && isCur {
                        current = append(current, sd)
                } else {
                        historical = append(historical, sd)
                }
        }

        sort.Slice(current, func(i, j int) bool {
                return current[i]["name"].(string) < current[j]["name"].(string)
        })

        sort.Slice(historical, func(i, j int) bool {
                di, _ := historical[i]["first_seen"].(string)
                dj, _ := historical[j]["first_seen"].(string)
                return di > dj
        })

        result := make([]map[string]any, 0, len(current)+len(historical))
        result = append(result, current...)
        result = append(result, historical...)
        return result
}

func applySubdomainDisplayCap(result map[string]any, subdomains []map[string]any, currentCount int) {
        const softCap = 200
        const historicalOverflow = 25

        total := len(subdomains)

        if total <= softCap {
                result["subdomains"] = subdomains
                result["displayed_count"] = total
                return
        }

        var displayLimit int
        if currentCount > softCap {
                displayLimit = currentCount + historicalOverflow
        } else {
                displayLimit = softCap
        }

        if displayLimit >= total {
                result["subdomains"] = subdomains
                result["displayed_count"] = total
                return
        }

        result["subdomains"] = subdomains[:displayLimit]
        result["displayed_count"] = displayLimit
        result["display_capped"] = true
        result["display_current_count"] = currentCount
        result["display_historical_omitted"] = total - displayLimit
}

func deduplicateCTEntries(entries []ctEntry) []ctEntry {
        seen := make(map[string]bool, len(entries))
        deduped := make([]ctEntry, 0, len(entries))
        for _, e := range entries {
                if e.SerialNumber == "" || !seen[e.SerialNumber] {
                        if e.SerialNumber != "" {
                                seen[e.SerialNumber] = true
                        }
                        deduped = append(deduped, e)
                }
        }
        return deduped
}

func detectWildcardCerts(ctEntries []ctEntry, domain string) map[string]any {
        wildcardPattern := "*." + domain
        now := time.Now()
        hasWildcard := false
        isCurrent := false

        sanSet := make(map[string]bool)
        var issuers []string
        issuerSeen := make(map[string]bool)
        certCount := 0
        var latestNotAfter time.Time
        var earliestNotBefore time.Time

        for _, entry := range ctEntries {
                names := strings.Split(entry.NameValue, "\n")
                isWildcardCert := false
                for _, name := range names {
                        name = strings.TrimSpace(strings.ToLower(name))
                        if name == wildcardPattern {
                                isWildcardCert = true
                                break
                        }
                }
                if !isWildcardCert {
                        continue
                }

                hasWildcard = true
                certCount++
                notAfter := parseCertDate(entry.NotAfter)
                notBefore := parseCertDate(entry.NotBefore)
                if notAfter.After(now) {
                        isCurrent = true
                }
                if notAfter.After(latestNotAfter) {
                        latestNotAfter = notAfter
                }
                if earliestNotBefore.IsZero() || notBefore.Before(earliestNotBefore) {
                        earliestNotBefore = notBefore
                }

                issuer := simplifyIssuer(entry.IssuerName)
                if !issuerSeen[issuer] {
                        issuerSeen[issuer] = true
                        if len(issuers) < 10 {
                                issuers = append(issuers, issuer)
                        }
                }

                for _, name := range names {
                        name = strings.TrimSpace(strings.ToLower(name))
                        if name != "" && name != wildcardPattern && name != domain {
                                if strings.HasSuffix(name, "."+domain) || name == domain {
                                        sanSet[name] = true
                                }
                        }
                }
        }

        if !hasWildcard {
                return nil
        }

        var explicitSANs []string
        for san := range sanSet {
                explicitSANs = append(explicitSANs, san)
        }
        sort.Strings(explicitSANs)

        result := map[string]any{
                "present":    true,
                "pattern":    wildcardPattern,
                "current":    isCurrent,
                "cert_count": certCount,
                "issuers":    issuers,
        }

        if len(explicitSANs) > 0 {
                result["explicit_sans"] = explicitSANs
                result["san_count"] = len(explicitSANs)
        }
        if !earliestNotBefore.IsZero() {
                result["earliest"] = earliestNotBefore.Format("2006-01-02")
        }
        if !latestNotAfter.IsZero() {
                result["latest_expiry"] = latestNotAfter.Format("2006-01-02")
        }

        return result
}

func buildCASummary(entries []ctEntry) []map[string]any {
        type caStats struct {
                name        string
                certCount   int
                firstSeen   time.Time
                lastSeen    time.Time
                hasCurrents bool
        }

        now := time.Now()
        caMap := make(map[string]*caStats)
        var caOrder []string

        for _, entry := range entries {
                issuer := simplifyIssuer(entry.IssuerName)
                notBefore := parseCertDate(entry.NotBefore)
                notAfter := parseCertDate(entry.NotAfter)

                stats, exists := caMap[issuer]
                if !exists {
                        stats = &caStats{name: issuer, firstSeen: notBefore, lastSeen: notBefore}
                        caMap[issuer] = stats
                        caOrder = append(caOrder, issuer)
                }
                stats.certCount++
                if !notBefore.IsZero() && notBefore.Before(stats.firstSeen) {
                        stats.firstSeen = notBefore
                }
                if !notBefore.IsZero() && notBefore.After(stats.lastSeen) {
                        stats.lastSeen = notBefore
                }
                if notAfter.After(now) {
                        stats.hasCurrents = true
                }
        }

        sort.Slice(caOrder, func(i, j int) bool {
                return caMap[caOrder[i]].certCount > caMap[caOrder[j]].certCount
        })

        maxCAs := 8
        if len(caOrder) < maxCAs {
                maxCAs = len(caOrder)
        }

        summary := make([]map[string]any, 0, maxCAs)
        for _, name := range caOrder[:maxCAs] {
                s := caMap[name]
                entry := map[string]any{
                        "name":       s.name,
                        "cert_count": s.certCount,
                        "first_seen": s.firstSeen.Format("2006-01-02"),
                        "last_seen":  s.lastSeen.Format("2006-01-02"),
                        "active":     s.hasCurrents,
                }
                summary = append(summary, entry)
        }

        return summary
}

func parseCertDate(s string) time.Time {
        s = strings.TrimSpace(s)
        if s == "" {
                return time.Time{}
        }
        formats := []string{
                "2006-01-02T15:04:05",
                "2006-01-02 15:04:05",
                "2006-01-02",
        }
        for _, fmt := range formats {
                if t, err := time.Parse(fmt, s); err == nil {
                        return t
                }
        }
        if len(s) >= 10 {
                if t, err := time.Parse("2006-01-02", s[:10]); err == nil {
                        return t
                }
        }
        return time.Time{}
}

func processCTEntries(ctEntries []ctEntry, domain string, subdomainSet map[string]map[string]any) {
        now := time.Now()
        for _, entry := range ctEntries {
                names := strings.Split(entry.NameValue, "\n")
                for _, name := range names {
                        name = normalizeCTName(name, domain)
                        if name == "" {
                                continue
                        }

                        isCurrent := parseCertDate(entry.NotAfter).After(now)

                        issuer := simplifyIssuer(entry.IssuerName)

                        if existing, exists := subdomainSet[name]; exists {
                                existing["cert_count"] = fmt.Sprintf("%d", atoi(existing["cert_count"].(string))+1)
                                if isCurrent {
                                        existing["is_current"] = true
                                }
                                if issuers, ok := existing["issuers"].([]string); ok {
                                        found := false
                                        for _, iss := range issuers {
                                                if iss == issuer {
                                                        found = true
                                                        break
                                                }
                                        }
                                        if !found && len(issuers) < 5 {
                                                existing["issuers"] = append(issuers, issuer)
                                        }
                                }
                        } else {
                                subdomainSet[name] = map[string]any{
                                        "name":       name,
                                        "source":     "ct",
                                        "is_current": isCurrent,
                                        "cert_count": "1",
                                        "first_seen": entry.NotBefore,
                                        "issuers":    []string{issuer},
                                }
                        }
                }
        }
}

func (a *Analyzer) probeCommonSubdomains(ctx context.Context, domain string, subdomainSet map[string]map[string]any) int {
        probeCtx, probeCancel := context.WithTimeout(context.Background(), 15*time.Second)
        defer probeCancel()

        found := 0
        var mu sync.Mutex
        var wg sync.WaitGroup

        sem := make(chan struct{}, 20)

        for _, prefix := range commonSubdomainProbes {
                fqdn := prefix + "." + domain

                mu.Lock()
                _, alreadyFound := subdomainSet[fqdn]
                mu.Unlock()
                if alreadyFound {
                        continue
                }

                wg.Add(1)
                sem <- struct{}{}
                go func(name string) {
                        defer wg.Done()
                        defer func() { <-sem }()

                        exists, cnameTarget := a.DNS.ProbeExists(probeCtx, name)
                        if !exists {
                                return
                        }

                        entry := map[string]any{
                                "name":       name,
                                "source":     "dns",
                                "is_current": true,
                                "cert_count": "—",
                                "first_seen": "—",
                                "issuers":    []string{},
                        }

                        if cnameTarget != "" {
                                entry["cname_target"] = cnameTarget
                        }

                        mu.Lock()
                        subdomainSet[name] = entry
                        found++
                        mu.Unlock()
                }(fqdn)
        }

        wg.Wait()
        return found
}

func (a *Analyzer) enrichSubdomainsV2(ctx context.Context, baseDomain string, subdomains []map[string]any) {
        enrichCtx, enrichCancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer enrichCancel()

        maxEnrich := 50
        if len(subdomains) < maxEnrich {
                maxEnrich = len(subdomains)
        }

        var wg sync.WaitGroup
        var mu sync.Mutex
        sem := make(chan struct{}, 20)

        for i := 0; i < maxEnrich; i++ {
                wg.Add(1)
                sem <- struct{}{}
                go func(idx int) {
                        defer wg.Done()
                        defer func() { <-sem }()

                        sd := subdomains[idx]
                        name := sd["name"].(string)

                        if sd["source"] == "dns" {
                                return
                        }

                        exists, cnameTarget := a.DNS.ProbeExists(enrichCtx, name)

                        mu.Lock()
                        if exists {
                                sd["is_current"] = true
                                if cnameTarget != "" {
                                        sd["cname_target"] = cnameTarget
                                }
                        }
                        mu.Unlock()
                }(i)
        }
        wg.Wait()
}

func parseDNAttributes(dn string) []string {
        var parts []string
        var current strings.Builder
        inQuote := false
        for i := 0; i < len(dn); i++ {
                ch := dn[i]
                if ch == '"' {
                        inQuote = !inQuote
                        continue
                }
                if ch == ',' && !inQuote {
                        parts = append(parts, current.String())
                        current.Reset()
                        continue
                }
                current.WriteByte(ch)
        }
        if current.Len() > 0 {
                parts = append(parts, current.String())
        }
        return parts
}

func simplifyIssuer(issuer string) string {
        parts := parseDNAttributes(issuer)
        for _, part := range parts {
                part = strings.TrimSpace(part)
                if strings.HasPrefix(part, "O=") {
                        return strings.TrimSpace(part[2:])
                }
        }
        for _, part := range parts {
                part = strings.TrimSpace(part)
                if strings.HasPrefix(part, "CN=") {
                        return strings.TrimSpace(part[3:])
                }
        }
        if len(issuer) > 40 {
                return issuer[:40] + "..."
        }
        return issuer
}

func atoi(s string) int {
        n := 0
        for _, c := range s {
                if c >= '0' && c <= '9' {
                        n = n*10 + int(c-'0')
                }
        }
        return n
}

func normalizeCTName(name, domain string) string {
        name = strings.TrimSpace(strings.ToLower(name))
        if name == "" || name == domain {
                return ""
        }
        if !strings.HasSuffix(name, "."+domain) {
                return ""
        }
        if strings.HasPrefix(name, "*.") {
                name = name[2:]
        }
        if name == domain {
                return ""
        }
        return name
}
