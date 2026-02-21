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
        "www", "www1", "www2", "www3", "web", "web1", "web2", "m", "mobile",
        "mail", "mail1", "mail2", "mail3", "email", "webmail", "smtp", "smtp1", "smtp2",
        "pop", "pop3", "imap", "mx", "mx1", "mx2", "mx3", "mx4", "mx5", "relay", "relay1", "mta",
        "autodiscover", "autoconfig", "owa", "exchange", "outlook",
        "ftp", "ftp1", "ftp2", "sftp", "ssh", "scp",
        "vpn", "vpn1", "vpn2", "vpn3", "remote", "ra", "gateway", "gw", "gw1", "gw2",
        "api", "api1", "api2", "api3", "apis", "rest", "graphql", "ws",
        "app", "app1", "app2", "apps", "portal", "portal2", "hub",
        "admin", "admin1", "admin2", "panel", "cpanel", "whm", "plesk",
        "dashboard", "console", "manage", "management", "manager",
        "server", "server1", "server2", "server3", "srv", "srv1", "srv2",
        "blog", "news", "press", "media", "wiki", "docs", "doc", "documentation",
        "help", "helpdesk", "support", "support2", "kb", "faq",
        "shop", "store", "ecommerce", "cart", "billing", "pay", "payment", "payments",
        "checkout", "invoice", "orders", "order",
        "sso", "auth", "oauth", "login", "signin", "id", "identity",
        "accounts", "account", "myaccount", "my", "profile", "signup", "register",
        "dev", "dev1", "dev2", "develop", "developer", "developers",
        "staging", "stg", "stage", "test", "test1", "test2", "testing",
        "demo", "sandbox", "beta", "alpha", "preview", "uat", "qa", "preprod", "pre",
        "cdn", "cdn1", "cdn2", "cdn3", "static", "static1", "static2",
        "assets", "media", "img", "images", "image", "photos", "video", "videos",
        "ns", "ns1", "ns2", "ns3", "ns4", "ns5", "ns6", "dns", "dns1", "dns2",
        "cloud", "host", "hosting", "vps", "dedicated",
        "db", "db1", "db2", "database", "sql", "mysql", "postgres", "mongo", "mongodb",
        "monitor", "monitoring", "status", "uptime", "health", "healthcheck",
        "grafana", "prometheus", "nagios", "zabbix", "kibana", "datadog",
        "git", "gitlab", "github", "repo", "repos", "bitbucket", "svn", "code",
        "ci", "cd", "jenkins", "build", "builds", "deploy", "deployment", "releases",
        "calendar", "cal", "meet", "meeting", "video", "chat", "conference",
        "webinar", "live", "stream", "streaming",
        "crm", "erp", "hr", "hris", "payroll", "finance", "accounting",
        "intranet", "internal", "corp", "corporate", "hq",
        "proxy", "proxy1", "proxy2", "lb", "loadbalancer", "haproxy", "nginx",
        "secure", "ssl", "tls", "ocsp", "crl", "pki", "ca", "cert", "certs",
        "files", "file", "download", "downloads", "upload", "uploads", "backup", "share",
        "forum", "forums", "community", "discuss", "discussions",
        "office", "o365", "work", "connect", "workspace",
        "analytics", "stats", "statistics", "metrics", "logs", "log", "tracking",
        "search", "es", "elastic", "elasticsearch", "solr",
        "cache", "redis", "memcached", "varnish",
        "queue", "mq", "rabbitmq", "kafka", "broker",
        "s3", "storage", "bucket", "blob", "object",
        "map", "maps", "geo", "location", "gis",
        "confluence", "jira", "ticket", "tickets", "servicedesk", "itsm",
        "slack", "teams", "zoom", "webex",
        "reports", "report", "reporting", "bi",
        "schedule", "booking", "appointments", "reservations",
        "tools", "tool", "utility",
        "client", "clients", "partner", "partners", "vendor", "vendors",
        "training", "learn", "learning", "lms", "academy", "courses", "education",
        "inventory", "catalog", "products", "product",
        "notify", "notifications", "alerts", "alert",
        "print", "printer", "scan", "scanner",
        "backup1", "backup2", "archive", "archives",
        "voip", "sip", "phone", "pbx", "tel", "telecom",
        "mdm", "devices", "endpoint",
        "edge", "edge1", "edge2", "waf", "firewall", "fw",
        "data", "data1", "data2", "bigdata", "warehouse", "etl",
        "service", "services", "svc", "microservices",
        "gateway", "apigw", "kong",
        "registry", "docker", "k8s", "kubernetes", "containers", "rancher",
        "vault", "secrets", "config", "configuration",
        "auth0", "okta", "adfs", "ldap", "ad", "directory",
        "cms", "content", "drupal", "wordpress", "wp",
        "marketing", "campaign", "campaigns", "promo",
        "feedback", "survey", "surveys", "forms",
        "careers", "jobs", "recruit", "hiring", "talent",
        "legal", "compliance", "policy", "policies", "terms", "privacy",
        "investor", "investors", "ir",
        "events", "event", "webinars",
        "network", "net", "lan", "wan",
        "it", "itsupport", "techsupport",
        "cname", "redirect",
        "origin", "origin1", "origin2",
        "primary", "secondary",
        "a", "b", "c", "d", "e", "f",
        "node1", "node2", "node3", "worker", "worker1", "worker2",
        "us", "eu", "ap", "asia", "na", "emea", "apac",
        "us-east", "us-west", "eu-west", "ap-south",
        "int", "ext", "public", "private",
        "go", "swift", "link", "links", "url", "r",
        "feeds", "feed", "rss", "atom", "xml",
        "websocket", "socket", "realtime", "rt",
        "metrics", "trace", "tracing", "apm",
        "sandbox1", "sandbox2", "lab", "labs",
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
                "ct_available":      true,
        }

        if cached, ok := a.getCTCache(domain); ok {
                result["unique_subdomains"] = len(cached)
                result["ct_source"] = "cache"
                result["ct_available"] = true

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
        ctFailureReason := ""

        if a.Telemetry.InCooldown(ctProvider) {
                slog.Info("CT provider in cooldown, skipping", "domain", domain)
                ctAvailable = false
                ctFailureReason = "cooldown"
        } else {
                ctEntries, ctAvailable, ctFailureReason = a.fetchCTWithRetry(domain, ctProvider)
        }

        if !ctAvailable || len(ctEntries) == 0 {
                csEntries, csOK := a.fetchCertspotter(domain)
                if csOK && len(csEntries) > 0 {
                        ctEntries = csEntries
                        ctAvailable = true
                        ctFailureReason = ""
                        result["ct_source_fallback"] = "certspotter"
                        slog.Info("Certspotter fallback succeeded", "domain", domain, "entries", len(csEntries))
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

        a.probeCommonSubdomains(ctx, domain, subdomainSet)

        if ctAvailable && len(dedupedEntries) > 0 {
                enrichDNSWithCTData(dedupedEntries, domain, subdomainSet)
        }

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
        result["ct_available"] = ctAvailable
        if !ctAvailable {
                result["ct_failure_reason"] = ctFailureReason
        }
        applySubdomainDisplayCap(result, subdomains, currentCount)

        return result
}

func (a *Analyzer) fetchCTWithRetry(domain, ctProvider string) ([]ctEntry, bool, string) {
        const maxAttempts = 2
        ctURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json&exclude=expired", domain)

        totalBudget, totalCancel := context.WithTimeout(context.Background(), 90*time.Second)
        defer totalCancel()

        var lastErr string
        for attempt := 1; attempt <= maxAttempts; attempt++ {
                if totalBudget.Err() != nil {
                        break
                }
                ctCtx, ctCancel := context.WithTimeout(totalBudget, 75*time.Second)
                start := time.Now()
                resp, err := a.SlowHTTP.Get(ctCtx, ctURL)
                if err != nil {
                        lastErr = err.Error()
                        a.Telemetry.RecordFailure(ctProvider, lastErr)
                        slog.Warn("CT log query failed", "domain", domain, "attempt", attempt, "error", err, "elapsed_ms", time.Since(start).Milliseconds())
                        ctCancel()
                        if attempt < maxAttempts {
                                time.Sleep(time.Duration(attempt*2) * time.Second)
                        }
                        continue
                }

                body, err := a.HTTP.ReadBody(resp, 20<<20)
                if err != nil {
                        lastErr = err.Error()
                        a.Telemetry.RecordFailure(ctProvider, lastErr)
                        ctCancel()
                        if attempt < maxAttempts {
                                time.Sleep(time.Duration(attempt*2) * time.Second)
                        }
                        continue
                }
                if resp.StatusCode != 200 {
                        lastErr = fmt.Sprintf("HTTP %d", resp.StatusCode)
                        a.Telemetry.RecordFailure(ctProvider, lastErr)
                        ctCancel()
                        if resp.StatusCode >= 400 && resp.StatusCode < 500 {
                                return nil, false, "error"
                        }
                        if attempt < maxAttempts {
                                time.Sleep(time.Duration(attempt*2) * time.Second)
                        }
                        continue
                }

                var entries []ctEntry
                if json.Unmarshal(body, &entries) != nil {
                        lastErr = "JSON parse error"
                        ctCancel()
                        return nil, false, "error"
                }

                elapsed := time.Since(start)
                a.Telemetry.RecordSuccess(ctProvider, elapsed)
                slog.Info("CT log query succeeded", "domain", domain, "attempt", attempt, "entries", len(entries), "elapsed_ms", elapsed.Milliseconds())
                ctCancel()

                if len(entries) == 0 && totalBudget.Err() == nil {
                        ctURL2 := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
                        ctCtx2, ctCancel2 := context.WithTimeout(totalBudget, 75*time.Second)
                        start2 := time.Now()
                        resp2, err2 := a.SlowHTTP.Get(ctCtx2, ctURL2)
                        if err2 == nil {
                                body2, err3 := a.HTTP.ReadBody(resp2, 20<<20)
                                if err3 == nil && resp2.StatusCode == 200 {
                                        var allEntries []ctEntry
                                        if json.Unmarshal(body2, &allEntries) == nil && len(allEntries) > 0 {
                                                a.Telemetry.RecordSuccess(ctProvider, time.Since(start2))
                                                ctCancel2()
                                                return allEntries, true, ""
                                        }
                                }
                        }
                        ctCancel2()
                }

                return entries, true, ""
        }

        reason := "timeout"
        if lastErr != "" && !strings.Contains(lastErr, "deadline") && !strings.Contains(lastErr, "timeout") {
                reason = "error"
        }
        return nil, false, reason
}

type certspotterEntry struct {
        ID        string   `json:"id"`
        DNSNames  []string `json:"dns_names"`
        NotBefore string   `json:"not_before"`
        NotAfter  string   `json:"not_after"`
}

func (a *Analyzer) fetchCertspotter(domain string) ([]ctEntry, bool) {
        const maxPages = 10
        budgetCtx, budgetCancel := context.WithTimeout(context.Background(), 60*time.Second)
        defer budgetCancel()

        var allEntries []ctEntry
        cursor := ""

        for page := 0; page < maxPages; page++ {
                if budgetCtx.Err() != nil {
                        break
                }

                csURL := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
                if cursor != "" {
                        csURL += "&after=" + cursor
                }

                pageCtx, pageCancel := context.WithTimeout(budgetCtx, 15*time.Second)
                resp, err := a.HTTP.Get(pageCtx, csURL)
                if err != nil {
                        slog.Warn("Certspotter query failed", "domain", domain, "page", page, "error", err)
                        pageCancel()
                        if page > 0 {
                                break
                        }
                        return nil, false
                }
                body, err := a.HTTP.ReadBody(resp, 10<<20)
                pageCancel()
                if err != nil || resp.StatusCode != 200 {
                        slog.Warn("Certspotter bad response", "domain", domain, "page", page, "status", resp.StatusCode)
                        if page > 0 {
                                break
                        }
                        return nil, false
                }

                var csEntries []certspotterEntry
                if json.Unmarshal(body, &csEntries) != nil {
                        if page > 0 {
                                break
                        }
                        return nil, false
                }

                for _, cs := range csEntries {
                        nameValue := strings.Join(cs.DNSNames, "\n")
                        allEntries = append(allEntries, ctEntry{
                                NameValue: nameValue,
                                NotBefore: cs.NotBefore,
                                NotAfter:  cs.NotAfter,
                        })
                }

                if len(csEntries) < 100 {
                        break
                }

                cursor = csEntries[len(csEntries)-1].ID
                slog.Info("Certspotter pagination", "domain", domain, "page", page+1, "entries_so_far", len(allEntries))
        }

        if len(allEntries) == 0 {
                return nil, false
        }

        slog.Info("Certspotter query succeeded", "domain", domain, "total_entries", len(allEntries))
        return allEntries, true
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
        result["was_truncated"] = true
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

func enrichDNSWithCTData(ctEntries []ctEntry, domain string, subdomainSet map[string]map[string]any) {
        now := time.Now()
        for name, entry := range subdomainSet {
                src, _ := entry["source"].(string)
                if src != "dns" {
                        continue
                }
                certCount := 0
                var firstSeen time.Time
                issuersMap := make(map[string]bool)
                var issuersList []string

                for _, ct := range ctEntries {
                        names := strings.Split(ct.NameValue, "\n")
                        covers := false
                        for _, n := range names {
                                n = strings.TrimSpace(strings.ToLower(n))
                                if n == name {
                                        covers = true
                                        break
                                }
                                if strings.HasPrefix(n, "*.") && strings.HasSuffix(name, n[1:]) {
                                        covers = true
                                        break
                                }
                        }
                        if !covers {
                                continue
                        }
                        certCount++
                        notBefore := parseCertDate(ct.NotBefore)
                        if !notBefore.IsZero() && (firstSeen.IsZero() || notBefore.Before(firstSeen)) {
                                firstSeen = notBefore
                        }
                        notAfter := parseCertDate(ct.NotAfter)
                        if notAfter.After(now) {
                                entry["is_current"] = true
                        }
                        issuer := simplifyIssuer(ct.IssuerName)
                        if issuer != "" && !issuersMap[issuer] && len(issuersList) < 5 {
                                issuersMap[issuer] = true
                                issuersList = append(issuersList, issuer)
                        }
                }

                if certCount > 0 {
                        entry["cert_count"] = fmt.Sprintf("%d", certCount)
                        if !firstSeen.IsZero() {
                                entry["first_seen"] = firstSeen.Format("2006-01-02")
                        }
                        if len(issuersList) > 0 {
                                entry["issuers"] = issuersList
                        }
                }
        }
}

func (a *Analyzer) probeCommonSubdomains(ctx context.Context, domain string, subdomainSet map[string]map[string]any) int {
        probeCtx, probeCancel := context.WithTimeout(context.Background(), 25*time.Second)
        defer probeCancel()

        found := 0
        var mu sync.Mutex
        var wg sync.WaitGroup

        sem := make(chan struct{}, 30)

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
