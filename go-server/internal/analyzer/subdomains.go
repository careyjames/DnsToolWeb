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
        NameValue  string `json:"name_value"`
        CommonName string `json:"common_name"`
        NotBefore  string `json:"not_before"`
        NotAfter   string `json:"not_after"`
        IssuerName string `json:"issuer_name"`
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
                result["subdomains"] = cached
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
                return result
        }

        ctProvider := "ct:crt.sh"
        var ctEntries []ctEntry
        ctAvailable := true

        if a.Telemetry.InCooldown(ctProvider) {
                slog.Info("CT provider in cooldown, skipping", "domain", domain)
                ctAvailable = false
        } else {
                ctURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
                start := time.Now()
                resp, err := a.SlowHTTP.Get(ctx, ctURL)
                if err != nil {
                        a.Telemetry.RecordFailure(ctProvider, err.Error())
                        slog.Warn("CT log query failed", "domain", domain, "error", err)
                        ctAvailable = false
                } else {
                        body, err := a.HTTP.ReadBody(resp, 2<<20)
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

        if ctAvailable {
                result["total_certs"] = len(ctEntries)
        }

        wildcardInfo := detectWildcardCerts(ctEntries, domain)
        if wildcardInfo != nil {
                result["wildcard_certs"] = wildcardInfo
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

        sort.Slice(subdomains, func(i, j int) bool {
                si := subdomains[i]["name"].(string)
                sj := subdomains[j]["name"].(string)
                return si < sj
        })

        result["current_count"] = fmt.Sprintf("%d", currentCount)
        result["expired_count"] = fmt.Sprintf("%d", expiredCount)
        result["cname_count"] = float64(cnameCount)

        if len(subdomains) > 0 {
                a.enrichSubdomainsV2(ctx, domain, subdomains)
        }

        a.setCTCache(domain, subdomains)

        result["subdomains"] = subdomains
        result["unique_subdomains"] = len(subdomains)
        result["ct_source"] = "live"
        _ = dnsProbed

        return result
}

func detectWildcardCerts(ctEntries []ctEntry, domain string) map[string]any {
        wildcardPattern := "*." + domain
        now := time.Now()
        hasWildcard := false
        isCurrent := false

        for _, entry := range ctEntries {
                names := strings.Split(entry.NameValue, "\n")
                for _, name := range names {
                        name = strings.TrimSpace(strings.ToLower(name))
                        if name == wildcardPattern {
                                hasWildcard = true
                                if parseCertDate(entry.NotAfter).After(now) {
                                        isCurrent = true
                                }
                        }
                }
        }

        if !hasWildcard {
                return nil
        }

        return map[string]any{
                "present": true,
                "pattern": wildcardPattern,
                "current": isCurrent,
        }
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
        found := 0
        var mu sync.Mutex
        var wg sync.WaitGroup

        sem := make(chan struct{}, 10)

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

                        aRecords := a.DNS.QueryDNS(ctx, "A", name)
                        aaaaRecords := a.DNS.QueryDNS(ctx, "AAAA", name)
                        cnameRecords := a.DNS.QueryDNS(ctx, "CNAME", name)

                        if len(aRecords) == 0 && len(aaaaRecords) == 0 && len(cnameRecords) == 0 {
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

                        if len(cnameRecords) > 0 {
                                entry["cname_target"] = cnameRecords[0]
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
        maxEnrich := 50
        if len(subdomains) < maxEnrich {
                maxEnrich = len(subdomains)
        }

        var wg sync.WaitGroup
        var mu sync.Mutex
        sem := make(chan struct{}, 10)

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

                        aRecords := a.DNS.QueryDNS(ctx, "A", name)
                        cnameRecords := a.DNS.QueryDNS(ctx, "CNAME", name)

                        mu.Lock()
                        if len(aRecords) > 0 || len(cnameRecords) > 0 {
                                sd["is_current"] = true
                        }
                        if len(cnameRecords) > 0 {
                                sd["cname_target"] = cnameRecords[0]
                        }
                        mu.Unlock()
                }(i)
        }
        wg.Wait()
}

func simplifyIssuer(issuer string) string {
        parts := strings.Split(issuer, ",")
        for _, part := range parts {
                part = strings.TrimSpace(part)
                if strings.HasPrefix(part, "O=") {
                        return part[2:]
                }
        }
        for _, part := range parts {
                part = strings.TrimSpace(part)
                if strings.HasPrefix(part, "CN=") {
                        return part[3:]
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
