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

func (a *Analyzer) DiscoverSubdomains(ctx context.Context, domain string) map[string]any {
        result := map[string]any{
                "status":            "success",
                "subdomains":        []map[string]any{},
                "unique_subdomains": 0,
                "total_certs":       0,
                "source":            "Certificate Transparency Logs",
        }

        if cached, ok := a.getCTCache(domain); ok {
                result["subdomains"] = cached
                result["unique_subdomains"] = len(cached)
                result["ct_source"] = "cache"
                return result
        }

        ctProvider := "ct:crt.sh"
        if a.Telemetry.InCooldown(ctProvider) {
                slog.Info("CT provider in cooldown, skipping", "domain", domain)
                result["status"] = "warning"
                result["message"] = "Certificate Transparency service temporarily unavailable"
                return result
        }

        ctURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
        start := time.Now()
        resp, err := a.SlowHTTP.Get(ctx, ctURL)
        if err != nil {
                a.Telemetry.RecordFailure(ctProvider, err.Error())
                slog.Warn("CT log query failed", "domain", domain, "error", err)
                result["status"] = "warning"
                result["message"] = "Certificate Transparency lookup failed"
                return result
        }

        body, err := a.HTTP.ReadBody(resp, 2<<20)
        if err != nil {
                a.Telemetry.RecordFailure(ctProvider, err.Error())
                result["status"] = "warning"
                result["message"] = "Failed to read CT response"
                return result
        }

        if resp.StatusCode != 200 {
                a.Telemetry.RecordFailure(ctProvider, fmt.Sprintf("HTTP %d", resp.StatusCode))
                result["status"] = "warning"
                result["message"] = fmt.Sprintf("CT log returned HTTP %d", resp.StatusCode)
                return result
        }

        a.Telemetry.RecordSuccess(ctProvider, time.Since(start))

        var ctEntries []ctEntry
        if json.Unmarshal(body, &ctEntries) != nil {
                result["status"] = "warning"
                result["message"] = "Failed to parse CT response"
                return result
        }

        result["total_certs"] = len(ctEntries)

        subdomains := deduplicateCTEntries(ctEntries, domain)

        if len(subdomains) > 0 {
                a.enrichSubdomains(ctx, domain, subdomains)
        }

        a.setCTCache(domain, subdomains)

        result["subdomains"] = subdomains
        result["unique_subdomains"] = len(subdomains)
        result["ct_source"] = "live"

        return result
}

func (a *Analyzer) enrichSubdomains(ctx context.Context, baseDomain string, subdomains []map[string]any) {
        maxEnrich := 30
        if len(subdomains) < maxEnrich {
                maxEnrich = len(subdomains)
        }

        var wg sync.WaitGroup
        var mu sync.Mutex

        for i := 0; i < maxEnrich; i++ {
                wg.Add(1)
                go func(idx int) {
                        defer wg.Done()
                        sd := subdomains[idx]
                        name := sd["subdomain"].(string)

                        aRecords := a.DNS.QueryDNS(ctx, "A", name)
                        cnameRecords := a.DNS.QueryDNS(ctx, "CNAME", name)

                        mu.Lock()
                        sd["has_dns"] = len(aRecords) > 0
                        if len(cnameRecords) > 0 {
                                sd["cname"] = cnameRecords[0]
                        }
                        mu.Unlock()
                }(i)
        }
        wg.Wait()
}

func deduplicateCTEntries(ctEntries []ctEntry, domain string) []map[string]any {
        subdomainSet := make(map[string]map[string]any)
        for _, entry := range ctEntries {
                processOneEntry(entry, domain, subdomainSet)
        }

        var subdomains []map[string]any
        for _, sd := range subdomainSet {
                subdomains = append(subdomains, sd)
        }

        sort.Slice(subdomains, func(i, j int) bool {
                return subdomains[i]["subdomain"].(string) < subdomains[j]["subdomain"].(string)
        })
        return subdomains
}

func processOneEntry(entry ctEntry, domain string, subdomainSet map[string]map[string]any) {
        names := strings.Split(entry.NameValue, "\n")
        for _, name := range names {
                name = normalizeCTName(name, domain)
                if name == "" {
                        continue
                }
                addOrIncrementSubdomain(subdomainSet, name, entry)
        }
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

func addOrIncrementSubdomain(subdomainSet map[string]map[string]any, name string, entry ctEntry) {
        if _, exists := subdomainSet[name]; !exists {
                subdomainSet[name] = map[string]any{
                        "subdomain":  name,
                        "not_before": entry.NotBefore,
                        "not_after":  entry.NotAfter,
                        "issuer":     entry.IssuerName,
                        "cert_count": 1,
                }
        } else {
                subdomainSet[name]["cert_count"] = subdomainSet[name]["cert_count"].(int) + 1
        }
}
