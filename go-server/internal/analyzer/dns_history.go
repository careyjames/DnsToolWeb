// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
package analyzer

import (
        "context"
        "encoding/json"
        "fmt"
        "log/slog"
        "net/http"
        "sort"
        "strings"
        "sync"
        "time"
)

const dateFormatISO = "2006-01-02"

const maxHistoryCacheEntries = 500

type DNSHistoryCache struct {
        mu      sync.RWMutex
        entries map[string]*dnsHistoryCacheEntry
        ttl     time.Duration
}

type dnsHistoryCacheEntry struct {
        result   map[string]any
        cachedAt time.Time
}

func NewDNSHistoryCache(ttl time.Duration) *DNSHistoryCache {
        return &DNSHistoryCache{
                entries: make(map[string]*dnsHistoryCacheEntry),
                ttl:     ttl,
        }
}

func (c *DNSHistoryCache) Get(domain string) (map[string]any, bool) {
        c.mu.RLock()
        defer c.mu.RUnlock()

        entry, ok := c.entries[domain]
        if !ok {
                return nil, false
        }
        if time.Since(entry.cachedAt) > c.ttl {
                return nil, false
        }

        cached := make(map[string]any, len(entry.result))
        for k, v := range entry.result {
                cached[k] = v
        }
        cached["cache_hit"] = true
        cached["cached_at"] = entry.cachedAt.UTC().Format(time.RFC3339)
        return cached, true
}

func (c *DNSHistoryCache) Set(domain string, result map[string]any) {
        c.mu.Lock()
        defer c.mu.Unlock()

        if len(c.entries) >= maxHistoryCacheEntries {
                c.evictOldest()
        }
        c.entries[domain] = &dnsHistoryCacheEntry{
                result:   result,
                cachedAt: time.Now(),
        }
}

func (c *DNSHistoryCache) evictOldest() {
        var oldestKey string
        var oldestTime time.Time
        first := true
        for k, e := range c.entries {
                if time.Since(e.cachedAt) > c.ttl {
                        delete(c.entries, k)
                        continue
                }
                if first || e.cachedAt.Before(oldestTime) {
                        oldestKey = k
                        oldestTime = e.cachedAt
                        first = false
                }
        }
        if len(c.entries) >= maxHistoryCacheEntries && oldestKey != "" {
                delete(c.entries, oldestKey)
        }
}

func (c *DNSHistoryCache) Stats() map[string]any {
        c.mu.RLock()
        defer c.mu.RUnlock()
        active := 0
        for _, e := range c.entries {
                if time.Since(e.cachedAt) <= c.ttl {
                        active++
                }
        }
        return map[string]any{
                "total_entries":  len(c.entries),
                "active_entries": active,
                "ttl_hours":      int(c.ttl.Hours()),
                "max_entries":    maxHistoryCacheEntries,
        }
}

type stHistoryResponse struct {
        Records []stHistoryRecord `json:"records"`
        Pages   int               `json:"pages"`
        Type    string            `json:"type"`
}

type stHistoryRecord struct {
        FirstSeen     string           `json:"first_seen"`
        LastSeen      *string          `json:"last_seen"`
        Organizations []string         `json:"organizations"`
        Values        []stHistoryValue `json:"values"`
}

type stHistoryValue struct {
        IP      string `json:"ip"`
        IPCount int    `json:"ip_count"`
        Host    string `json:"host,omitempty"`
}

type dnsChangeEvent struct {
        RecordType  string
        Value       string
        Action      string
        Date        string
        Org         string
        Description string
        DaysAgo     int
}

type historyFetchResult struct {
        changes     []dnsChangeEvent
        rateLimited bool
        errored     bool
}

func FetchDNSHistory(ctx context.Context, domain string, cache *DNSHistoryCache) map[string]any {
        initSecurityTrails()
        if !securityTrailsEnabled {
                return map[string]any{
                        "available":   false,
                        "api_enabled": false,
                        "status":      "disabled",
                }
        }

        if cache != nil {
                if cached, ok := cache.Get(domain); ok {
                        slog.Info("DNS history cache hit", "domain", domain)
                        return cached
                }
        }

        recordTypes := []string{"a", "aaaa", "mx", "ns"}

        if !stBudget.canSpend(len(recordTypes)) {
                slog.Info("DNS history: budget exhausted, skipping", "domain", domain)
                return map[string]any{
                        "available":   false,
                        "api_enabled": true,
                        "status":      "budget_exhausted",
                }
        }

        type indexedResult struct {
                idx    int
                result historyFetchResult
        }
        resultsCh := make(chan indexedResult, len(recordTypes))
        for i, rtype := range recordTypes {
                go func(idx int, rt string) {
                        resultsCh <- indexedResult{idx, fetchHistoryForType(ctx, domain, rt)}
                }(i, rtype)
        }

        var allChanges []dnsChangeEvent
        rateLimitedCount := 0
        errorCount := 0
        for range recordTypes {
                ir := <-resultsCh
                allChanges = append(allChanges, ir.result.changes...)
                if ir.result.rateLimited {
                        rateLimitedCount++
                }
                if ir.result.errored {
                        errorCount++
                }
        }

        sort.Slice(allChanges, func(i, j int) bool {
                return allChanges[i].Date > allChanges[j].Date
        })

        maxChanges := 15
        if len(allChanges) > maxChanges {
                allChanges = allChanges[:maxChanges]
        }

        changesMaps := make([]map[string]any, len(allChanges))
        for i, ch := range allChanges {
                changesMaps[i] = map[string]any{
                        "record_type": ch.RecordType,
                        "value":       ch.Value,
                        "action":      ch.Action,
                        "date":        ch.Date,
                        "org":         ch.Org,
                        "description": ch.Description,
                        "days_ago":    float64(ch.DaysAgo),
                }
        }

        failedCount := rateLimitedCount + errorCount
        allFailed := failedCount == len(recordTypes)
        allRateLimited := rateLimitedCount == len(recordTypes)
        anyFailed := failedCount > 0
        fullyChecked := failedCount == 0

        status := determineHistoryStatus(allRateLimited, allFailed, anyFailed)

        result := map[string]any{
                "available":      !allFailed,
                "api_enabled":    true,
                "has_changes":    len(allChanges) > 0,
                "changes":       changesMaps,
                "total_events":  float64(len(allChanges)),
                "source":        "SecurityTrails",
                "status":        status,
                "rate_limited":  rateLimitedCount > 0,
                "fully_checked": fullyChecked,
        }

        if cache != nil && (status == "success" || status == "partial") {
                cache.Set(domain, result)
                slog.Info("DNS history cached", "domain", domain, "status", status, "ttl", cache.ttl)
        }

        return result
}

func determineHistoryStatus(allRateLimited, allFailed, anyFailed bool) string {
        if allRateLimited {
                return "rate_limited"
        }
        if allFailed {
                return "error"
        }
        if anyFailed {
                return "partial"
        }
        return "success"
}

func fetchHistoryForType(ctx context.Context, domain, rtype string) historyFetchResult {
        url := fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/%s", domain, rtype)

        req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
        if err != nil {
                slog.Warn("SecurityTrails history: failed to create request", "domain", domain, "type", rtype, "error", err)
                return historyFetchResult{errored: true}
        }
        req.Header.Set("APIKEY", securityTrailsAPIKey)
        req.Header.Set("Accept", contentTypeJSON)

        stBudget.spend(1)
        resp, err := securityTrailsHTTPClient.Do(req)
        if err != nil {
                slog.Warn("SecurityTrails history: request failed", "domain", domain, "type", rtype, "error", err)
                return historyFetchResult{errored: true}
        }
        defer resp.Body.Close()

        if resp.StatusCode == http.StatusTooManyRequests {
                slog.Warn("SecurityTrails history: rate limited", "domain", domain, "type", rtype)
                stBudget.markRateLimited()
                return historyFetchResult{rateLimited: true}
        }

        if resp.StatusCode != http.StatusOK {
                slog.Warn("SecurityTrails history: unexpected status", "domain", domain, "type", rtype, "status", resp.StatusCode)
                return historyFetchResult{errored: true}
        }

        var histResp stHistoryResponse
        if err := json.NewDecoder(resp.Body).Decode(&histResp); err != nil {
                slog.Warn("SecurityTrails history: parse failed", "domain", domain, "type", rtype, "error", err)
                return historyFetchResult{errored: true}
        }

        now := time.Now()
        upperType := strings.ToUpper(rtype)
        var changes []dnsChangeEvent

        for _, rec := range histResp.Records {
                value := extractHistoryValue(rec, rtype)
                if value == "" {
                        continue
                }

                firstSeen, _ := time.Parse(dateFormatISO, rec.FirstSeen)

                var daysActive int
                var daysSinceGone int

                if rec.LastSeen != nil {
                        lastSeen, _ := time.Parse(dateFormatISO, *rec.LastSeen)
                        daysActive = int(lastSeen.Sub(firstSeen).Hours() / 24)
                        daysSinceGone = int(now.Sub(lastSeen).Hours() / 24)
                } else {
                        daysActive = int(now.Sub(firstSeen).Hours() / 24)
                }

                orgLabel := ""
                if len(rec.Organizations) > 0 {
                        orgLabel = rec.Organizations[0]
                }

                changes = append(changes, dnsChangeEvent{
                        RecordType:  upperType,
                        Value:       value,
                        Action:      "added",
                        Date:        rec.FirstSeen,
                        Org:         orgLabel,
                        Description: buildChangeDescription(upperType, value, "added", orgLabel, daysActive),
                        DaysAgo:     int(now.Sub(firstSeen).Hours() / 24),
                })

                if rec.LastSeen != nil {
                        lastSeen, _ := time.Parse(dateFormatISO, *rec.LastSeen)
                        changes = append(changes, dnsChangeEvent{
                                RecordType:  upperType,
                                Value:       value,
                                Action:      "removed",
                                Date:        *rec.LastSeen,
                                Org:         orgLabel,
                                Description: buildChangeDescription(upperType, value, "removed", orgLabel, daysSinceGone),
                                DaysAgo:     int(now.Sub(lastSeen).Hours() / 24),
                        })
                }
        }

        slog.Info("SecurityTrails history: fetched", "domain", domain, "type", rtype, "events", len(changes))
        return historyFetchResult{changes: changes}
}

func extractHistoryValue(rec stHistoryRecord, rtype string) string {
        if len(rec.Values) == 0 {
                return ""
        }
        v := rec.Values[0]
        switch rtype {
        case "a", "aaaa":
                return v.IP
        case "mx", "ns":
                if v.Host != "" {
                        return v.Host
                }
                return v.IP
        default:
                if v.IP != "" {
                        return v.IP
                }
                return v.Host
        }
}

func buildChangeDescription(rtype, value, action, org string, daysMetric int) string {
        timeLabel := formatDaysAgo(daysMetric)

        switch action {
        case "added":
                if org != "" {
                        return fmt.Sprintf("%s record %s (%s) appeared %s", rtype, value, org, timeLabel)
                }
                return fmt.Sprintf("%s record %s appeared %s", rtype, value, timeLabel)
        case "removed":
                if org != "" {
                        return fmt.Sprintf("%s record %s (%s) was removed %s", rtype, value, org, timeLabel)
                }
                return fmt.Sprintf("%s record %s was removed %s", rtype, value, timeLabel)
        default:
                return fmt.Sprintf("%s record %s changed %s", rtype, value, timeLabel)
        }
}

func formatDaysAgo(days int) string {
        if days == 0 {
                return "today"
        }
        if days == 1 {
                return "yesterday"
        }
        if days < 7 {
                return fmt.Sprintf("%d days ago", days)
        }
        if days < 30 {
                weeks := days / 7
                if weeks == 1 {
                        return "1 week ago"
                }
                return fmt.Sprintf("%d weeks ago", weeks)
        }
        if days < 365 {
                months := days / 30
                if months == 1 {
                        return "1 month ago"
                }
                return fmt.Sprintf("%d months ago", months)
        }
        years := days / 365
        if years == 1 {
                return "1 year ago"
        }
        return fmt.Sprintf("%d years ago", years)
}
