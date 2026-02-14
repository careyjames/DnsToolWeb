// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
package analyzer

import (
        "bytes"
        "context"
        "encoding/json"
        "fmt"
        "log/slog"
        "net/http"
        "os"
        "sync"
        "time"
)

const contentTypeJSON = "application/json"

const (
        stMonthlyBudget     = 50
        stBudgetReserve     = 5
        stSubdomainCacheTTL = 24 * time.Hour
        stMaxSubdomainCache = 500
        stRateLimitCooldown = 6 * time.Hour
)

var (
        securityTrailsEnabled bool
        securityTrailsAPIKey  string
        securityTrailsOnce    sync.Once

        stBudget = &stAPIBudget{}
)

type stAPIBudget struct {
        mu         sync.Mutex
        callCount  int
        monthKey   string
        rateLimitedAt time.Time
}

func (b *stAPIBudget) canSpend(n int) bool {
        b.mu.Lock()
        defer b.mu.Unlock()

        currentMonth := time.Now().UTC().Format("2006-01")
        if b.monthKey != currentMonth {
                b.callCount = 0
                b.monthKey = currentMonth
                b.rateLimitedAt = time.Time{}
                slog.Info("SecurityTrails budget: new month reset", "month", currentMonth)
        }

        if !b.rateLimitedAt.IsZero() && time.Since(b.rateLimitedAt) < stRateLimitCooldown {
                return false
        }

        return b.callCount+n <= stMonthlyBudget-stBudgetReserve
}

func (b *stAPIBudget) spend(n int) {
        b.mu.Lock()
        defer b.mu.Unlock()
        b.callCount += n
        slog.Info("SecurityTrails budget: spent", "calls", n, "total_this_month", b.callCount, "remaining", stMonthlyBudget-b.callCount)
}

func (b *stAPIBudget) markRateLimited() {
        b.mu.Lock()
        defer b.mu.Unlock()
        b.rateLimitedAt = time.Now()
        slog.Warn("SecurityTrails budget: rate limited, cooling down", "cooldown", stRateLimitCooldown)
}

func (b *stAPIBudget) stats() map[string]any {
        b.mu.Lock()
        defer b.mu.Unlock()
        currentMonth := time.Now().UTC().Format("2006-01")
        if b.monthKey != currentMonth {
                return map[string]any{"month": currentMonth, "used": 0, "budget": stMonthlyBudget, "available": true}
        }
        cooldownActive := !b.rateLimitedAt.IsZero() && time.Since(b.rateLimitedAt) < stRateLimitCooldown
        return map[string]any{
                "month":            b.monthKey,
                "used":             b.callCount,
                "budget":           stMonthlyBudget,
                "available":        b.callCount < stMonthlyBudget-stBudgetReserve && !cooldownActive,
                "cooldown_active":  cooldownActive,
        }
}

func STBudgetAvailable(n int) bool {
        initSecurityTrails()
        if !securityTrailsEnabled {
                return false
        }
        return stBudget.canSpend(n)
}

func STBudgetStats() map[string]any {
        return stBudget.stats()
}

func initSecurityTrails() {
        securityTrailsOnce.Do(func() {
                securityTrailsAPIKey = os.Getenv("SECURITYTRAILS_API_KEY")
                securityTrailsEnabled = securityTrailsAPIKey != ""
                if securityTrailsEnabled {
                        slog.Info("SecurityTrails API enabled")
                }
        })
}

var securityTrailsHTTPClient = &http.Client{
        Timeout: 10 * time.Second,
}

type stSubdomainCacheEntry struct {
        subdomains []string
        cachedAt   time.Time
}

var (
        stSubdomainCache   = make(map[string]*stSubdomainCacheEntry)
        stSubdomainCacheMu sync.RWMutex
)

func getSubdomainCache(domain string) ([]string, bool) {
        stSubdomainCacheMu.RLock()
        defer stSubdomainCacheMu.RUnlock()
        entry, ok := stSubdomainCache[domain]
        if !ok || time.Since(entry.cachedAt) > stSubdomainCacheTTL {
                return nil, false
        }
        result := make([]string, len(entry.subdomains))
        copy(result, entry.subdomains)
        return result, true
}

func setSubdomainCache(domain string, subs []string) {
        stSubdomainCacheMu.Lock()
        defer stSubdomainCacheMu.Unlock()
        if len(stSubdomainCache) >= stMaxSubdomainCache {
                var oldestKey string
                var oldestTime time.Time
                first := true
                for k, e := range stSubdomainCache {
                        if time.Since(e.cachedAt) > stSubdomainCacheTTL {
                                delete(stSubdomainCache, k)
                                continue
                        }
                        if first || e.cachedAt.Before(oldestTime) {
                                oldestKey = k
                                oldestTime = e.cachedAt
                                first = false
                        }
                }
                if len(stSubdomainCache) >= stMaxSubdomainCache && oldestKey != "" {
                        delete(stSubdomainCache, oldestKey)
                }
        }
        cached := make([]string, len(subs))
        copy(cached, subs)
        stSubdomainCache[domain] = &stSubdomainCacheEntry{subdomains: cached, cachedAt: time.Now()}
}

type stSubdomainsResponse struct {
        Subdomains []string `json:"subdomains"`
}

type stSearchResponse struct {
        Records []struct {
                Hostname string `json:"hostname"`
        } `json:"records"`
}

type STFetchStatus struct {
        RateLimited bool
        Errored     bool
}

func FetchSubdomains(ctx context.Context, domain string) ([]string, *STFetchStatus, error) {
        initSecurityTrails()
        if !securityTrailsEnabled {
                return nil, nil, nil
        }

        if cached, ok := getSubdomainCache(domain); ok {
                slog.Info("SecurityTrails subdomains: cache hit", "domain", domain, "count", len(cached))
                return cached, nil, nil
        }

        if !stBudget.canSpend(1) {
                slog.Info("SecurityTrails subdomains: budget exhausted, skipping", "domain", domain)
                return []string{}, nil, nil
        }

        url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains?children_only=false&include_inactive=false", domain)

        req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
        if err != nil {
                slog.Warn("SecurityTrails: failed to create request", "domain", domain, "error", err)
                return []string{}, &STFetchStatus{Errored: true}, nil
        }
        req.Header.Set("APIKEY", securityTrailsAPIKey)
        req.Header.Set("Accept", contentTypeJSON)

        stBudget.spend(1)
        resp, err := securityTrailsHTTPClient.Do(req)
        if err != nil {
                slog.Warn("SecurityTrails: request failed", "domain", domain, "error", err)
                return []string{}, &STFetchStatus{Errored: true}, nil
        }
        defer resp.Body.Close()

        if resp.StatusCode == http.StatusTooManyRequests {
                slog.Warn("SecurityTrails: rate limited (429)", "domain", domain)
                stBudget.markRateLimited()
                return []string{}, &STFetchStatus{RateLimited: true}, nil
        }

        if resp.StatusCode != http.StatusOK {
                slog.Warn("SecurityTrails: unexpected status", "domain", domain, "status", resp.StatusCode)
                return []string{}, &STFetchStatus{Errored: true}, nil
        }

        var stResp stSubdomainsResponse
        if err := json.NewDecoder(resp.Body).Decode(&stResp); err != nil {
                slog.Warn("SecurityTrails: failed to parse response", "domain", domain, "error", err)
                return []string{}, &STFetchStatus{Errored: true}, nil
        }

        fqdns := make([]string, 0, len(stResp.Subdomains))
        for _, label := range stResp.Subdomains {
                if label == "" {
                        continue
                }
                fqdns = append(fqdns, label+"."+domain)
        }

        setSubdomainCache(domain, fqdns)
        slog.Info("SecurityTrails: discovered subdomains", "domain", domain, "count", len(fqdns))
        return fqdns, nil, nil
}

func FetchDomainsByIP(ctx context.Context, ip string) ([]string, error) {
        initSecurityTrails()
        if !securityTrailsEnabled {
                return nil, nil
        }

        payload := map[string]any{
                "filter": map[string]string{
                        "ipv4": ip,
                },
        }
        body, err := json.Marshal(payload)
        if err != nil {
                slog.Warn("SecurityTrails: failed to marshal search payload", "ip", ip, "error", err)
                return []string{}, nil
        }

        req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.securitytrails.com/v1/search/list", bytes.NewReader(body))
        if err != nil {
                slog.Warn("SecurityTrails: failed to create search request", "ip", ip, "error", err)
                return []string{}, nil
        }
        req.Header.Set("APIKEY", securityTrailsAPIKey)
        req.Header.Set("Accept", contentTypeJSON)
        req.Header.Set("Content-Type", contentTypeJSON)

        resp, err := securityTrailsHTTPClient.Do(req)
        if err != nil {
                slog.Warn("SecurityTrails: search request failed", "ip", ip, "error", err)
                return []string{}, nil
        }
        defer resp.Body.Close()

        if resp.StatusCode == http.StatusTooManyRequests {
                slog.Warn("SecurityTrails: rate limited (429)", "ip", ip)
                return []string{}, nil
        }

        if resp.StatusCode != http.StatusOK {
                slog.Warn("SecurityTrails: search unexpected status", "ip", ip, "status", resp.StatusCode)
                return []string{}, nil
        }

        var stResp stSearchResponse
        if err := json.NewDecoder(resp.Body).Decode(&stResp); err != nil {
                slog.Warn("SecurityTrails: failed to parse search response", "ip", ip, "error", err)
                return []string{}, nil
        }

        domains := make([]string, 0, len(stResp.Records))
        for _, rec := range stResp.Records {
                if rec.Hostname != "" {
                        domains = append(domains, rec.Hostname)
                }
        }

        slog.Info("SecurityTrails: discovered domains by IP", "ip", ip, "count", len(domains))
        return domains, nil
}
