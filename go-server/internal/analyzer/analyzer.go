// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "context"
        "log/slog"
        "sync"
        "time"

        "dnstool/go-server/internal/dnsclient"
        "dnstool/go-server/internal/telemetry"
)

type Analyzer struct {
        DNS        *dnsclient.Client
        HTTP       *dnsclient.SafeHTTPClient
        SlowHTTP   *dnsclient.SafeHTTPClient
        RDAPHTTP   *dnsclient.SafeHTTPClient
        IANARDAPMap map[string][]string
        Telemetry  *telemetry.Registry
        RDAPCache  *telemetry.TTLCache[map[string]any]

        ctCacheMu  sync.RWMutex
        ctCache    map[string]ctCacheEntry
        ctCacheTTL time.Duration

        maxConcurrent int
        semaphore     chan struct{}

        SMTPProbeMode string
        ProbeAPIURL   string
        ProbeAPIKey   string
}

type ctCacheEntry struct {
        data      []map[string]any
        timestamp time.Time
}

type Option func(*Analyzer)

func WithMaxConcurrent(n int) Option {
        return func(a *Analyzer) {
                a.maxConcurrent = n
                a.semaphore = make(chan struct{}, n)
        }
}

func New(opts ...Option) *Analyzer {
        a := &Analyzer{
                DNS:           dnsclient.New(),
                HTTP:          dnsclient.NewSafeHTTPClient(),
                SlowHTTP:      dnsclient.NewSafeHTTPClientWithTimeout(75 * time.Second),
                RDAPHTTP:      dnsclient.NewRDAPHTTPClient(),
                IANARDAPMap:   make(map[string][]string),
                Telemetry:     telemetry.NewRegistry(),
                RDAPCache:     telemetry.NewTTLCache[map[string]any]("rdap", 500, 24*time.Hour),
                ctCache:       make(map[string]ctCacheEntry),
                ctCacheTTL:    1 * time.Hour,
                maxConcurrent: 6,
                semaphore:     make(chan struct{}, 6),
        }
        for _, o := range opts {
                o(a)
        }

        go a.fetchIANARDAPData()

        return a
}

func (a *Analyzer) fetchIANARDAPData() {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()

        resp, err := a.HTTP.Get(ctx, "https://data.iana.org/rdap/dns.json")
        if err != nil {
                slog.Error("Failed to fetch IANA RDAP data", "error", err)
                return
        }

        body, err := a.HTTP.ReadBody(resp, 1<<20)
        if err != nil {
                slog.Error("Failed to read IANA RDAP response", "error", err)
                return
        }

        var data struct {
                Services [][][]string `json:"services"`
        }

        if err := jsonUnmarshal(body, &data); err != nil {
                slog.Error("Failed to parse IANA RDAP data", "error", err)
                return
        }

        for _, svc := range data.Services {
                if len(svc) != 2 {
                        continue
                }
                tlds, endpoints := svc[0], svc[1]
                if len(tlds) > 0 && len(endpoints) > 0 {
                        for _, tld := range tlds {
                                a.IANARDAPMap[tld] = endpoints
                        }
                }
        }
        slog.Info("Loaded IANA RDAP map", "tld_count", len(a.IANARDAPMap))
}

func (a *Analyzer) getCTCache(domain string) ([]map[string]any, bool) {
        a.ctCacheMu.RLock()
        defer a.ctCacheMu.RUnlock()
        entry, ok := a.ctCache[domain]
        if !ok {
                return nil, false
        }
        if time.Since(entry.timestamp) > a.ctCacheTTL {
                return nil, false
        }
        return entry.data, true
}

func (a *Analyzer) GetCTCache(domain string) ([]map[string]any, bool) {
        return a.getCTCache(domain)
}

func (a *Analyzer) setCTCache(domain string, data []map[string]any) {
        a.ctCacheMu.Lock()
        defer a.ctCacheMu.Unlock()
        a.ctCache[domain] = ctCacheEntry{data: data, timestamp: time.Now()}
        if len(a.ctCache) > 200 {
                cutoff := time.Now().Add(-a.ctCacheTTL)
                for k, v := range a.ctCache {
                        if v.timestamp.Before(cutoff) {
                                delete(a.ctCache, k)
                        }
                }
        }
}
