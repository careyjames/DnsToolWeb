package analyzer

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

type CachedAnalysis struct {
	Results   map[string]any
	CachedAt  time.Time
	Domain    string
	FromCache bool
}

type AnalysisCache struct {
	mu      sync.RWMutex
	entries map[string]*CachedAnalysis
	ttl     time.Duration
}

var (
	topDomains = []string{
		"it-help.tech",
		"google.com",
		"cia.gov",
		"ietf.org",
		"microsoft.com",
		"cloudflare.com",
		"protonmail.com",
		"apple.com",
		"amazon.com",
		"github.com",
	}
)

func NewAnalysisCache(ttl time.Duration) *AnalysisCache {
	return &AnalysisCache{
		entries: make(map[string]*CachedAnalysis),
		ttl:     ttl,
	}
}

func (c *AnalysisCache) Get(domain string) (*CachedAnalysis, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[domain]
	if !ok {
		return nil, false
	}

	if time.Since(entry.CachedAt) > c.ttl {
		return nil, false
	}

	result := &CachedAnalysis{
		Results:   entry.Results,
		CachedAt:  entry.CachedAt,
		Domain:    entry.Domain,
		FromCache: true,
	}
	return result, true
}

func (c *AnalysisCache) Set(domain string, results map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[domain] = &CachedAnalysis{
		Results:  results,
		CachedAt: time.Now(),
		Domain:   domain,
	}
}

func (c *AnalysisCache) Stats() map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cached := make([]map[string]any, 0, len(c.entries))
	for domain, entry := range c.entries {
		age := time.Since(entry.CachedAt)
		stale := age > c.ttl
		cached = append(cached, map[string]any{
			"domain":   domain,
			"age_mins": int(age.Minutes()),
			"stale":    stale,
		})
	}

	return map[string]any{
		"cached_domains": cached,
		"total":          len(c.entries),
		"ttl_mins":       int(c.ttl.Minutes()),
	}
}

func (c *AnalysisCache) IsTopDomain(domain string) bool {
	for _, d := range topDomains {
		if d == domain {
			return true
		}
	}
	return false
}

func (a *Analyzer) WarmCache(cache *AnalysisCache) {
	go func() {
		slog.Info("Pre-cache: starting warm-up for top domains", "count", len(topDomains))
		warmed := 0
		for _, domain := range topDomains {
			if _, ok := cache.Get(domain); ok {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			results := a.AnalyzeDomain(ctx, domain, nil)
			cancel()

			if _, hasError := results["error"]; !hasError {
				cache.Set(domain, results)
				warmed++
				slog.Info("Pre-cache: warmed", "domain", domain)
			} else {
				slog.Warn("Pre-cache: failed", "domain", domain)
			}

			time.Sleep(2 * time.Second)
		}
		slog.Info("Pre-cache: warm-up complete", "warmed", warmed, "total", len(topDomains))
	}()
}

func (a *Analyzer) ScheduleCacheRefresh(cache *AnalysisCache, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			slog.Info("Pre-cache: scheduled refresh starting")
			a.WarmCache(cache)
		}
	}()
}
