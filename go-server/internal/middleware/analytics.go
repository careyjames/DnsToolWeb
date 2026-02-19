// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AnalyticsCollector struct {
	pool *pgxpool.Pool

	mu              sync.Mutex
	dailySalt       string
	saltDate        string
	visitors        map[string]bool
	pageviews       int
	pageCounts      map[string]int
	refCounts       map[string]int
	analysisDomains map[string]bool
	analysesRun     int
}

func NewAnalyticsCollector(pool *pgxpool.Pool) *AnalyticsCollector {
	ac := &AnalyticsCollector{
		pool:            pool,
		visitors:        make(map[string]bool),
		pageCounts:      make(map[string]int),
		refCounts:       make(map[string]int),
		analysisDomains: make(map[string]bool),
	}
	ac.rotateSalt()
	go ac.flushLoop()
	return ac
}

func (ac *AnalyticsCollector) rotateSalt() {
	today := time.Now().UTC().Format("2006-01-02")
	if ac.saltDate == today {
		return
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	ac.dailySalt = hex.EncodeToString(b)
	ac.saltDate = today
	ac.visitors = make(map[string]bool)
	ac.pageCounts = make(map[string]int)
	ac.refCounts = make(map[string]int)
	ac.analysisDomains = make(map[string]bool)
	ac.analysesRun = 0
	ac.pageviews = 0
}

func (ac *AnalyticsCollector) pseudoID(ip string) string {
	h := sha256.Sum256([]byte(ac.dailySalt + "|" + ip))
	return hex.EncodeToString(h[:8])
}

func (ac *AnalyticsCollector) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		if strings.HasPrefix(path, "/static/") ||
			strings.HasPrefix(path, "/favicon") ||
			path == "/robots.txt" ||
			path == "/sitemap.xml" ||
			path == "/health" ||
			path == "/sw.js" ||
			path == "/manifest.json" ||
			strings.HasPrefix(path, "/.well-known/") ||
			path == "/llms.txt" ||
			path == "/llms-full.txt" {
			c.Next()
			return
		}

		c.Set("analytics_collector", ac)
		c.Next()

		if c.Writer.Status() >= 400 {
			return
		}

		ip := c.ClientIP()
		referer := extractRefOrigin(c.Request.Referer())
		pagePath := normalizePath(path)

		ac.mu.Lock()
		ac.rotateSalt()
		ac.pageviews++
		pid := ac.pseudoID(ip)
		ac.visitors[pid] = true
		ac.pageCounts[pagePath]++
		if referer != "" && referer != "direct" {
			ac.refCounts[referer]++
		}
		ac.mu.Unlock()
	}
}

func (ac *AnalyticsCollector) RecordAnalysis(domain string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.analysesRun++
	ac.analysisDomains[strings.ToLower(domain)] = true
}

func extractRefOrigin(ref string) string {
	if ref == "" {
		return "direct"
	}
	u, err := url.Parse(ref)
	if err != nil {
		return "direct"
	}
	host := u.Hostname()
	if host == "" {
		return "direct"
	}
	if strings.Contains(host, "dnstool") || strings.Contains(host, "it-help.tech") {
		return ""
	}
	return host
}

func normalizePath(p string) string {
	if p == "/" {
		return "/"
	}
	p = strings.TrimRight(p, "/")
	parts := strings.SplitN(p, "?", 2)
	return parts[0]
}

func (ac *AnalyticsCollector) flushLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		ac.Flush()
	}
}

func (ac *AnalyticsCollector) Flush() {
	ac.mu.Lock()
	if ac.pageviews == 0 {
		ac.mu.Unlock()
		return
	}

	today := time.Now().UTC().Format("2006-01-02")
	pv := ac.pageviews
	uv := len(ac.visitors)
	ar := ac.analysesRun
	ud := len(ac.analysisDomains)

	topPages := make(map[string]int)
	for k, v := range ac.pageCounts {
		topPages[k] = v
	}
	refs := make(map[string]int)
	for k, v := range ac.refCounts {
		refs[k] = v
	}

	ac.pageviews = 0
	ac.analysesRun = 0
	ac.mu.Unlock()

	pagesJSON, _ := json.Marshal(topPages)
	refsJSON, _ := json.Marshal(refs)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := ac.pool.Exec(ctx, `
		INSERT INTO site_analytics (date, pageviews, unique_visitors, analyses_run, unique_domains_analyzed, referrer_sources, top_pages)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (date) DO UPDATE SET
			pageviews = site_analytics.pageviews + EXCLUDED.pageviews,
			unique_visitors = GREATEST(site_analytics.unique_visitors, EXCLUDED.unique_visitors),
			analyses_run = site_analytics.analyses_run + EXCLUDED.analyses_run,
			unique_domains_analyzed = GREATEST(site_analytics.unique_domains_analyzed, EXCLUDED.unique_domains_analyzed),
			referrer_sources = site_analytics.referrer_sources || EXCLUDED.referrer_sources,
			top_pages = site_analytics.top_pages || EXCLUDED.top_pages,
			updated_at = NOW()
	`, today, pv, uv, ar, ud, refsJSON, pagesJSON)
	if err != nil {
		slog.Error("Analytics flush failed", "error", err)
	} else {
		slog.Debug("Analytics flushed", "date", today, "pageviews", pv, "unique_visitors", uv)
	}
}
