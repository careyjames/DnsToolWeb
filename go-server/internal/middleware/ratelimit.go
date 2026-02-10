package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	RateLimitWindow      = 60
	RateLimitMaxRequests = 8
	AntiRepeatWindow     = 15
)

type RateLimitResult struct {
	Allowed     bool
	Reason      string
	WaitSeconds int
}

type RateLimiter interface {
	CheckAndRecord(ip, domain string) RateLimitResult
}

type requestEntry struct {
	timestamp float64
	domain    string
}

type InMemoryRateLimiter struct {
	mu       sync.Mutex
	requests map[string][]requestEntry
}

func NewInMemoryRateLimiter() *InMemoryRateLimiter {
	limiter := &InMemoryRateLimiter{
		requests: make(map[string][]requestEntry),
	}

	go limiter.cleanupLoop()

	return limiter
}

func (l *InMemoryRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		now := float64(time.Now().Unix())
		for ip, entries := range l.requests {
			l.requests[ip] = pruneOld(entries, now)
			if len(l.requests[ip]) == 0 {
				delete(l.requests, ip)
			}
		}
		l.mu.Unlock()
	}
}

func pruneOld(entries []requestEntry, now float64) []requestEntry {
	cutoff := now - RateLimitWindow
	result := entries[:0]
	for _, e := range entries {
		if e.timestamp >= cutoff {
			result = append(result, e)
		}
	}
	return result
}

func (l *InMemoryRateLimiter) CheckAndRecord(ip, domain string) RateLimitResult {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := float64(time.Now().Unix())
	domain = strings.ToLower(domain)

	l.requests[ip] = pruneOld(l.requests[ip], now)
	entries := l.requests[ip]

	if len(entries) >= RateLimitMaxRequests {
		oldest := entries[0].timestamp
		waitSeconds := int(oldest+RateLimitWindow-now) + 1
		if waitSeconds < 1 {
			waitSeconds = 1
		}
		return RateLimitResult{
			Allowed:     false,
			Reason:      "rate_limit",
			WaitSeconds: waitSeconds,
		}
	}

	antiRepeatCutoff := now - AntiRepeatWindow
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].timestamp < antiRepeatCutoff {
			break
		}
		if entries[i].domain == domain {
			waitSeconds := int(entries[i].timestamp+AntiRepeatWindow-now) + 1
			if waitSeconds < 1 {
				waitSeconds = 1
			}
			return RateLimitResult{
				Allowed:     false,
				Reason:      "anti_repeat",
				WaitSeconds: waitSeconds,
			}
		}
	}

	l.requests[ip] = append(entries, requestEntry{
		timestamp: now,
		domain:    domain,
	})

	return RateLimitResult{
		Allowed: true,
		Reason:  "ok",
	}
}

func AnalyzeRateLimit(limiter RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != "POST" {
			c.Next()
			return
		}

		domain := strings.TrimSpace(c.PostForm("domain"))
		if domain == "" {
			c.Next()
			return
		}

		clientIP := c.ClientIP()
		result := limiter.CheckAndRecord(clientIP, domain)

		if !result.Allowed {
			traceID, _ := c.Get("trace_id")
			slog.Info("Rate limit triggered",
				"trace_id", traceID,
				"ip", clientIP,
				"domain", domain,
				"reason", result.Reason,
				"wait_seconds", result.WaitSeconds,
			)

			var msg string
			switch result.Reason {
			case "rate_limit":
				msg = fmt.Sprintf("Rate limit reached. Please wait %d seconds before trying again.", result.WaitSeconds)
			case "anti_repeat":
				msg = fmt.Sprintf("This domain was recently analyzed. Please wait %d seconds before re-analyzing.", result.WaitSeconds)
			}

			if c.GetHeader("Accept") == "application/json" {
				c.JSON(http.StatusTooManyRequests, gin.H{
					"error":        msg,
					"reason":       result.Reason,
					"wait_seconds": result.WaitSeconds,
				})
			} else {
				c.SetCookie("flash_message", msg, 10, "/", "", false, false)
				c.SetCookie("flash_category", "warning", 10, "/", "", false, false)
				c.Redirect(http.StatusSeeOther, "/")
			}
			c.Abort()
			return
		}

		c.Next()
	}
}
