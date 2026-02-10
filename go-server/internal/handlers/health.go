package handlers

import (
	"net/http"
	"runtime"
	"time"

	"dnstool/internal/analyzer"
	"dnstool/internal/db"
	"dnstool/internal/telemetry"

	"github.com/gin-gonic/gin"
)

type HealthHandler struct {
	DB        *db.Database
	StartTime time.Time
	Analyzer  *analyzer.Analyzer
}

func NewHealthHandler(database *db.Database, a *analyzer.Analyzer) *HealthHandler {
	return &HealthHandler{
		DB:        database,
		StartTime: time.Now(),
		Analyzer:  a,
	}
}

func (h *HealthHandler) HealthCheck(c *gin.Context) {
	dbStatus := "healthy"
	if err := h.DB.HealthCheck(c.Request.Context()); err != nil {
		dbStatus = "unhealthy: " + err.Error()
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	response := gin.H{
		"status":  "ok",
		"runtime": "go",
		"uptime":  time.Since(h.StartTime).String(),
		"database": gin.H{
			"status": dbStatus,
		},
		"memory": gin.H{
			"alloc_mb":       memStats.Alloc / 1024 / 1024,
			"sys_mb":         memStats.Sys / 1024 / 1024,
			"num_goroutines": runtime.NumGoroutine(),
		},
	}

	if h.Analyzer != nil {
		providerStats := h.Analyzer.Telemetry.AllStats()

		providers := make([]gin.H, 0, len(providerStats))
		for _, ps := range providerStats {
			p := gin.H{
				"name":                ps.Name,
				"state":               string(ps.State),
				"total_requests":      ps.TotalRequests,
				"success_count":       ps.SuccessCount,
				"failure_count":       ps.FailureCount,
				"consecutive_failures": ps.ConsecFailures,
				"avg_latency_ms":      ps.AvgLatencyMs,
				"p95_latency_ms":      ps.P95LatencyMs,
				"in_cooldown":         ps.InCooldown,
			}
			if ps.LastError != "" {
				p["last_error"] = ps.LastError
			}
			if ps.LastErrorTime != nil {
				p["last_error_time"] = ps.LastErrorTime.Format(time.RFC3339)
			}
			if ps.LastSuccessTime != nil {
				p["last_success_time"] = ps.LastSuccessTime.Format(time.RFC3339)
			}
			providers = append(providers, p)
		}

		caches := []gin.H{}
		if h.Analyzer.RDAPCache != nil {
			cs := h.Analyzer.RDAPCache.Stats()
			caches = append(caches, gin.H{
				"name":     cs.Name,
				"size":     cs.Size,
				"max_size": cs.MaxSize,
				"hits":     cs.Hits,
				"misses":   cs.Misses,
				"hit_rate": cs.HitRate,
			})
		}

		caches = append(caches, gin.H{
			"name": "dns_query",
			"note": "built into DNS client",
		})

		response["providers"] = providers
		response["caches"] = caches

		overallState := telemetry.Healthy
		for _, ps := range providerStats {
			if ps.State == telemetry.Unhealthy {
				overallState = telemetry.Unhealthy
				break
			}
			if ps.State == telemetry.Degraded {
				overallState = telemetry.Degraded
			}
		}
		response["overall_provider_health"] = string(overallState)
	}

	c.JSON(http.StatusOK, response)
}
