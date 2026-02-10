package handlers

import (
	"net/http"
	"runtime"
	"time"

	"dnstool/internal/db"

	"github.com/gin-gonic/gin"
)

type HealthHandler struct {
	DB        *db.Database
	StartTime time.Time
}

func NewHealthHandler(database *db.Database) *HealthHandler {
	return &HealthHandler{
		DB:        database,
		StartTime: time.Now(),
	}
}

func (h *HealthHandler) HealthCheck(c *gin.Context) {
	dbStatus := "healthy"
	if err := h.DB.HealthCheck(c.Request.Context()); err != nil {
		dbStatus = "unhealthy: " + err.Error()
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	c.JSON(http.StatusOK, gin.H{
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
	})
}
