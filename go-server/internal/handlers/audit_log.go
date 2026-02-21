// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"
	"dnstool/go-server/internal/dbq"

	"github.com/gin-gonic/gin"
)

const auditLogPageSize = 50

type AuditLogEntry struct {
	ID        int32
	Domain    string
	Hash      string
	Timestamp string
}

type AuditLogData struct {
	Entries    []AuditLogEntry
	Total      int64
	Page       int
	TotalPages int
	HasPrev    bool
	HasNext    bool
	PrevPage   int
	NextPage   int
}

func (h *ConfidenceHandler) AuditLog(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")

	page := 1
	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	data := gin.H{
		"AppVersion": h.Config.AppVersion,
		"CspNonce":   nonce,
		"CsrfToken":  csrfToken,
		"ActivePage": "confidence",
	}
	data["IsDev"] = h.Config.IsDevEnvironment
	mergeAuthData(c, h.Config, data)

	auditData := &AuditLogData{Page: page}

	if h.DB != nil {
		ctx := c.Request.Context()

		total, err := h.DB.Queries.CountHashedAnalyses(ctx)
		if err == nil {
			auditData.Total = total
			auditData.TotalPages = int(math.Ceil(float64(total) / float64(auditLogPageSize)))
			if auditData.TotalPages < 1 {
				auditData.TotalPages = 1
			}
			if page > auditData.TotalPages {
				page = auditData.TotalPages
				auditData.Page = page
			}
		}

		offset := int32((page - 1) * auditLogPageSize)
		rows, err := h.DB.Queries.ListHashedAnalyses(ctx, dbq.ListHashedAnalysesParams{
			Limit:  auditLogPageSize,
			Offset: offset,
		})
		if err == nil {
			for _, row := range rows {
				entry := AuditLogEntry{
					ID:     row.ID,
					Domain: row.Domain,
				}
				if row.PostureHash != nil {
					entry.Hash = *row.PostureHash
				}
				if row.CreatedAt.Valid {
					entry.Timestamp = row.CreatedAt.Time.Format(time.RFC3339)
				}
				auditData.Entries = append(auditData.Entries, entry)
			}
		}

		auditData.HasPrev = page > 1
		auditData.HasNext = page < auditData.TotalPages
		auditData.PrevPage = page - 1
		auditData.NextPage = page + 1
	}

	data["AuditLog"] = auditData
	c.HTML(http.StatusOK, "audit_log.html", data)
}

func NewAuditLogHandler(cfg *config.Config, database *db.Database) *ConfidenceHandler {
	return &ConfidenceHandler{Config: cfg, DB: database}
}
