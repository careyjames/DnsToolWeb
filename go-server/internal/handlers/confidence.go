// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/icae"

        "github.com/gin-gonic/gin"
)

type ConfidenceHandler struct {
        Config *config.Config
        DB     *db.Database
}

func NewConfidenceHandler(cfg *config.Config, database *db.Database) *ConfidenceHandler {
        return &ConfidenceHandler{Config: cfg, DB: database}
}

func (h *ConfidenceHandler) Confidence(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")
        data := gin.H{
                "AppVersion": h.Config.AppVersion,
                "CspNonce":   nonce,
                "CsrfToken":  csrfToken,
                "ActivePage": "confidence",
        }

        isDev := h.Config.IsDevEnvironment
        data["IsDev"] = isDev

        if h.DB != nil {
                if metrics := icae.LoadReportMetrics(c.Request.Context(), h.DB.Queries); metrics != nil {
                        metrics.HashAudit = icae.AuditHashIntegrity(c.Request.Context(), h.DB.Queries, 50)
                        data["ICAEMetrics"] = metrics
                }
        }

        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "confidence.html", data)
}
