// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

type ChangelogHandler struct {
        Config *config.Config
}

func NewChangelogHandler(cfg *config.Config) *ChangelogHandler {
        return &ChangelogHandler{Config: cfg}
}

func (h *ChangelogHandler) Changelog(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        c.HTML(http.StatusOK, "changelog.html", gin.H{
                "AppVersion":      h.Config.AppVersion,
                "MaintenanceNote": h.Config.MaintenanceNote,
                "CspNonce":       nonce,
                "ActivePage":     "changelog",
                "Changelog":      GetChangelog(),
                "LegacyChangelog": GetLegacyChangelog(),
        })
}
