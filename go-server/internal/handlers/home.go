// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

type HomeHandler struct {
        Config *config.Config
}

func NewHomeHandler(cfg *config.Config) *HomeHandler {
        return &HomeHandler{Config: cfg}
}

func (h *HomeHandler) Index(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")
        data := gin.H{
                "AppVersion":      h.Config.AppVersion,
                "MaintenanceNote": h.Config.MaintenanceNote,
                "CspNonce":    nonce,
                "ActivePage":  "home",
                "CsrfToken":   csrfToken,
                "WaitDomain":  c.Query("wait_domain"),
                "WaitSeconds": c.Query("wait_seconds"),
                "WaitReason":  c.DefaultQuery("wait_reason", "anti_repeat"),
                "Changelog":   GetRecentChangelog(6),
                "DKIMExpand":  c.Query("dkim") != "",
        }

        if flash := c.Query("flash"); flash != "" {
                data["FlashMessages"] = []FlashMessage{{Category: "warning", Message: flash}}
                if domain := c.Query("domain"); domain != "" {
                        data["PrefillDomain"] = domain
                }
        }

        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "index.html", data)
}
