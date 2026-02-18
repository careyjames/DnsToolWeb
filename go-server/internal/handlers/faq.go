// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

type FAQHandler struct {
        Config *config.Config
}

func NewFAQHandler(cfg *config.Config) *FAQHandler {
        return &FAQHandler{Config: cfg}
}

func (h *FAQHandler) SubdomainDiscovery(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        data := gin.H{
                "AppVersion":      h.Config.AppVersion,
                "MaintenanceNote": h.Config.MaintenanceNote,
                "CspNonce":        nonce,
                "ActivePage":      "faq",
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "faq_subdomains.html", data)
}
