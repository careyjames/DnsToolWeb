// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
package handlers

import (
	"net/http"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

type SecurityPolicyHandler struct {
	Config *config.Config
}

func NewSecurityPolicyHandler(cfg *config.Config) *SecurityPolicyHandler {
	return &SecurityPolicyHandler{Config: cfg}
}

func (h *SecurityPolicyHandler) SecurityPolicy(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	c.HTML(http.StatusOK, "security_policy.html", gin.H{
		"AppVersion": h.Config.AppVersion,
		"CspNonce":   nonce,
		"ActivePage": "security-policy",
	})
}
