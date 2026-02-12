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
        c.HTML(http.StatusOK, "index.html", gin.H{
                "AppVersion":  h.Config.AppVersion,
                "CspNonce":    nonce,
                "ActivePage":  "home",
                "CsrfToken":   csrfToken,
                "WaitDomain":  c.Query("wait_domain"),
                "WaitSeconds": c.Query("wait_seconds"),
                "WaitReason":  c.DefaultQuery("wait_reason", "anti_repeat"),
                "Changelog":   GetChangelog(),
                "DKIMExpand":  c.Query("dkim") != "",
        })
}
