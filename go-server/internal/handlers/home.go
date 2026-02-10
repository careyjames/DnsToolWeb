package handlers

import (
	"net/http"

	"dnstool/internal/config"

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
	c.HTML(http.StatusOK, "index.html", gin.H{
		"app_version": h.Config.AppVersion,
		"csp_nonce":   nonce,
	})
}
