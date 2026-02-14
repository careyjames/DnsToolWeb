// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
package handlers

import (
	"io"
	"net/http"
	"strings"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

const emailHeaderTemplate = "email_header.html"
const maxHeaderSize = 256 * 1024

type EmailHeaderHandler struct {
	Config *config.Config
}

func NewEmailHeaderHandler(cfg *config.Config) *EmailHeaderHandler {
	return &EmailHeaderHandler{Config: cfg}
}

func (h *EmailHeaderHandler) EmailHeaderPage(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")

	c.HTML(http.StatusOK, emailHeaderTemplate, gin.H{
		"AppVersion": h.Config.AppVersion,
		"CspNonce":   nonce,
		"CsrfToken":  csrfToken,
		"ActivePage": "email-header",
		"ShowForm":   true,
	})
}

func (h *EmailHeaderHandler) AnalyzeEmailHeader(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")

	var rawHeader string

	file, fileHeader, err := c.Request.FormFile("header_file")
	if err == nil && fileHeader != nil && fileHeader.Size > 0 {
		defer file.Close()
		if fileHeader.Size > maxHeaderSize {
			c.HTML(http.StatusOK, emailHeaderTemplate, gin.H{
				"AppVersion":    h.Config.AppVersion,
				"CspNonce":      nonce,
				"CsrfToken":     csrfToken,
				"ActivePage":    "email-header",
				"ShowForm":      true,
				"FlashMessages": []FlashMessage{{Category: "danger", Message: "File too large. Maximum size is 256 KB."}},
			})
			return
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxHeaderSize))
		if readErr != nil {
			c.HTML(http.StatusOK, emailHeaderTemplate, gin.H{
				"AppVersion":    h.Config.AppVersion,
				"CspNonce":      nonce,
				"CsrfToken":     csrfToken,
				"ActivePage":    "email-header",
				"ShowForm":      true,
				"FlashMessages": []FlashMessage{{Category: "danger", Message: "Could not read the uploaded file."}},
			})
			return
		}
		rawHeader = string(data)
	}

	if rawHeader == "" {
		rawHeader = strings.TrimSpace(c.PostForm("raw_header"))
	}

	if rawHeader == "" {
		c.HTML(http.StatusOK, emailHeaderTemplate, gin.H{
			"AppVersion":    h.Config.AppVersion,
			"CspNonce":      nonce,
			"CsrfToken":     csrfToken,
			"ActivePage":    "email-header",
			"ShowForm":      true,
			"FlashMessages": []FlashMessage{{Category: "danger", Message: "Please paste an email header or upload a header file."}},
		})
		return
	}

	if len(rawHeader) > maxHeaderSize {
		rawHeader = rawHeader[:maxHeaderSize]
	}

	analysis := analyzer.AnalyzeEmailHeaders(rawHeader)

	c.HTML(http.StatusOK, emailHeaderTemplate, gin.H{
		"AppVersion": h.Config.AppVersion,
		"CspNonce":   nonce,
		"CsrfToken":  csrfToken,
		"ActivePage": "email-header",
		"ShowForm":   false,
		"ShowResults": true,
		"Analysis":   analysis,
	})
}
