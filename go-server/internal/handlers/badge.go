// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "encoding/json"
        "fmt"
        "net/http"
        "strings"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dnsclient"

        "github.com/gin-gonic/gin"
)

type BadgeHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewBadgeHandler(database *db.Database, cfg *config.Config) *BadgeHandler {
        return &BadgeHandler{DB: database, Config: cfg}
}

func (h *BadgeHandler) Badge(c *gin.Context) {
        domain := strings.TrimSpace(c.Query("domain"))
        if domain == "" {
                c.Data(http.StatusBadRequest, "image/svg+xml; charset=utf-8", badgeSVG("error", "missing domain", "#e05d44"))
                return
        }

        ascii, err := dnsclient.DomainToASCII(domain)
        if err != nil || !dnsclient.ValidateDomain(ascii) {
                c.Data(http.StatusBadRequest, "image/svg+xml; charset=utf-8", badgeSVG("error", "invalid domain", "#e05d44"))
                return
        }

        ctx := c.Request.Context()
        analysis, err := h.DB.Queries.GetRecentAnalysisByDomain(ctx, ascii)
        if err != nil {
                c.Data(http.StatusNotFound, "image/svg+xml; charset=utf-8", badgeSVG("DNS Tool", "not scanned", "#9f9f9f"))
                return
        }

        if analysis.Private {
                c.Data(http.StatusForbidden, "image/svg+xml; charset=utf-8", badgeSVG("DNS Tool", "private", "#9f9f9f"))
                return
        }

        var results map[string]any
        if len(analysis.FullResults) > 0 {
                _ = json.Unmarshal(analysis.FullResults, &results)
        }
        if results == nil {
                c.Data(http.StatusOK, "image/svg+xml; charset=utf-8", badgeSVG("DNS Tool", "no data", "#9f9f9f"))
                return
        }

        riskLabel := "Unknown"
        riskColor := "#9f9f9f"

        if postureRaw, ok := results["posture"]; ok {
                if posture, ok := postureRaw.(map[string]any); ok {
                        if rl, ok := posture["label"].(string); ok && rl != "" {
                                riskLabel = rl
                        } else if rl, ok := posture["grade"].(string); ok && rl != "" {
                                riskLabel = rl
                        }
                        if rc, ok := posture["color"].(string); ok {
                                riskColor = riskColorToHex(rc)
                        }
                }
        }

        style := c.DefaultQuery("style", "flat")

        c.Header("Cache-Control", "public, max-age=3600, s-maxage=3600")
        c.Header("Expires", time.Now().Add(1*time.Hour).UTC().Format(http.TimeFormat))

        if style == "covert" {
                c.Data(http.StatusOK, "image/svg+xml; charset=utf-8", badgeSVGCovert(ascii, riskLabel, riskColor))
        } else {
                c.Data(http.StatusOK, "image/svg+xml; charset=utf-8", badgeSVG("DNS Tool", riskLabel, riskColor))
        }
}

func (h *BadgeHandler) BadgeEmbed(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")
        c.HTML(http.StatusOK, "badge_embed.html", gin.H{
                "CspNonce":   nonce,
                "CsrfToken":  csrfToken,
                "AppVersion": h.Config.AppVersion,
                "BaseURL":    h.Config.BaseURL,
        })
}

func riskColorToHex(color string) string {
        switch color {
        case "success":
                return "#4c1"
        case "warning":
                return "#dfb317"
        case "danger":
                return "#e05d44"
        default:
                return "#9f9f9f"
        }
}

func badgeSVG(label, value, color string) []byte {
        labelWidth := len(label)*7 + 10
        valueWidth := len(value)*7 + 10
        totalWidth := labelWidth + valueWidth

        svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">
  <title>%s: %s</title>
  <linearGradient id="s" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="%d" height="20" fill="#555"/>
    <rect x="%d" width="%d" height="20" fill="%s"/>
    <rect width="%d" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text aria-hidden="true" x="%d" y="15" fill="#010101" fill-opacity=".3">%s</text>
    <text x="%d" y="14">%s</text>
    <text aria-hidden="true" x="%d" y="15" fill="#010101" fill-opacity=".3">%s</text>
    <text x="%d" y="14">%s</text>
  </g>
</svg>`,
                totalWidth, label, value, label, value,
                totalWidth,
                labelWidth,
                labelWidth, valueWidth, color,
                totalWidth,
                labelWidth/2+1, label,
                labelWidth/2+1, label,
                labelWidth+valueWidth/2-1, value,
                labelWidth+valueWidth/2-1, value,
        )
        return []byte(svg)
}

func badgeSVGCovert(domain, riskLabel, color string) []byte {
        label := "DNS Tool // " + domain
        labelWidth := len(label)*6 + 14
        valueWidth := len(riskLabel)*7 + 10
        totalWidth := labelWidth + valueWidth

        svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">
  <title>%s: %s</title>
  <clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="%d" height="20" fill="#1a0808"/>
    <rect x="%d" width="%d" height="20" fill="%s"/>
    <rect width="%d" height="20" fill="url(#s)"/>
  </g>
  <g fill="#c43c3c" text-anchor="middle" font-family="'Courier New',monospace" text-rendering="geometricPrecision" font-size="11">
    <text x="%d" y="14">%s</text>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text x="%d" y="14">%s</text>
  </g>
</svg>`,
                totalWidth, domain, riskLabel, domain, riskLabel,
                totalWidth,
                labelWidth,
                labelWidth, valueWidth, color,
                totalWidth,
                labelWidth/2+1, label,
                labelWidth+valueWidth/2-1, riskLabel,
        )
        return []byte(svg)
}
