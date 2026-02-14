// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
package handlers

import (
        "net/http"
        "strings"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dnsclient"

        "github.com/gin-gonic/gin"
)

const investigateTemplate = "investigate.html"

type InvestigateHandler struct {
        Config   *config.Config
        Analyzer *analyzer.Analyzer
}

func NewInvestigateHandler(cfg *config.Config, a *analyzer.Analyzer) *InvestigateHandler {
        return &InvestigateHandler{Config: cfg, Analyzer: a}
}

func (h *InvestigateHandler) InvestigatePage(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")

        c.HTML(http.StatusOK, investigateTemplate, gin.H{
                "AppVersion": h.Config.AppVersion,
                "CspNonce":   nonce,
                "CsrfToken":  csrfToken,
                "ActivePage": "investigate",
                "ShowForm":   true,
        })
}

func (h *InvestigateHandler) Investigate(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")

        domain := strings.TrimSpace(c.PostForm("domain"))
        ip := strings.TrimSpace(c.PostForm("ip_address"))

        if domain == "" || ip == "" {
                c.HTML(http.StatusOK, investigateTemplate, gin.H{
                        "AppVersion":    h.Config.AppVersion,
                        "CspNonce":      nonce,
                        "CsrfToken":     csrfToken,
                        "ActivePage":    "investigate",
                        "ShowForm":      true,
                        "FlashMessages": []FlashMessage{{Category: "danger", Message: "Please enter both a domain name and an IP address."}},
                        "FormDomain":    domain,
                        "FormIP":        ip,
                })
                return
        }

        if !dnsclient.ValidateDomain(domain) {
                c.HTML(http.StatusOK, investigateTemplate, gin.H{
                        "AppVersion":    h.Config.AppVersion,
                        "CspNonce":      nonce,
                        "CsrfToken":     csrfToken,
                        "ActivePage":    "investigate",
                        "ShowForm":      true,
                        "FlashMessages": []FlashMessage{{Category: "danger", Message: "Invalid domain name. Enter a domain like example.com."}},
                        "FormDomain":    domain,
                        "FormIP":        ip,
                })
                return
        }

        if !analyzer.ValidateIPAddress(ip) {
                c.HTML(http.StatusOK, investigateTemplate, gin.H{
                        "AppVersion":    h.Config.AppVersion,
                        "CspNonce":      nonce,
                        "CsrfToken":     csrfToken,
                        "ActivePage":    "investigate",
                        "ShowForm":      true,
                        "FlashMessages": []FlashMessage{{Category: "danger", Message: "Invalid IP address. Enter a valid IPv4 or IPv6 address."}},
                        "FormDomain":    domain,
                        "FormIP":        ip,
                })
                return
        }

        if analyzer.IsPrivateIP(ip) {
                c.HTML(http.StatusOK, investigateTemplate, gin.H{
                        "AppVersion":    h.Config.AppVersion,
                        "CspNonce":      nonce,
                        "CsrfToken":     csrfToken,
                        "ActivePage":    "investigate",
                        "ShowForm":      true,
                        "FlashMessages": []FlashMessage{{Category: "warning", Message: "Private, loopback, and link-local IP addresses cannot be investigated. Enter a public IP address."}},
                        "FormDomain":    domain,
                        "FormIP":        ip,
                })
                return
        }

        asciiDomain, err := dnsclient.DomainToASCII(domain)
        if err != nil {
                asciiDomain = domain
        }

        securityTrailsKey := strings.TrimSpace(c.PostForm("securitytrails_key"))
        ipInfoToken := strings.TrimSpace(c.PostForm("ipinfo_token"))

        results := h.Analyzer.InvestigateIP(c.Request.Context(), asciiDomain, ip)

        if securityTrailsKey != "" {
                stDomains, stErr := analyzer.FetchDomainsByIPWithKey(c.Request.Context(), ip, securityTrailsKey)
                if stErr == nil && len(stDomains) > 0 {
                        neighborhood := make([]map[string]any, 0, len(stDomains))
                        for _, d := range stDomains {
                                if !strings.EqualFold(d, domain) && !strings.EqualFold(d, asciiDomain) {
                                        neighborhood = append(neighborhood, map[string]any{
                                                "domain": d,
                                                "source": "securitytrails",
                                        })
                                }
                        }
                        cap := 10
                        if len(neighborhood) > cap {
                                neighborhood = neighborhood[:cap]
                        }
                        results["neighborhood"] = neighborhood
                        results["neighborhood_total"] = len(stDomains)
                        results["neighborhood_source"] = "SecurityTrails"
                        results["st_enabled"] = true
                }
        }

        var ipInfoData map[string]any
        if ipInfoToken != "" {
                ipInfo, ipInfoErr := analyzer.FetchIPInfo(c.Request.Context(), ip, ipInfoToken)
                if ipInfoErr == nil && ipInfo != nil {
                        ipInfoData = map[string]any{
                                "ip":       ipInfo.IP,
                                "hostname": ipInfo.Hostname,
                                "city":     ipInfo.City,
                                "region":   ipInfo.Region,
                                "country":  ipInfo.Country,
                                "loc":      ipInfo.Loc,
                                "org":      ipInfo.Org,
                                "postal":   ipInfo.Postal,
                                "timezone": ipInfo.Timezone,
                                "anycast":  ipInfo.Anycast,
                                "bogon":    ipInfo.Bogon,
                        }
                }
        }

        c.HTML(http.StatusOK, investigateTemplate, gin.H{
                "AppVersion":  h.Config.AppVersion,
                "CspNonce":    nonce,
                "CsrfToken":   csrfToken,
                "ActivePage":  "investigate",
                "ShowForm":    false,
                "ShowResults": true,
                "Domain":      domain,
                "AsciiDomain": asciiDomain,
                "IPAddress":   ip,
                "Results":     results,
                "IPInfo":      ipInfoData,
        })
}
