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

        results := h.Analyzer.InvestigateIP(c.Request.Context(), asciiDomain, ip)

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
        })
}
