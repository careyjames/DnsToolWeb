package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"dnstool/internal/config"
	"dnstool/internal/db"

	"github.com/gin-gonic/gin"
)

type AnalysisHandler struct {
	DB     *db.Database
	Config *config.Config
}

func NewAnalysisHandler(database *db.Database, cfg *config.Config) *AnalysisHandler {
	return &AnalysisHandler{DB: database, Config: cfg}
}

func (h *AnalysisHandler) ViewAnalysisStatic(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	idStr := c.Param("id")
	analysisID, err := strconv.ParseInt(idStr, 10, 32)
	if err != nil {
		c.HTML(http.StatusBadRequest, "index.html", gin.H{
			"AppVersion":     h.Config.AppVersion,
			"CspNonce":       nonce,
			"ActivePage":     "home",
			"FlashMessages":  []FlashMessage{{Category: "danger", Message: "Invalid analysis ID"}},
		})
		return
	}

	ctx := c.Request.Context()
	analysis, err := h.DB.Queries.GetAnalysisByID(ctx, int32(analysisID))
	if err != nil {
		c.HTML(http.StatusNotFound, "index.html", gin.H{
			"AppVersion":     h.Config.AppVersion,
			"CspNonce":       nonce,
			"ActivePage":     "home",
			"FlashMessages":  []FlashMessage{{Category: "danger", Message: "Analysis not found"}},
		})
		return
	}

	if len(analysis.FullResults) == 0 || string(analysis.FullResults) == "null" {
		c.HTML(http.StatusGone, "index.html", gin.H{
			"AppVersion":     h.Config.AppVersion,
			"CspNonce":       nonce,
			"ActivePage":     "home",
			"FlashMessages":  []FlashMessage{{Category: "warning", Message: "This report is no longer available. Please re-analyze the domain."}},
		})
		return
	}

	results := NormalizeResults(analysis.FullResults)
	if results == nil {
		c.HTML(http.StatusInternalServerError, "index.html", gin.H{
			"AppVersion":     h.Config.AppVersion,
			"CspNonce":       nonce,
			"ActivePage":     "home",
			"FlashMessages":  []FlashMessage{{Category: "danger", Message: "Failed to parse results"}},
		})
		return
	}

	waitSeconds, _ := strconv.Atoi(c.Query("wait_seconds"))
	waitReason := c.Query("wait_reason")

	timestamp := formatTimestamp(analysis.CreatedAt)
	if analysis.UpdatedAt.Valid {
		timestamp = formatTimestamp(analysis.UpdatedAt)
	}

	dur := 0.0
	if analysis.AnalysisDuration != nil {
		dur = *analysis.AnalysisDuration
	}

	domainExists := true
	if v, ok := results["domain_exists"]; ok {
		if b, ok := v.(bool); ok {
			domainExists = b
		}
	}

	toolVersion := ""
	if tv, ok := results["_tool_version"].(string); ok {
		toolVersion = tv
	}

	c.HTML(http.StatusOK, "results.html", gin.H{
		"AppVersion":        h.Config.AppVersion,
		"CspNonce":          nonce,
		"ActivePage":        "",
		"Domain":            analysis.Domain,
		"AsciiDomain":       analysis.AsciiDomain,
		"Results":           results,
		"AnalysisID":        analysis.ID,
		"AnalysisDuration":  dur,
		"AnalysisTimestamp": timestamp,
		"FromHistory":       true,
		"WaitSeconds":       waitSeconds,
		"WaitReason":        waitReason,
		"DomainExists":      domainExists,
		"ToolVersion":       toolVersion,
	})
}

func (h *AnalysisHandler) proxyToPython(c *gin.Context) {
	backendURL, err := url.Parse(h.Config.PythonBackendURL)
	if err != nil {
		slog.Error("Invalid Python backend URL", "url", h.Config.PythonBackendURL, "error", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "Backend unavailable"})
		return
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = backendURL.Scheme
			req.URL.Host = backendURL.Host
			req.Host = backendURL.Host
			if _, ok := req.Header["User-Agent"]; !ok {
				req.Header.Set("User-Agent", "")
			}
		},
		Transport: &http.Transport{
			ResponseHeaderTimeout: 120 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("Proxy error", "path", r.URL.Path, "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			io.WriteString(w, `{"error":"DNS analysis backend is temporarily unavailable"}`)
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Server")
			return nil
		},
	}

	slog.Info("Proxying request to Python backend", "method", c.Request.Method, "path", c.Request.URL.Path)
	proxy.ServeHTTP(c.Writer, c.Request)
}

func (h *AnalysisHandler) ViewAnalysis(c *gin.Context) {
	h.proxyToPython(c)
}

func (h *AnalysisHandler) Analyze(c *gin.Context) {
	h.proxyToPython(c)
}

func (h *AnalysisHandler) APISubdomains(c *gin.Context) {
	domain := strings.TrimPrefix(c.Param("domain"), "/")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain is required"})
		return
	}
	h.proxyToPython(c)
}

func (h *AnalysisHandler) APIAnalysis(c *gin.Context) {
	idStr := c.Param("id")
	analysisID, err := strconv.ParseInt(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid analysis ID"})
		return
	}

	ctx := c.Request.Context()
	analysis, err := h.DB.Queries.GetAnalysisByID(ctx, int32(analysisID))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Analysis not found"})
		return
	}

	var fullResults interface{}
	if len(analysis.FullResults) > 0 {
		json.Unmarshal(analysis.FullResults, &fullResults)
	}
	var ctSubdomains interface{}
	if len(analysis.CtSubdomains) > 0 {
		json.Unmarshal(analysis.CtSubdomains, &ctSubdomains)
	}

	c.JSON(http.StatusOK, gin.H{
		"id":                    analysis.ID,
		"domain":               analysis.Domain,
		"ascii_domain":         analysis.AsciiDomain,
		"spf_status":           analysis.SpfStatus,
		"dmarc_status":         analysis.DmarcStatus,
		"dmarc_policy":         analysis.DmarcPolicy,
		"dkim_status":          analysis.DkimStatus,
		"registrar_name":       analysis.RegistrarName,
		"registrar_source":     analysis.RegistrarSource,
		"analysis_success":     analysis.AnalysisSuccess,
		"error_message":        analysis.ErrorMessage,
		"analysis_duration":    analysis.AnalysisDuration,
		"created_at":           formatTimestamp(analysis.CreatedAt),
		"updated_at":           formatTimestamp(analysis.UpdatedAt),
		"country_code":         analysis.CountryCode,
		"country_name":         analysis.CountryName,
		"full_results":         fullResults,
		"ct_subdomains":        ctSubdomains,
	})
}
