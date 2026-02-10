package handlers

import (
        "encoding/json"
        "net/http"
        "strconv"

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

        if len(analysis.FullResults) == 0 || string(analysis.FullResults) == "null" {
                c.JSON(http.StatusGone, gin.H{
                        "error": "This report is no longer available. Please re-analyze the domain.",
                })
                return
        }

        results := NormalizeResults(analysis.FullResults)
        if results == nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse results"})
                return
        }

        waitSeconds, _ := strconv.Atoi(c.Query("wait_seconds"))
        waitReason := c.Query("wait_reason")

        timestamp := formatTimestamp(analysis.CreatedAt)
        if analysis.UpdatedAt.Valid {
                timestamp = formatTimestamp(analysis.UpdatedAt)
        }

        c.JSON(http.StatusOK, gin.H{
                "domain":            analysis.Domain,
                "ascii_domain":      analysis.AsciiDomain,
                "results":           results,
                "analysis_id":       analysis.ID,
                "analysis_duration": analysis.AnalysisDuration,
                "analysis_timestamp": timestamp,
                "from_history":      true,
                "wait_seconds":      waitSeconds,
                "wait_reason":       waitReason,
        })
}

func (h *AnalysisHandler) ViewAnalysis(c *gin.Context) {
        c.JSON(http.StatusNotImplemented, gin.H{
                "error":   "Live DNS analysis is not yet available in the Go server",
                "message": "This feature requires the DNS engine (Phase 5). Use the Python server for live analysis.",
        })
}

func (h *AnalysisHandler) Analyze(c *gin.Context) {
        c.JSON(http.StatusNotImplemented, gin.H{
                "error":   "DNS analysis is not yet available in the Go server",
                "message": "This feature requires the DNS engine (Phase 5). Use the Python server for live analysis.",
        })
}

func (h *AnalysisHandler) APISubdomains(c *gin.Context) {
        c.JSON(http.StatusNotImplemented, gin.H{
                "error":   "Subdomain discovery is not yet available in the Go server",
                "message": "This feature requires the DNS engine (Phase 5). Use the Python server for subdomain discovery.",
        })
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
