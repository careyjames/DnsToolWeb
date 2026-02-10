package handlers

import (
        "encoding/json"
        "fmt"
        "net/http"
        "strconv"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
)

const (
        templateCompare       = "compare.html"
        templateCompareSelect = "compare_select.html"
)

type CompareHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewCompareHandler(database *db.Database, cfg *config.Config) *CompareHandler {
        return &CompareHandler{DB: database, Config: cfg}
}

func formatDiffValue(v interface{}) string {
        if v == nil {
                return ""
        }
        if s, ok := v.(string); ok {
                return s
        }
        b, _ := json.Marshal(v)
        return string(b)
}

func buildCompareAnalysis(a dbq.DomainAnalysis) CompareAnalysis {
        ca := CompareAnalysis{}
        if a.CreatedAt.Valid {
                ca.CreatedAt = a.CreatedAt.Time.Format("2006-01-02 15:04:05")
        }
        if len(a.FullResults) > 0 {
                var fr map[string]interface{}
                if json.Unmarshal(a.FullResults, &fr) == nil {
                        if tv, ok := fr["_tool_version"].(string); ok {
                                ca.ToolVersion = tv
                                ca.HasToolVersion = true
                        }
                }
        }
        if a.AnalysisDuration != nil {
                ca.AnalysisDuration = fmt.Sprintf("%.1fs", *a.AnalysisDuration)
                ca.HasDuration = true
        }
        return ca
}

func (h *CompareHandler) Compare(c *gin.Context) {
        domain := c.Query("domain")
        idAStr := c.Query("a")
        idBStr := c.Query("b")

        idA, errA := strconv.ParseInt(idAStr, 10, 32)
        idB, errB := strconv.ParseInt(idBStr, 10, 32)

        if errA != nil || errB != nil {
                h.selectDomain(c, domain)
                return
        }

        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")
        ctx := c.Request.Context()

        analysisA, err := h.DB.Queries.GetAnalysisByID(ctx, int32(idA))
        if err != nil {
                c.HTML(http.StatusNotFound, templateCompare, gin.H{
                        "AppVersion":     h.Config.AppVersion,
                        "CspNonce":       nonce,
                        "CsrfToken":     csrfToken,
                        "ActivePage":     "compare",
                        "FlashMessages":  []FlashMessage{{Category: "danger", Message: "Analysis A not found"}},
                })
                return
        }

        analysisB, err := h.DB.Queries.GetAnalysisByID(ctx, int32(idB))
        if err != nil {
                c.HTML(http.StatusNotFound, templateCompare, gin.H{
                        "AppVersion":     h.Config.AppVersion,
                        "CspNonce":       nonce,
                        "CsrfToken":     csrfToken,
                        "ActivePage":     "compare",
                        "FlashMessages":  []FlashMessage{{Category: "danger", Message: "Analysis B not found"}},
                })
                return
        }

        if analysisA.Domain != analysisB.Domain {
                c.HTML(http.StatusBadRequest, templateCompareSelect, gin.H{
                        "AppVersion":     h.Config.AppVersion,
                        "CspNonce":       nonce,
                        "CsrfToken":     csrfToken,
                        "ActivePage":     "compare",
                        "Domain":         analysisA.Domain,
                        "FlashMessages":  []FlashMessage{{Category: "danger", Message: "Cannot compare analyses of different domains"}},
                })
                return
        }

        if analysisA.CreatedAt.Valid && analysisB.CreatedAt.Valid {
                if analysisA.CreatedAt.Time.After(analysisB.CreatedAt.Time) {
                        analysisA, analysisB = analysisB, analysisA
                }
        }

        resultsA := NormalizeResults(analysisA.FullResults)
        resultsB := NormalizeResults(analysisB.FullResults)

        if resultsA == nil || resultsB == nil {
                c.HTML(http.StatusBadRequest, templateCompareSelect, gin.H{
                        "AppVersion":     h.Config.AppVersion,
                        "CspNonce":       nonce,
                        "CsrfToken":     csrfToken,
                        "ActivePage":     "compare",
                        "Domain":         analysisA.Domain,
                        "FlashMessages":  []FlashMessage{{Category: "danger", Message: "One or both analyses have no stored data"}},
                })
                return
        }

        diffs := ComputeAllDiffs(resultsA, resultsB)

        diffItems := make([]DiffItem, 0, len(diffs))
        changesFound := 0
        for _, d := range diffs {
                item := DiffItem{
                        Label:   d.Label,
                        Icon:    d.Icon,
                        Changed: d.Changed,
                        StatusA: d.StatusA,
                        StatusB: d.StatusB,
                }
                if d.Changed {
                        changesFound++
                }
                for _, dc := range d.DetailChanges {
                        oldStr := formatDiffValue(dc.Old)
                        newStr := formatDiffValue(dc.New)
                        _, isMapOld := dc.Old.(map[string]interface{})
                        item.DetailChanges = append(item.DetailChanges, DiffChange{
                                Field:  dc.Field,
                                Old:    dc.Old,
                                New:    dc.New,
                                OldStr: oldStr,
                                NewStr: newStr,
                                IsMap:  isMapOld,
                        })
                }
                diffItems = append(diffItems, item)
        }

        c.HTML(http.StatusOK, templateCompare, gin.H{
                "AppVersion":   h.Config.AppVersion,
                "CspNonce":     nonce,
                "CsrfToken":   csrfToken,
                "ActivePage":   "compare",
                "Domain":       analysisA.Domain,
                "AnalysisA":    buildCompareAnalysis(analysisA),
                "AnalysisB":    buildCompareAnalysis(analysisB),
                "Diffs":        diffItems,
                "ChangesFound": changesFound,
        })
}

func (h *CompareHandler) selectDomain(c *gin.Context, domain string) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")

        if domain == "" {
                c.HTML(http.StatusOK, templateCompareSelect, gin.H{
                        "AppVersion":     h.Config.AppVersion,
                        "CspNonce":       nonce,
                        "CsrfToken":     csrfToken,
                        "ActivePage":     "compare",
                        "Domain":         "",
                        "FlashMessages":  []FlashMessage{{Category: "warning", Message: "Please provide a domain to compare analyses."}},
                })
                return
        }

        ctx := c.Request.Context()
        analyses, err := h.DB.Queries.ListAnalysesByDomain(ctx, dbq.ListAnalysesByDomainParams{
                Domain: domain,
                Limit:  20,
        })
        if err != nil {
                c.HTML(http.StatusInternalServerError, templateCompareSelect, gin.H{
                        "AppVersion":     h.Config.AppVersion,
                        "CspNonce":       nonce,
                        "CsrfToken":     csrfToken,
                        "ActivePage":     "compare",
                        "Domain":         domain,
                        "FlashMessages":  []FlashMessage{{Category: "danger", Message: "Failed to fetch analyses"}},
                })
                return
        }

        if len(analyses) < 2 {
                c.HTML(http.StatusOK, templateCompareSelect, gin.H{
                        "AppVersion":     h.Config.AppVersion,
                        "CspNonce":       nonce,
                        "CsrfToken":     csrfToken,
                        "ActivePage":     "compare",
                        "Domain":         domain,
                        "FlashMessages":  []FlashMessage{{Category: "warning", Message: "Need at least 2 analyses to compare"}},
                })
                return
        }

        items := make([]AnalysisItem, 0, len(analyses))
        for _, a := range analyses {
                items = append(items, buildSelectAnalysisItem(a))
        }

        c.HTML(http.StatusOK, templateCompareSelect, gin.H{
                "AppVersion": h.Config.AppVersion,
                "CspNonce":   nonce,
                "CsrfToken":  csrfToken,
                "ActivePage": "",
                "Domain":     domain,
                "Analyses":   items,
        })
}

func buildSelectAnalysisItem(a dbq.DomainAnalysis) AnalysisItem {
        spfStatus := ""
        if a.SpfStatus != nil {
                spfStatus = *a.SpfStatus
        }
        dmarcStatus := ""
        if a.DmarcStatus != nil {
                dmarcStatus = *a.DmarcStatus
        }
        dkimStatus := ""
        if a.DkimStatus != nil {
                dkimStatus = *a.DkimStatus
        }
        dur := 0.0
        if a.AnalysisDuration != nil {
                dur = *a.AnalysisDuration
        }
        createdAt := ""
        if a.CreatedAt.Valid {
                createdAt = a.CreatedAt.Time.Format("2006-01-02 15:04:05")
        }
        toolVersion := ""
        if len(a.FullResults) > 0 {
                var fr map[string]interface{}
                if json.Unmarshal(a.FullResults, &fr) == nil {
                        if tv, ok := fr["_tool_version"].(string); ok {
                                toolVersion = tv
                        }
                }
        }
        return AnalysisItem{
                ID:               a.ID,
                Domain:           a.Domain,
                AsciiDomain:      a.AsciiDomain,
                SpfStatus:        spfStatus,
                DmarcStatus:      dmarcStatus,
                DkimStatus:       dkimStatus,
                AnalysisDuration: dur,
                CreatedAt:        createdAt,
                ToolVersion:      toolVersion,
        }
}
