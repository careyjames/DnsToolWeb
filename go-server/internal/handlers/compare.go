package handlers

import (
        "net/http"
        "strconv"

        "dnstool/internal/config"
        "dnstool/internal/db"
        "dnstool/internal/dbq"

        "github.com/gin-gonic/gin"
)

type CompareHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewCompareHandler(database *db.Database, cfg *config.Config) *CompareHandler {
        return &CompareHandler{DB: database, Config: cfg}
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

        ctx := c.Request.Context()

        analysisA, err := h.DB.Queries.GetAnalysisByID(ctx, int32(idA))
        if err != nil {
                c.JSON(http.StatusNotFound, gin.H{"error": "Analysis A not found"})
                return
        }

        analysisB, err := h.DB.Queries.GetAnalysisByID(ctx, int32(idB))
        if err != nil {
                c.JSON(http.StatusNotFound, gin.H{"error": "Analysis B not found"})
                return
        }

        if analysisA.Domain != analysisB.Domain {
                c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot compare analyses of different domains"})
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
                c.JSON(http.StatusBadRequest, gin.H{"error": "One or both analyses have no stored data"})
                return
        }

        diffs := ComputeAllDiffs(resultsA, resultsB)

        c.JSON(http.StatusOK, gin.H{
                "domain": analysisA.Domain,
                "analysis_a": gin.H{
                        "id":         analysisA.ID,
                        "domain":     analysisA.Domain,
                        "created_at": formatTimestamp(analysisA.CreatedAt),
                },
                "analysis_b": gin.H{
                        "id":         analysisB.ID,
                        "domain":     analysisB.Domain,
                        "created_at": formatTimestamp(analysisB.CreatedAt),
                },
                "diffs": diffs,
        })
}

func (h *CompareHandler) selectDomain(c *gin.Context, domain string) {
        if domain == "" {
                c.JSON(http.StatusBadRequest, gin.H{"error": "Please provide a domain to compare analyses"})
                return
        }

        ctx := c.Request.Context()
        analyses, err := h.DB.Queries.ListAnalysesByDomain(ctx, dbq.ListAnalysesByDomainParams{
                Domain: domain,
                Limit:  20,
        })
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch analyses"})
                return
        }

        if len(analyses) < 2 {
                c.JSON(http.StatusBadRequest, gin.H{
                        "error": "Need at least 2 analyses to compare",
                        "count": len(analyses),
                })
                return
        }

        type AnalysisItem struct {
                ID        int32  `json:"id"`
                Domain    string `json:"domain"`
                CreatedAt string `json:"created_at"`
        }

        items := make([]AnalysisItem, 0, len(analyses))
        for _, a := range analyses {
                items = append(items, AnalysisItem{
                        ID:        a.ID,
                        Domain:    a.Domain,
                        CreatedAt: formatTimestamp(a.CreatedAt),
                })
        }

        c.JSON(http.StatusOK, gin.H{
                "domain":   domain,
                "analyses": items,
        })
}
