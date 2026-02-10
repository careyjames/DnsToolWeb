package handlers

import (
        "net/http"
        "strconv"

        "dnstool/internal/config"
        "dnstool/internal/db"
        "dnstool/internal/dbq"

        "github.com/gin-gonic/gin"
)

type HistoryHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewHistoryHandler(database *db.Database, cfg *config.Config) *HistoryHandler {
        return &HistoryHandler{DB: database, Config: cfg}
}

func (h *HistoryHandler) History(c *gin.Context) {
        page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
        if page < 1 {
                page = 1
        }
        searchDomain := c.Query("domain")
        perPage := 20

        ctx := c.Request.Context()

        var total int64

        if searchDomain != "" {
                searchPattern := "%" + searchDomain + "%"
                count, countErr := h.DB.Queries.CountSearchSuccessfulAnalyses(ctx, searchPattern)
                if countErr != nil {
                        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count analyses"})
                        return
                }
                total = count
        } else {
                count, countErr := h.DB.Queries.CountSuccessfulAnalyses(ctx)
                if countErr != nil {
                        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count analyses"})
                        return
                }
                total = count
        }

        pagination := NewPagination(page, perPage, total)

        type AnalysisItem struct {
                ID               int32   `json:"id"`
                Domain           string  `json:"domain"`
                AsciiDomain      string  `json:"ascii_domain"`
                SpfStatus        *string `json:"spf_status"`
                DmarcStatus      *string `json:"dmarc_status"`
                DkimStatus       *string `json:"dkim_status"`
                AnalysisDuration *float64 `json:"analysis_duration"`
                CreatedAt        string  `json:"created_at"`
                CountryCode      *string `json:"country_code"`
                CountryName      *string `json:"country_name"`
        }

        var items []AnalysisItem

        if searchDomain != "" {
                searchPattern := "%" + searchDomain + "%"
                analyses, queryErr := h.DB.Queries.SearchSuccessfulAnalyses(ctx, dbq.SearchSuccessfulAnalysesParams{
                        Domain: searchPattern,
                        Limit:  pagination.Limit(),
                        Offset: pagination.Offset(),
                })
                if queryErr != nil {
                        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch analyses"})
                        return
                }
                for _, a := range analyses {
                        items = append(items, AnalysisItem{
                                ID: a.ID, Domain: a.Domain, AsciiDomain: a.AsciiDomain,
                                SpfStatus: a.SpfStatus, DmarcStatus: a.DmarcStatus, DkimStatus: a.DkimStatus,
                                AnalysisDuration: a.AnalysisDuration,
                                CreatedAt:        formatTimestamp(a.CreatedAt),
                                CountryCode:      a.CountryCode, CountryName: a.CountryName,
                        })
                }
        } else {
                analyses, queryErr := h.DB.Queries.ListSuccessfulAnalyses(ctx, dbq.ListSuccessfulAnalysesParams{
                        Limit:  pagination.Limit(),
                        Offset: pagination.Offset(),
                })
                if queryErr != nil {
                        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch analyses"})
                        return
                }
                for _, a := range analyses {
                        items = append(items, AnalysisItem{
                                ID: a.ID, Domain: a.Domain, AsciiDomain: a.AsciiDomain,
                                SpfStatus: a.SpfStatus, DmarcStatus: a.DmarcStatus, DkimStatus: a.DkimStatus,
                                AnalysisDuration: a.AnalysisDuration,
                                CreatedAt:        formatTimestamp(a.CreatedAt),
                                CountryCode:      a.CountryCode, CountryName: a.CountryName,
                        })
                }
        }

        c.JSON(http.StatusOK, gin.H{
                "analyses":      items,
                "pagination":    pagination,
                "search_domain": searchDomain,
        })
}
