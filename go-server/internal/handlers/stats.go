package handlers

import (
        "net/http"

        "dnstool/internal/config"
        "dnstool/internal/db"

        "github.com/gin-gonic/gin"
)

type StatsHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewStatsHandler(database *db.Database, cfg *config.Config) *StatsHandler {
        return &StatsHandler{DB: database, Config: cfg}
}

func (h *StatsHandler) Stats(c *gin.Context) {
        ctx := c.Request.Context()

        recentStats, err := h.DB.Queries.ListRecentStats(ctx, 30)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch stats"})
                return
        }

        totalAnalyses, _ := h.DB.Queries.CountAllAnalyses(ctx)
        successfulAnalyses, _ := h.DB.Queries.CountSuccessfulAnalysesTotal(ctx)
        uniqueDomains, _ := h.DB.Queries.CountUniqueDomainsTotal(ctx)

        popularDomains, _ := h.DB.Queries.ListPopularDomains(ctx, 10)
        countryStats, _ := h.DB.Queries.ListCountryDistribution(ctx, 20)

        type StatItem struct {
                Date               string   `json:"date"`
                TotalAnalyses      *int32   `json:"total_analyses"`
                SuccessfulAnalyses *int32   `json:"successful_analyses"`
                FailedAnalyses     *int32   `json:"failed_analyses"`
                UniqueDomains      *int32   `json:"unique_domains"`
                AvgAnalysisTime    *float64 `json:"avg_analysis_time"`
        }

        statItems := make([]StatItem, 0, len(recentStats))
        for _, s := range recentStats {
                dateStr := ""
                if s.Date.Valid {
                        dateStr = s.Date.Time.Format("2006-01-02")
                }
                statItems = append(statItems, StatItem{
                        Date:               dateStr,
                        TotalAnalyses:      s.TotalAnalyses,
                        SuccessfulAnalyses: s.SuccessfulAnalyses,
                        FailedAnalyses:     s.FailedAnalyses,
                        UniqueDomains:      s.UniqueDomains,
                        AvgAnalysisTime:    s.AvgAnalysisTime,
                })
        }

        type PopularItem struct {
                Domain string `json:"domain"`
                Count  int64  `json:"count"`
        }
        popItems := make([]PopularItem, 0, len(popularDomains))
        for _, d := range popularDomains {
                popItems = append(popItems, PopularItem{Domain: d.Domain, Count: d.Count})
        }

        type CountryItem struct {
                Code  string `json:"code"`
                Name  string `json:"name"`
                Count int64  `json:"count"`
        }
        countryItems := make([]CountryItem, 0, len(countryStats))
        for _, cs := range countryStats {
                code, name := "", ""
                if cs.CountryCode != nil {
                        code = *cs.CountryCode
                }
                if cs.CountryName != nil {
                        name = *cs.CountryName
                }
                countryItems = append(countryItems, CountryItem{Code: code, Name: name, Count: cs.Count})
        }

        c.JSON(http.StatusOK, gin.H{
                "recent_stats":        statItems,
                "total_analyses":      totalAnalyses,
                "successful_analyses": successfulAnalyses,
                "unique_domains":      uniqueDomains,
                "popular_domains":     popItems,
                "country_stats":       countryItems,
        })
}

func (h *StatsHandler) StatisticsRedirect(c *gin.Context) {
        c.Redirect(http.StatusFound, "/stats")
}
