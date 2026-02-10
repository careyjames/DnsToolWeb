package handlers

import (
        "net/http"
        "strings"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"

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
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")
        ctx := c.Request.Context()

        recentStats, err := h.DB.Queries.ListRecentStats(ctx, 30)
        if err != nil {
                c.HTML(http.StatusInternalServerError, "stats.html", gin.H{
                        "AppVersion":     h.Config.AppVersion,
                        "CspNonce":       nonce,
                        "CsrfToken":     csrfToken,
                        "ActivePage":     "stats",
                        "FlashMessages":  []FlashMessage{{Category: "danger", Message: "Failed to fetch stats"}},
                })
                return
        }

        totalAnalyses, _ := h.DB.Queries.CountAllAnalyses(ctx)
        successfulAnalyses, _ := h.DB.Queries.CountSuccessfulAnalysesTotal(ctx)
        uniqueDomains, _ := h.DB.Queries.CountUniqueDomainsTotal(ctx)

        popularDomains, _ := h.DB.Queries.ListPopularDomains(ctx, 10)
        countryStats, _ := h.DB.Queries.ListCountryDistribution(ctx, 20)

        maxRecentStats := 7
        if len(recentStats) < maxRecentStats {
                maxRecentStats = len(recentStats)
        }
        slicedStats := recentStats[:maxRecentStats]

        statItems := make([]DailyStat, 0, len(slicedStats))
        for _, s := range slicedStats {
                statItems = append(statItems, buildDailyStat(s))
        }

        popItems := make([]PopularDomain, 0, len(popularDomains))
        for _, d := range popularDomains {
                popItems = append(popItems, PopularDomain{Domain: d.Domain, Count: d.Count})
        }

        countryItems := make([]CountryStat, 0, len(countryStats))
        for _, cs := range countryStats {
                countryItems = append(countryItems, buildCountryStat(cs))
        }

        c.HTML(http.StatusOK, "stats.html", gin.H{
                "AppVersion":         h.Config.AppVersion,
                "CspNonce":           nonce,
                "CsrfToken":         csrfToken,
                "ActivePage":         "stats",
                "TotalAnalyses":      totalAnalyses,
                "SuccessfulAnalyses": successfulAnalyses,
                "UniqueDomains":      uniqueDomains,
                "CountryStats":       countryItems,
                "PopularDomains":     popItems,
                "RecentStats":        statItems,
        })
}

func buildDailyStat(s dbq.AnalysisStat) DailyStat {
        dateStr := ""
        if s.Date.Valid {
                dateStr = s.Date.Time.Format("01/02")
        }
        var total, successful, failed, unique int32
        if s.TotalAnalyses != nil {
                total = *s.TotalAnalyses
        }
        if s.SuccessfulAnalyses != nil {
                successful = *s.SuccessfulAnalyses
        }
        if s.FailedAnalyses != nil {
                failed = *s.FailedAnalyses
        }
        if s.UniqueDomains != nil {
                unique = *s.UniqueDomains
        }
        var avg float64
        hasAvg := false
        if s.AvgAnalysisTime != nil {
                avg = *s.AvgAnalysisTime
                hasAvg = true
        }
        return DailyStat{
                Date:               dateStr,
                TotalAnalyses:      total,
                SuccessfulAnalyses: successful,
                FailedAnalyses:     failed,
                UniqueDomains:      unique,
                AvgAnalysisTime:    avg,
                HasAvgTime:         hasAvg,
        }
}

func buildCountryStat(cs dbq.ListCountryDistributionRow) CountryStat {
        code, name := "", ""
        if cs.CountryCode != nil {
                code = *cs.CountryCode
        }
        if cs.CountryName != nil {
                name = *cs.CountryName
        }
        flag := ""
        if len(code) == 2 {
                upper := strings.ToUpper(code)
                r1 := rune(0x1F1E6 + int(upper[0]) - int('A'))
                r2 := rune(0x1F1E6 + int(upper[1]) - int('A'))
                flag = string([]rune{r1, r2})
        }
        return CountryStat{Code: code, Name: name, Count: cs.Count, Flag: flag}
}

func (h *StatsHandler) StatisticsRedirect(c *gin.Context) {
        c.Redirect(http.StatusFound, "/stats")
}
