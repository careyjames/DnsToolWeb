package handlers

import (
	"encoding/json"
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

type historyAnalysisItem struct {
	ID               int32
	Domain           string
	AsciiDomain      string
	SpfStatus        string
	DmarcStatus      string
	DkimStatus       string
	AnalysisSuccess  bool
	AnalysisDuration float64
	CreatedDate      string
	CreatedTime      string
	ToolVersion      string
}

func buildHistoryItem(a dbq.DomainAnalysis) historyAnalysisItem {
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
	createdDate, createdTime := "", ""
	if a.CreatedAt.Valid {
		createdDate = a.CreatedAt.Time.Format("2006-01-02")
		createdTime = a.CreatedAt.Time.Format("15:04:05")
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
	return historyAnalysisItem{
		ID:               a.ID,
		Domain:           a.Domain,
		AsciiDomain:      a.AsciiDomain,
		SpfStatus:        spfStatus,
		DmarcStatus:      dmarcStatus,
		DkimStatus:       dkimStatus,
		AnalysisSuccess:  true,
		AnalysisDuration: dur,
		CreatedDate:      createdDate,
		CreatedTime:      createdTime,
		ToolVersion:      toolVersion,
	}
}

func (h *HistoryHandler) History(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
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
			c.HTML(http.StatusInternalServerError, "history.html", gin.H{
				"AppVersion": h.Config.AppVersion,
				"CspNonce":   nonce,
				"ActivePage": "history",
				"FlashMessages": []FlashMessage{{Category: "danger", Message: "Failed to count analyses"}},
			})
			return
		}
		total = count
	} else {
		count, countErr := h.DB.Queries.CountSuccessfulAnalyses(ctx)
		if countErr != nil {
			c.HTML(http.StatusInternalServerError, "history.html", gin.H{
				"AppVersion": h.Config.AppVersion,
				"CspNonce":   nonce,
				"ActivePage": "history",
				"FlashMessages": []FlashMessage{{Category: "danger", Message: "Failed to count analyses"}},
			})
			return
		}
		total = count
	}

	pagination := NewPagination(page, perPage, total)

	var items []historyAnalysisItem

	if searchDomain != "" {
		searchPattern := "%" + searchDomain + "%"
		analyses, queryErr := h.DB.Queries.SearchSuccessfulAnalyses(ctx, dbq.SearchSuccessfulAnalysesParams{
			Domain: searchPattern,
			Limit:  pagination.Limit(),
			Offset: pagination.Offset(),
		})
		if queryErr != nil {
			c.HTML(http.StatusInternalServerError, "history.html", gin.H{
				"AppVersion": h.Config.AppVersion,
				"CspNonce":   nonce,
				"ActivePage": "history",
				"FlashMessages": []FlashMessage{{Category: "danger", Message: "Failed to fetch analyses"}},
			})
			return
		}
		for _, a := range analyses {
			items = append(items, buildHistoryItem(a))
		}
	} else {
		analyses, queryErr := h.DB.Queries.ListSuccessfulAnalyses(ctx, dbq.ListSuccessfulAnalysesParams{
			Limit:  pagination.Limit(),
			Offset: pagination.Offset(),
		})
		if queryErr != nil {
			c.HTML(http.StatusInternalServerError, "history.html", gin.H{
				"AppVersion": h.Config.AppVersion,
				"CspNonce":   nonce,
				"ActivePage": "history",
				"FlashMessages": []FlashMessage{{Category: "danger", Message: "Failed to fetch analyses"}},
			})
			return
		}
		for _, a := range analyses {
			items = append(items, buildHistoryItem(a))
		}
	}

	pd := BuildPagination(page, pagination.TotalPages, total)

	c.HTML(http.StatusOK, "history.html", gin.H{
		"AppVersion":   h.Config.AppVersion,
		"CspNonce":     nonce,
		"ActivePage":   "history",
		"Analyses":     items,
		"Pagination":   pd,
		"SearchDomain": searchDomain,
	})
}
