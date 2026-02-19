// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"
	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/zoneparse"

	"github.com/gin-gonic/gin"
)

const maxZoneFileSize = 2 << 20 // 2 MB

type ZoneHandler struct {
	DB     *db.Database
	Config *config.Config
}

func NewZoneHandler(database *db.Database, cfg *config.Config) *ZoneHandler {
	return &ZoneHandler{DB: database, Config: cfg}
}

func (h *ZoneHandler) UploadForm(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")

	data := gin.H{
		"AppVersion":      h.Config.AppVersion,
		"CspNonce":        nonce,
		"CsrfToken":       csrfToken,
		"ActivePage":      "zone",
		"ShowForm":        true,
		"MaintenanceNote": h.Config.MaintenanceNote,
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "zone.html", data)
}

func (h *ZoneHandler) ProcessUpload(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")

	uid, _ := c.Get("user_id")
	userID, _ := uid.(int32)

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxZoneFileSize+1024)

	file, header, err := c.Request.FormFile("zone_file")
	if err != nil {
		h.renderZoneFlash(c, nonce, csrfToken, "danger", "Please select a zone file to upload.")
		return
	}
	defer file.Close()

	if header.Size > maxZoneFileSize {
		h.renderZoneFlash(c, nonce, csrfToken, "danger", "Zone file exceeds the 2 MB size limit.")
		return
	}

	domainOverride := strings.TrimSpace(c.PostForm("domain_override"))
	retain := c.PostForm("retain") == "1"

	parseResult, rawData, err := zoneparse.ParseZoneFile(file, domainOverride)
	if err != nil {
		slog.Error("Zone file parse error", "error", err)
		h.renderZoneFlash(c, nonce, csrfToken, "danger", "Failed to parse zone file: "+err.Error())
		return
	}

	if parseResult.RecordCount == 0 {
		h.renderZoneFlash(c, nonce, csrfToken, "warning", "No DNS records found in the uploaded zone file. Verify the file format.")
		return
	}

	domain := parseResult.Domain
	if domain == "" {
		h.renderZoneFlash(c, nonce, csrfToken, "danger", "Could not determine the domain from the zone file. Please provide a domain override.")
		return
	}

	ctx := c.Request.Context()
	var driftReport *zoneparse.DriftReport
	var liveAnalysisID int32

	analysis, err := h.DB.Queries.GetRecentAnalysisByDomain(ctx, domain)
	if err == nil && len(analysis.FullResults) > 0 {
		var liveResults map[string]any
		if json.Unmarshal(analysis.FullResults, &liveResults) == nil {
			driftReport = zoneparse.CompareDrift(parseResult.Records, liveResults)
			driftReport.Domain = domain
			liveAnalysisID = analysis.ID
		}
	}

	if retain && userID > 0 {
		var driftJSON []byte
		if driftReport != nil {
			driftJSON, _ = json.Marshal(driftReport)
		}
		var zoneDataPtr *string
		zoneStr := string(rawData)
		zoneDataPtr = &zoneStr

		_, dbErr := h.DB.Queries.InsertZoneImport(ctx, dbq.InsertZoneImportParams{
			UserID:           userID,
			Domain:           domain,
			Sha256Hash:       parseResult.SHA256,
			OriginalFilename: header.Filename,
			FileSize:         int32(header.Size),
			RecordCount:      int32(parseResult.RecordCount),
			Retained:         true,
			ZoneData:         zoneDataPtr,
			DriftSummary:     driftJSON,
		})
		if dbErr != nil {
			slog.Error("Failed to store zone import", "error", dbErr, "domain", domain, "user_id", userID)
		}
	}

	data := gin.H{
		"AppVersion":      h.Config.AppVersion,
		"CspNonce":        nonce,
		"CsrfToken":       csrfToken,
		"ActivePage":      "zone",
		"ShowForm":        false,
		"ShowResults":     true,
		"ParseResult":     parseResult,
		"DriftReport":     driftReport,
		"LiveAnalysisID":  liveAnalysisID,
		"Filename":        header.Filename,
		"FileSize":        header.Size,
		"Retained":        retain,
		"MaintenanceNote": h.Config.MaintenanceNote,
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "zone.html", data)
}

func (h *ZoneHandler) renderZoneFlash(c *gin.Context, nonce, csrfToken any, category, message string) {
	data := gin.H{
		"AppVersion":      h.Config.AppVersion,
		"CspNonce":        nonce,
		"CsrfToken":       csrfToken,
		"ActivePage":      "zone",
		"ShowForm":        true,
		"FlashMessages":   []FlashMessage{{Category: category, Message: message}},
		"MaintenanceNote": h.Config.MaintenanceNote,
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "zone.html", data)
}
