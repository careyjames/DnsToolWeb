// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "context"
        "encoding/json"
        "fmt"
        "log/slog"
        "net/http"
        "strconv"
        "strings"
        "time"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"
        "dnstool/go-server/internal/dnsclient"

        "github.com/gin-gonic/gin"
)

const (
        templateIndex = "index.html"
)

type AnalysisHandler struct {
        DB              *db.Database
        Config          *config.Config
        Analyzer        *analyzer.Analyzer
        DNSHistoryCache *analyzer.DNSHistoryCache
}

func NewAnalysisHandler(database *db.Database, cfg *config.Config, a *analyzer.Analyzer, historyCache *analyzer.DNSHistoryCache) *AnalysisHandler {
        return &AnalysisHandler{DB: database, Config: cfg, Analyzer: a, DNSHistoryCache: historyCache}
}

func (h *AnalysisHandler) ViewAnalysisStatic(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")
        idStr := c.Param("id")
        analysisID, err := strconv.ParseInt(idStr, 10, 32)
        if err != nil {
                c.HTML(http.StatusBadRequest, templateIndex, gin.H{
                        "AppVersion":    h.Config.AppVersion,
                        "CspNonce":      nonce,
                        "CsrfToken":    csrfToken,
                        "ActivePage":    "home",
                        "FlashMessages": []FlashMessage{{Category: "danger", Message: "Invalid analysis ID"}},
                })
                return
        }

        ctx := c.Request.Context()
        analysis, err := h.DB.Queries.GetAnalysisByID(ctx, int32(analysisID))
        if err != nil {
                c.HTML(http.StatusNotFound, templateIndex, gin.H{
                        "AppVersion":    h.Config.AppVersion,
                        "CspNonce":      nonce,
                        "CsrfToken":    csrfToken,
                        "ActivePage":    "home",
                        "FlashMessages": []FlashMessage{{Category: "danger", Message: "Analysis not found"}},
                })
                return
        }

        if len(analysis.FullResults) == 0 || string(analysis.FullResults) == "null" {
                c.HTML(http.StatusGone, templateIndex, gin.H{
                        "AppVersion":    h.Config.AppVersion,
                        "CspNonce":      nonce,
                        "CsrfToken":    csrfToken,
                        "ActivePage":    "home",
                        "FlashMessages": []FlashMessage{{Category: "warning", Message: "This report is no longer available. Please re-analyze the domain."}},
                })
                return
        }

        results := NormalizeResults(analysis.FullResults)
        if results == nil {
                c.HTML(http.StatusInternalServerError, templateIndex, gin.H{
                        "AppVersion":    h.Config.AppVersion,
                        "CspNonce":      nonce,
                        "CsrfToken":    csrfToken,
                        "ActivePage":    "home",
                        "FlashMessages": []FlashMessage{{Category: "danger", Message: "Failed to parse results"}},
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

        verifyCommands := analyzer.GenerateVerificationCommands(analysis.AsciiDomain, results)

        hashVersion := toolVersion
        if hashVersion == "" {
                hashVersion = h.Config.AppVersion
        }
        integrityHash := analyzer.ReportIntegrityHash(analysis.AsciiDomain, analysis.ID, timestamp, hashVersion, results)
        rfcCount := analyzer.CountVerifiedRFCs(results)

        var supersededByID int32
        newerRow, newerErr := h.DB.Queries.GetNewerAnalysisForDomain(ctx, dbq.GetNewerAnalysisForDomainParams{
                AsciiDomain: analysis.AsciiDomain,
                ID:          analysis.ID,
        })
        if newerErr == nil {
                supersededByID = newerRow.ID
        }

        isSub, rootDom := extractRootDomain(analysis.AsciiDomain)
        c.HTML(http.StatusOK, "results.html", gin.H{
                "AppVersion":           h.Config.AppVersion,
                "CspNonce":             nonce,
                "CsrfToken":           csrfToken,
                "ActivePage":           "",
                "Domain":               analysis.Domain,
                "AsciiDomain":          analysis.AsciiDomain,
                "Results":              results,
                "AnalysisID":           analysis.ID,
                "AnalysisDuration":     dur,
                "AnalysisTimestamp":    timestamp,
                "FromHistory":          true,
                "WaitSeconds":          waitSeconds,
                "WaitReason":           waitReason,
                "DomainExists":         domainExists,
                "ToolVersion":          toolVersion,
                "VerificationCommands": verifyCommands,
                "IsSubdomain":          isSub,
                "RootDomain":           rootDom,
                "SecurityTrailsKey":    "",
                "IntegrityHash":        integrityHash,
                "RFCCount":             rfcCount,
                "SupersededByID":       supersededByID,
        })
}

func (h *AnalysisHandler) ViewAnalysis(c *gin.Context) {
        h.ViewAnalysisStatic(c)
}

func (h *AnalysisHandler) ViewAnalysisExecutive(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")
        idStr := c.Param("id")
        analysisID, err := strconv.ParseInt(idStr, 10, 32)
        if err != nil {
                c.HTML(http.StatusBadRequest, templateIndex, gin.H{
                        "AppVersion":    h.Config.AppVersion,
                        "CspNonce":      nonce,
                        "CsrfToken":    csrfToken,
                        "ActivePage":    "home",
                        "FlashMessages": []FlashMessage{{Category: "danger", Message: "Invalid analysis ID"}},
                })
                return
        }

        ctx := c.Request.Context()
        analysis, err := h.DB.Queries.GetAnalysisByID(ctx, int32(analysisID))
        if err != nil {
                c.HTML(http.StatusNotFound, templateIndex, gin.H{
                        "AppVersion":    h.Config.AppVersion,
                        "CspNonce":      nonce,
                        "CsrfToken":    csrfToken,
                        "ActivePage":    "home",
                        "FlashMessages": []FlashMessage{{Category: "danger", Message: "Analysis not found"}},
                })
                return
        }

        if len(analysis.FullResults) == 0 || string(analysis.FullResults) == "null" {
                c.HTML(http.StatusGone, templateIndex, gin.H{
                        "AppVersion":    h.Config.AppVersion,
                        "CspNonce":      nonce,
                        "CsrfToken":    csrfToken,
                        "ActivePage":    "home",
                        "FlashMessages": []FlashMessage{{Category: "warning", Message: "This report is no longer available. Please re-analyze the domain."}},
                })
                return
        }

        results := NormalizeResults(analysis.FullResults)
        if results == nil {
                c.HTML(http.StatusInternalServerError, templateIndex, gin.H{
                        "AppVersion":    h.Config.AppVersion,
                        "CspNonce":      nonce,
                        "CsrfToken":    csrfToken,
                        "ActivePage":    "home",
                        "FlashMessages": []FlashMessage{{Category: "danger", Message: "Failed to parse results"}},
                })
                return
        }

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

        hashVersion := toolVersion
        if hashVersion == "" {
                hashVersion = h.Config.AppVersion
        }
        integrityHash := analyzer.ReportIntegrityHash(analysis.AsciiDomain, analysis.ID, timestamp, hashVersion, results)
        rfcCount := analyzer.CountVerifiedRFCs(results)

        var supersededByID int32
        newerRow, newerErr := h.DB.Queries.GetNewerAnalysisForDomain(ctx, dbq.GetNewerAnalysisForDomainParams{
                AsciiDomain: analysis.AsciiDomain,
                ID:          analysis.ID,
        })
        if newerErr == nil {
                supersededByID = newerRow.ID
        }

        c.HTML(http.StatusOK, "results_executive.html", gin.H{
                "AppVersion":        h.Config.AppVersion,
                "CspNonce":          nonce,
                "CsrfToken":        csrfToken,
                "ActivePage":        "",
                "Domain":            analysis.Domain,
                "AsciiDomain":       analysis.AsciiDomain,
                "Results":           results,
                "AnalysisID":        analysis.ID,
                "AnalysisDuration":  dur,
                "AnalysisTimestamp": timestamp,
                "DomainExists":      domainExists,
                "ToolVersion":       toolVersion,
                "IntegrityHash":     integrityHash,
                "RFCCount":          rfcCount,
                "SupersededByID":    supersededByID,
        })
}

func (h *AnalysisHandler) Analyze(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")

        domain := strings.TrimSpace(c.PostForm("domain"))
        if domain == "" {
                domain = strings.TrimSpace(c.Query("domain"))
        }

        if domain == "" {
                h.renderIndexFlash(c, nonce, csrfToken, "danger", "Please enter a domain name.")
                return
        }

        if !dnsclient.ValidateDomain(domain) {
                h.renderIndexFlash(c, nonce, csrfToken, "danger", fmt.Sprintf("Invalid domain name: %s", domain))
                return
        }

        asciiDomain, err := dnsclient.DomainToASCII(domain)
        if err != nil {
                asciiDomain = domain
        }

        customSelectors := extractCustomSelectors(c)
        exposureChecks := c.PostForm("exposure_checks") == "1"

        startTime := time.Now()
        ctx := c.Request.Context()

        opts := analyzer.AnalysisOptions{
                ExposureChecks: exposureChecks,
        }
        results := h.Analyzer.AnalyzeDomain(ctx, asciiDomain, customSelectors, opts)
        analysisDuration := time.Since(startTime).Seconds()

        if success, ok := results["analysis_success"].(bool); ok && !success {
                if errMsg, ok := results["error"].(string); ok {
                        h.renderIndexFlash(c, nonce, csrfToken, "warning", errMsg)
                        return
                }
        }

        h.enrichResultsNoHistory(c, asciiDomain, results)

        countryCode, countryName := lookupCountry(c.ClientIP())

        analysisID, timestamp := h.saveAnalysis(c.Request.Context(), domain, asciiDomain, results, analysisDuration, countryCode, countryName)

        domainExists := resultsDomainExists(results)
        verifyCommands := analyzer.GenerateVerificationCommands(asciiDomain, results)

        integrityHash := analyzer.ReportIntegrityHash(asciiDomain, analysisID, timestamp, h.Config.AppVersion, results)
        rfcCount := analyzer.CountVerifiedRFCs(results)

        isSub, rootDom := extractRootDomain(asciiDomain)
        c.HTML(http.StatusOK, "results.html", gin.H{
                "AppVersion":           h.Config.AppVersion,
                "CspNonce":             nonce,
                "CsrfToken":           csrfToken,
                "ActivePage":           "",
                "Domain":               domain,
                "AsciiDomain":          asciiDomain,
                "Results":              results,
                "AnalysisID":           analysisID,
                "AnalysisDuration":     analysisDuration,
                "AnalysisTimestamp":    timestamp,
                "FromHistory":          false,
                "FromCache":            false,
                "DomainExists":         domainExists,
                "ToolVersion":          h.Config.AppVersion,
                "VerificationCommands": verifyCommands,
                "IsSubdomain":          isSub,
                "RootDomain":           rootDom,
                "SecurityTrailsKey":    "",
                "IntegrityHash":        integrityHash,
                "RFCCount":             rfcCount,
                "ExposureChecks":       exposureChecks,
        })
}

func (h *AnalysisHandler) renderIndexFlash(c *gin.Context, nonce, csrfToken any, category, message string) {
        c.HTML(http.StatusOK, templateIndex, gin.H{
                "AppVersion":    h.Config.AppVersion,
                "CspNonce":      nonce,
                "CsrfToken":    csrfToken,
                "ActivePage":    "home",
                "FlashMessages": []FlashMessage{{Category: category, Message: message}},
        })
}

func extractCustomSelectors(c *gin.Context) []string {
        var customSelectors []string
        for _, sel := range []string{c.PostForm("dkim_selector1"), c.PostForm("dkim_selector2")} {
                sel = strings.TrimSpace(sel)
                if sel != "" {
                        customSelectors = append(customSelectors, sel)
                }
        }
        return customSelectors
}


func (h *AnalysisHandler) APIDNSHistory(c *gin.Context) {
        domain := strings.TrimSpace(c.Query("domain"))
        if domain == "" || !dnsclient.ValidateDomain(domain) {
                c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid domain"})
                return
        }
        asciiDomain, err := dnsclient.DomainToASCII(domain)
        if err != nil {
                asciiDomain = domain
        }

        userAPIKey := strings.TrimSpace(c.GetHeader("X-SecurityTrails-Key"))

        if userAPIKey == "" {
                c.JSON(http.StatusOK, gin.H{"status": "no_key", "message": "SecurityTrails API key required"})
                return
        }

        result := analyzer.FetchDNSHistoryWithKey(c.Request.Context(), asciiDomain, userAPIKey, h.DNSHistoryCache)

        status, _ := result["status"].(string)
        if status == "rate_limited" || status == "error" || status == "timeout" {
                c.JSON(http.StatusOK, gin.H{"status": "unavailable"})
                return
        }

        available, _ := result["available"].(bool)
        if !available {
                c.JSON(http.StatusOK, gin.H{"status": "unavailable"})
                return
        }

        c.JSON(http.StatusOK, result)
}

func (h *AnalysisHandler) enrichResultsNoHistory(_ *gin.Context, _ string, results map[string]any) {
        if rem, ok := results["remediation"].(map[string]any); ok {
                results["remediation"] = analyzer.EnrichRemediationWithRFCMeta(rem)
        }

        results["rfc_metadata"] = analyzer.GetAllRFCMetadata()
}

func resultsDomainExists(results map[string]any) bool {
        if v, ok := results["domain_exists"]; ok {
                if b, ok := v.(bool); ok {
                        return b
                }
        }
        return true
}

func (h *AnalysisHandler) APISubdomains(c *gin.Context) {
        domain := strings.TrimPrefix(c.Param("domain"), "/")
        domain = strings.TrimSpace(strings.ToLower(domain))
        if domain == "" {
                c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Domain is required"})
                return
        }
        if !dnsclient.ValidateDomain(domain) {
                c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid domain"})
                return
        }
        result := h.Analyzer.DiscoverSubdomains(c.Request.Context(), domain)
        c.JSON(http.StatusOK, result)
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
                "id":                analysis.ID,
                "domain":            analysis.Domain,
                "ascii_domain":      analysis.AsciiDomain,
                "spf_status":        analysis.SpfStatus,
                "dmarc_status":      analysis.DmarcStatus,
                "dmarc_policy":      analysis.DmarcPolicy,
                "dkim_status":       analysis.DkimStatus,
                "registrar_name":    analysis.RegistrarName,
                "registrar_source":  analysis.RegistrarSource,
                "analysis_success":  analysis.AnalysisSuccess,
                "error_message":     analysis.ErrorMessage,
                "analysis_duration": analysis.AnalysisDuration,
                "created_at":        formatTimestampISO(analysis.CreatedAt),
                "updated_at":        formatTimestampISO(analysis.UpdatedAt),
                "country_code":      analysis.CountryCode,
                "country_name":      analysis.CountryName,
                "full_results":      fullResults,
                "ct_subdomains":     ctSubdomains,
        })
}

func (h *AnalysisHandler) saveAnalysis(ctx context.Context, domain, asciiDomain string, results map[string]any, duration float64, countryCode, countryName string) (int32, string) {
        results["_tool_version"] = h.Config.AppVersion
        fullResultsJSON, _ := json.Marshal(results)

        basicRecordsJSON := getJSONFromResults(results, "basic_records", "")
        authRecordsJSON := getJSONFromResults(results, "authoritative_records", "")

        spfStatus := getStringFromResults(results, "spf_analysis", "status")
        dmarcStatus := getStringFromResults(results, "dmarc_analysis", "status")
        dmarcPolicy := getStringFromResults(results, "dmarc_analysis", "policy")
        dkimStatus := getStringFromResults(results, "dkim_analysis", "status")
        registrarName := getStringFromResults(results, "registrar_info", "registrar_name")
        registrarSource := getStringFromResults(results, "registrar_info", "source")

        spfRecordsJSON := getJSONFromResults(results, "spf_analysis", "records")
        dmarcRecordsJSON := getJSONFromResults(results, "dmarc_analysis", "records")
        dkimSelectorsJSON := getJSONFromResults(results, "dkim_analysis", "selectors")
        ctSubdomainsJSON := getJSONFromResults(results, "ct_subdomains", "")

        postureHash := analyzer.CanonicalPostureHash(results)

        success := true
        var errorMessage *string
        if errStr, ok := results["error"].(string); ok && errStr != "" {
                success = false
                errorMessage = &errStr
        }

        var cc, cn *string
        if countryCode != "" {
                cc = &countryCode
        }
        if countryName != "" {
                cn = &countryName
        }

        params := dbq.InsertAnalysisParams{
                Domain:               domain,
                AsciiDomain:          asciiDomain,
                BasicRecords:         basicRecordsJSON,
                AuthoritativeRecords: authRecordsJSON,
                SpfStatus:            spfStatus,
                SpfRecords:           spfRecordsJSON,
                DmarcStatus:          dmarcStatus,
                DmarcPolicy:          dmarcPolicy,
                DmarcRecords:         dmarcRecordsJSON,
                DkimStatus:           dkimStatus,
                DkimSelectors:        dkimSelectorsJSON,
                RegistrarName:        registrarName,
                RegistrarSource:      registrarSource,
                CtSubdomains:         ctSubdomainsJSON,
                FullResults:          fullResultsJSON,
                CountryCode:          cc,
                CountryName:          cn,
                AnalysisSuccess:      &success,
                ErrorMessage:         errorMessage,
                AnalysisDuration:     &duration,
                PostureHash:          &postureHash,
        }

        row, err := h.DB.Queries.InsertAnalysis(ctx, params)
        if err != nil {
                slog.Error("Failed to save analysis", "domain", domain, "error", err)
                return 0, time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
        }

        timestamp := "just now"
        if row.CreatedAt.Valid {
                timestamp = row.CreatedAt.Time.Format("2006-01-02 15:04:05 UTC")
        }
        return row.ID, timestamp
}

func lookupCountry(ip string) (string, string) {
        if ip == "" || ip == "127.0.0.1" || ip == "::1" {
                return "", ""
        }

        client := &http.Client{Timeout: 2 * time.Second}
        resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=status,countryCode,country", ip))
        if err != nil {
                return "", ""
        }
        defer resp.Body.Close()

        if resp.StatusCode != 200 {
                return "", ""
        }

        var result struct {
                Status      string `json:"status"`
                CountryCode string `json:"countryCode"`
                Country     string `json:"country"`
        }
        if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || result.Status != "success" {
                return "", ""
        }
        return result.CountryCode, result.Country
}

func getStringFromResults(results map[string]any, section, key string) *string {
        if key == "" {
                if v, ok := results[section]; ok {
                        if s, ok := v.(string); ok {
                                return &s
                        }
                }
                return nil
        }
        sectionData, ok := results[section].(map[string]any)
        if !ok {
                return nil
        }
        v, ok := sectionData[key]
        if !ok {
                return nil
        }
        s, ok := v.(string)
        if !ok {
                return nil
        }
        return &s
}

func getJSONFromResults(results map[string]any, section, key string) json.RawMessage {
        var data any
        if key == "" {
                data = results[section]
        } else {
                sectionData, ok := results[section].(map[string]any)
                if !ok {
                        return nil
                }
                data = sectionData[key]
        }
        if data == nil {
                return nil
        }
        b, err := json.Marshal(data)
        if err != nil {
                return nil
        }
        return b
}
