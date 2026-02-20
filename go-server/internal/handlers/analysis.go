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
        "dnstool/go-server/internal/icae"
        "dnstool/go-server/internal/scanner"

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

func (h *AnalysisHandler) checkPrivateAccess(c *gin.Context, analysisID int32, private bool) bool {
        if !private {
                return true
        }
        auth, exists := c.Get("authenticated")
        if !exists || auth != true {
                return false
        }
        uid, ok := c.Get("user_id")
        if !ok {
                return false
        }
        userID, ok := uid.(int32)
        if !ok {
                return false
        }
        isOwner, err := h.DB.Queries.CheckAnalysisOwnership(c.Request.Context(), dbq.CheckAnalysisOwnershipParams{
                AnalysisID: analysisID,
                UserID:     userID,
        })
        return err == nil && isOwner
}

func (h *AnalysisHandler) ViewAnalysisStatic(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")
        idStr := c.Param("id")
        analysisID, err := strconv.ParseInt(idStr, 10, 32)
        if err != nil {
                h.renderErrorPage(c, http.StatusBadRequest, nonce, csrfToken, "danger", "Invalid analysis ID")
                return
        }

        ctx := c.Request.Context()
        analysis, err := h.DB.Queries.GetAnalysisByID(ctx, int32(analysisID))
        if err != nil {
                h.renderErrorPage(c, http.StatusNotFound, nonce, csrfToken, "danger", "Analysis not found")
                return
        }

        if !h.checkPrivateAccess(c, analysis.ID, analysis.Private) {
                h.renderRestrictedAccess(c, nonce, csrfToken)
                return
        }

        if len(analysis.FullResults) == 0 || string(analysis.FullResults) == "null" {
                h.renderErrorPage(c, http.StatusGone, nonce, csrfToken, "warning", "This report is no longer available. Please re-analyze the domain.")
                return
        }

        results := NormalizeResults(analysis.FullResults)
        if results == nil {
                h.renderErrorPage(c, http.StatusInternalServerError, nonce, csrfToken, "danger", "Failed to parse results")
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

        toolVersion := extractToolVersion(results)
        verifyCommands := analyzer.GenerateVerificationCommands(analysis.AsciiDomain, results)

        hashVersion := toolVersion
        if hashVersion == "" {
                hashVersion = h.Config.AppVersion
        }
        integrityHash := analyzer.ReportIntegrityHash(analysis.AsciiDomain, analysis.ID, timestamp, hashVersion, results)
        rfcCount := analyzer.CountVerifiedRFCs(results)

        currentHash := ""
        if analysis.PostureHash != nil {
                currentHash = *analysis.PostureHash
        }
        drift := driftInfo{}
        if currentHash != "" {
                prevRow, prevErr := h.DB.Queries.GetPreviousAnalysisForDriftBefore(ctx, dbq.GetPreviousAnalysisForDriftBeforeParams{
                        Domain: analysis.Domain,
                        ID:     analysis.ID,
                })
                if prevErr == nil {
                        drift = computeDriftFromPrev(currentHash, prevRow.PostureHash, prevRow.ID, prevRow.CreatedAt.Valid, prevRow.CreatedAt.Time, prevRow.FullResults, results)
                }
        }

        isSub, rootDom := extractRootDomain(analysis.AsciiDomain)

        var emailScope *subdomainEmailScope
        if isSub && rootDom != "" {
                es := computeSubdomainEmailScope(ctx, h.Analyzer.DNS, analysis.AsciiDomain, rootDom, results)
                emailScope = &es
        }

        viewData := gin.H{
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
                "DomainExists":         resultsDomainExists(results),
                "ToolVersion":          toolVersion,
                "VerificationCommands": verifyCommands,
                "IsSubdomain":          isSub,
                "RootDomain":           rootDom,
                "SecurityTrailsKey":    "",
                "IntegrityHash":        integrityHash,
                "RFCCount":             rfcCount,
                "MaintenanceNote":      h.Config.MaintenanceNote,
                "SectionTuning":        h.Config.SectionTuning,
                "PostureHash":          currentHash,
                "DriftDetected":        drift.Detected,
                "DriftPrevHash":        drift.PrevHash,
                "DriftPrevTime":        drift.PrevTime,
                "DriftPrevID":          drift.PrevID,
                "DriftFields":          drift.Fields,
                "IsPublicSuffix":       isPublicSuffixDomain(analysis.AsciiDomain),
                "SubdomainEmailScope":  emailScope,
        }
        if icaeMetrics := icae.LoadReportMetrics(ctx, h.DB.Queries); icaeMetrics != nil {
                viewData["ICAEMetrics"] = icaeMetrics
        }

        mergeAuthData(c, h.Config, viewData)
        c.HTML(http.StatusOK, "results.html", viewData)
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
                h.renderErrorPage(c, http.StatusBadRequest, nonce, csrfToken, "danger", "Invalid analysis ID")
                return
        }

        ctx := c.Request.Context()
        analysis, err := h.DB.Queries.GetAnalysisByID(ctx, int32(analysisID))
        if err != nil {
                h.renderErrorPage(c, http.StatusNotFound, nonce, csrfToken, "danger", "Analysis not found")
                return
        }

        if !h.checkPrivateAccess(c, analysis.ID, analysis.Private) {
                h.renderRestrictedAccess(c, nonce, csrfToken)
                return
        }

        if len(analysis.FullResults) == 0 || string(analysis.FullResults) == "null" {
                h.renderErrorPage(c, http.StatusGone, nonce, csrfToken, "warning", "This report is no longer available. Please re-analyze the domain.")
                return
        }

        results := NormalizeResults(analysis.FullResults)
        if results == nil {
                h.renderErrorPage(c, http.StatusInternalServerError, nonce, csrfToken, "danger", "Failed to parse results")
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

        toolVersion := extractToolVersion(results)
        hashVersion := toolVersion
        if hashVersion == "" {
                hashVersion = h.Config.AppVersion
        }
        integrityHash := analyzer.ReportIntegrityHash(analysis.AsciiDomain, analysis.ID, timestamp, hashVersion, results)
        rfcCount := analyzer.CountVerifiedRFCs(results)

        execData := gin.H{
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
                "DomainExists":      resultsDomainExists(results),
                "ToolVersion":       toolVersion,
                "IntegrityHash":     integrityHash,
                "RFCCount":          rfcCount,
                "MaintenanceNote":   h.Config.MaintenanceNote,
                "SectionTuning":     h.Config.SectionTuning,
        }
        mergeAuthData(c, h.Config, execData)
        c.HTML(http.StatusOK, "results_executive.html", execData)
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
        hasNovelSelectors := len(customSelectors) > 0 && !analyzer.AllSelectorsKnown(customSelectors)
        exposureChecks := c.PostForm("exposure_checks") == "1"
        devNull := c.PostForm("devnull") == "1"

        isAuthenticated := false
        var userID int32
        if auth, exists := c.Get("authenticated"); exists && auth == true {
                isAuthenticated = true
                if uid, ok := c.Get("user_id"); ok {
                        userID, _ = uid.(int32)
                }
        }

        ephemeral := devNull || (hasNovelSelectors && !isAuthenticated)

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

        domainExists := true
        if de, ok := results["domain_exists"].(bool); ok && !de {
                domainExists = false
        }

        clientIP := c.ClientIP()
        countryCode, countryName := lookupCountry(clientIP)

        scanClass := scanner.Classify(asciiDomain, clientIP)

        postureHash := analyzer.CanonicalPostureHash(results)

        drift := driftInfo{}
        if !devNull && domainExists {
                prevRow, prevErr := h.DB.Queries.GetPreviousAnalysisForDrift(ctx, asciiDomain)
                if prevErr == nil {
                        drift = computeDriftFromPrev(postureHash, prevRow.PostureHash, prevRow.ID, prevRow.CreatedAt.Valid, prevRow.CreatedAt.Time, prevRow.FullResults, results)
                        if drift.Detected {
                                slog.Info("Posture drift detected", "domain", asciiDomain, "prev_hash", drift.PrevHash[:8], "new_hash", postureHash[:8], "changed_fields", len(drift.Fields))
                        }
                }
        }

        var analysisID int32
        var timestamp string
        isPrivate := hasNovelSelectors && isAuthenticated

        if ephemeral || !domainExists {
                if devNull {
                        slog.Info("/dev/null scan — full analysis, zero persistence", "domain", asciiDomain)
                } else if !domainExists {
                        slog.Info("Non-existent/undelegated domain — not persisted", "domain", asciiDomain)
                } else {
                        slog.Info("Ephemeral analysis (custom DKIM selectors, unauthenticated) — not persisted", "domain", asciiDomain)
                }
                timestamp = time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
        } else {
                analysisID, timestamp = h.saveAnalysis(c.Request.Context(), domain, asciiDomain, results, analysisDuration, countryCode, countryName, isPrivate, hasNovelSelectors, scanClass)
        }

        if analysisID > 0 && isAuthenticated && userID > 0 {
                go func() {
                        err := h.DB.Queries.InsertUserAnalysis(context.Background(), dbq.InsertUserAnalysisParams{
                                UserID:     userID,
                                AnalysisID: analysisID,
                        })
                        if err != nil {
                                slog.Error("Failed to record user analysis association", "user_id", userID, "analysis_id", analysisID, "error", err)
                        }
                }()
        }

        if !ephemeral && domainExists {
                icae.EvaluateAndRecord(context.Background(), h.DB.Queries, h.Config.AppVersion)
        }

        if !ephemeral && domainExists {
                if ac, exists := c.Get("analytics_collector"); exists {
                        if collector, ok := ac.(interface{ RecordAnalysis(string) }); ok {
                                collector.RecordAnalysis(asciiDomain)
                        }
                }
        }

        verifyCommands := analyzer.GenerateVerificationCommands(asciiDomain, results)
        integrityHash := analyzer.ReportIntegrityHash(asciiDomain, analysisID, timestamp, h.Config.AppVersion, results)
        rfcCount := analyzer.CountVerifiedRFCs(results)

        isSub, rootDom := extractRootDomain(asciiDomain)
        isPublicSuffix := isPublicSuffixDomain(asciiDomain)

        var emailScope *subdomainEmailScope
        if isSub && rootDom != "" {
                es := computeSubdomainEmailScope(ctx, h.Analyzer.DNS, asciiDomain, rootDom, results)
                emailScope = &es
        }

        analyzeData := gin.H{
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
                "DomainExists":         resultsDomainExists(results),
                "ToolVersion":          h.Config.AppVersion,
                "VerificationCommands": verifyCommands,
                "IsSubdomain":          isSub,
                "RootDomain":           rootDom,
                "SecurityTrailsKey":    "",
                "IntegrityHash":        integrityHash,
                "RFCCount":             rfcCount,
                "ExposureChecks":       exposureChecks,
                "MaintenanceNote":      h.Config.MaintenanceNote,
                "SectionTuning":        h.Config.SectionTuning,
                "PostureHash":          postureHash,
                "DriftDetected":        drift.Detected,
                "DriftPrevHash":        drift.PrevHash,
                "DriftPrevTime":        drift.PrevTime,
                "DriftPrevID":          drift.PrevID,
                "DriftFields":          drift.Fields,
                "Ephemeral":            ephemeral,
                "DevNull":              devNull,
                "IsPrivateReport":      isPrivate,
                "IsPublicSuffix":       isPublicSuffix,
                "SubdomainEmailScope":  emailScope,
        }
        if icaeMetrics := icae.LoadReportMetrics(ctx, h.DB.Queries); icaeMetrics != nil {
                analyzeData["ICAEMetrics"] = icaeMetrics
        }

        if devNull {
                c.Header("X-Hacker", "MUST means MUST -- not kinda, maybe, should. // DNS Tool")
                c.Header("X-Persistence", "/dev/null")
        }

        mergeAuthData(c, h.Config, analyzeData)
        c.HTML(http.StatusOK, "results.html", analyzeData)
}

type driftInfo struct {
        Detected bool
        PrevHash string
        PrevTime string
        PrevID   int32
        Fields   []analyzer.PostureDiffField
}

func computeDriftFromPrev(currentHash string, prevHash *string, prevID int32, prevCreatedAtValid bool, prevCreatedAt time.Time, prevFullResults json.RawMessage, currentResults map[string]any) driftInfo {
        if prevHash == nil || *prevHash == "" || *prevHash == currentHash {
                return driftInfo{}
        }
        di := driftInfo{
                Detected: true,
                PrevHash: *prevHash,
                PrevID:   prevID,
        }
        if prevCreatedAtValid {
                di.PrevTime = prevCreatedAt.Format("2 Jan 2006 15:04 UTC")
        }
        if prevFullResults != nil {
                var prevResults map[string]any
                if json.Unmarshal(prevFullResults, &prevResults) == nil {
                        di.Fields = analyzer.ComputePostureDiff(prevResults, currentResults)
                }
        }
        return di
}

func (h *AnalysisHandler) renderRestrictedAccess(c *gin.Context, nonce, csrfToken any) {
        auth, _ := c.Get("authenticated")
        if auth != true {
                h.renderErrorPage(c, http.StatusNotFound, nonce, csrfToken, "danger", "Analysis not found")
                return
        }
        msg := "This report includes user-provided intelligence and is restricted to its owner. " +
                "Custom selectors can reveal internal mail infrastructure and vendor relationships — " +
                "responsible intelligence handling means sharing only with trusted parties. " +
                "If you should have access, request it from the report owner."
        errData := gin.H{
                "AppVersion":    h.Config.AppVersion,
                "CspNonce":      nonce,
                "CsrfToken":    csrfToken,
                "ActivePage":    "home",
                "FlashMessages": []FlashMessage{{Category: "warning", Message: msg}},
        }
        mergeAuthData(c, h.Config, errData)
        c.HTML(http.StatusForbidden, templateIndex, errData)
}

func (h *AnalysisHandler) renderErrorPage(c *gin.Context, status int, nonce, csrfToken any, category, message string) {
        errData := gin.H{
                "AppVersion":    h.Config.AppVersion,
                "CspNonce":      nonce,
                "CsrfToken":    csrfToken,
                "ActivePage":    "home",
                "FlashMessages": []FlashMessage{{Category: category, Message: message}},
        }
        mergeAuthData(c, h.Config, errData)
        c.HTML(status, templateIndex, errData)
}

func extractToolVersion(results map[string]any) string {
        if tv, ok := results["_tool_version"].(string); ok {
                return tv
        }
        return ""
}

func (h *AnalysisHandler) renderIndexFlash(c *gin.Context, nonce, csrfToken any, category, message string) {
        flashData := gin.H{
                "AppVersion":    h.Config.AppVersion,
                "CspNonce":      nonce,
                "CsrfToken":    csrfToken,
                "ActivePage":    "home",
                "FlashMessages": []FlashMessage{{Category: category, Message: message}},
        }
        mergeAuthData(c, h.Config, flashData)
        c.HTML(http.StatusOK, templateIndex, flashData)
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

func (h *AnalysisHandler) ExportSubdomainsCSV(c *gin.Context) {
        domain := strings.TrimSpace(strings.ToLower(c.Query("domain")))
        if domain == "" {
                c.Redirect(http.StatusFound, "/")
                return
        }
        if !dnsclient.ValidateDomain(domain) {
                c.Redirect(http.StatusFound, "/")
                return
        }

        cached, ok := h.Analyzer.GetCTCache(domain)
        if !ok || len(cached) == 0 {
                c.Redirect(http.StatusFound, "/analyze?domain="+domain)
                return
        }

        timestamp := time.Now().UTC().Format("20060102_150405")
        filename := fmt.Sprintf("%s_subdomains_%s.csv", strings.ReplaceAll(domain, ".", "_"), timestamp)

        c.Header("Content-Type", "text/csv; charset=utf-8")
        c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
        c.Status(http.StatusOK)

        w := c.Writer
        w.WriteString("Subdomain,Status,Source,CNAME Target,Provider,Certificates,First Seen,Issuers\n")

        for _, sd := range cached {
                name, _ := sd["name"].(string)
                status := "Expired"
                if isCur, ok := sd["is_current"].(bool); ok && isCur {
                        status = "Current"
                }
                source, _ := sd["source"].(string)
                cnameTarget, _ := sd["cname_target"].(string)
                provider, _ := sd["provider"].(string)
                certCount, _ := sd["cert_count"].(string)
                firstSeen, _ := sd["first_seen"].(string)

                var issuerStr string
                if issuers, ok := sd["issuers"].([]string); ok && len(issuers) > 0 {
                        issuerStr = strings.Join(issuers, "; ")
                }

                w.WriteString(csvEscape(name) + "," +
                        csvEscape(status) + "," +
                        csvEscape(source) + "," +
                        csvEscape(cnameTarget) + "," +
                        csvEscape(provider) + "," +
                        csvEscape(certCount) + "," +
                        csvEscape(firstSeen) + "," +
                        csvEscape(issuerStr) + "\n")
        }
        w.Flush()
}

func csvEscape(s string) string {
        if strings.ContainsAny(s, ",\"\n\r") {
                return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
        }
        return s
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

        if !h.checkPrivateAccess(c, analysis.ID, analysis.Private) {
                auth, _ := c.Get("authenticated")
                if auth == true {
                        c.JSON(http.StatusForbidden, gin.H{
                                "error":   "restricted",
                                "message": "This report includes user-provided intelligence and is restricted to its owner. Custom selectors can reveal internal mail infrastructure and vendor relationships.",
                        })
                } else {
                        c.JSON(http.StatusNotFound, gin.H{"error": "Analysis not found"})
                }
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

func (h *AnalysisHandler) saveAnalysis(ctx context.Context, domain, asciiDomain string, results map[string]any, duration float64, countryCode, countryName string, private, hasUserSelectors bool, scanClass scanner.Classification) (int32, string) {
        results["_tool_version"] = h.Config.AppVersion
        fullResultsJSON, _ := json.Marshal(results)

        basicRecordsJSON := getJSONFromResults(results, "basic_records", "")
        authRecordsJSON := getJSONFromResults(results, "authoritative_records", "")

        spfStatus := getStringFromResults(results, "spf_analysis", "status")
        dmarcStatus := getStringFromResults(results, "dmarc_analysis", "status")
        dmarcPolicy := getStringFromResults(results, "dmarc_analysis", "policy")
        dkimStatus := getStringFromResults(results, "dkim_analysis", "status")
        registrarName := getStringFromResults(results, "registrar_info", "registrar")
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

        var scanSource, scanIP *string
        if scanClass.IsScan {
                scanSource = &scanClass.Source
        }
        if scanClass.IP != "" {
                scanIP = &scanClass.IP
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
                Private:              private,
                HasUserSelectors:     hasUserSelectors,
                ScanFlag:             scanClass.IsScan,
                ScanSource:           scanSource,
                ScanIP:               scanIP,
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
