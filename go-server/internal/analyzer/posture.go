// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "fmt"
        "strings"
)

const (
        riskLow      = "Low Risk"
        riskMedium   = "Medium Risk"
        riskHigh     = "High Risk"
        riskCritical = "Critical Risk"

        iconShieldAlt           = "shield-alt"
        iconExclamationTriangle = "exclamation-triangle"

        protocolMTASTS = "MTA-STS"
        protocolTLSRPT = "TLS-RPT"
)

type protocolState struct {
        spfOK              bool
        spfWarning         bool
        spfMissing         bool
        spfHardFail        bool
        spfDangerous       bool
        spfNeutral         bool
        spfLookupExceeded  bool
        spfLookupCount     int
        dmarcOK            bool
        dmarcWarning       bool
        dmarcMissing       bool
        dmarcPolicy        string
        dmarcPct           int
        dmarcHasRua        bool
        dkimOK             bool
        dkimProvider       bool
        dkimPartial        bool
        dkimWeakKeys       bool
        dkimThirdPartyOnly bool
        caaOK              bool
        mtaStsOK           bool
        tlsrptOK           bool
        bimiOK             bool
        daneOK             bool
        dnssecOK           bool
        dnssecBroken       bool
        primaryProvider    string
        isNoMailDomain     bool
}

type postureAccumulator struct {
        issues          []string
        recommendations []string
        monitoring      []string
        configured      []string
        absent          []string
}

type gradeInput struct {
        corePresent           bool
        dmarcFullEnforcing    bool
        dmarcPartialEnforcing bool
        dmarcStrict           bool
        hasCAA                bool
        hasSPF                bool
        hasDMARC              bool
        hasDKIM               bool
        dkimInconclusive      bool
        isNoMail              bool
        monitoring            []string
        configured            []string
        absent                []string
}

func evaluateSPFState(spf map[string]any) (spfOK, spfWarning, spfMissing, spfHardFail, spfDangerous, spfNeutral, spfLookupExceeded bool, spfLookupCount int) {
        if isMissingRecord(spf) {
                spfMissing = true
                return
        }

        status, _ := spf["status"].(string)
        switch status {
        case "success":
                spfOK = true
        case "warning":
                spfWarning = true
                spfOK = true
        default:
                spfMissing = true
        }

        mechanism, _ := spf["mechanism"].(string)
        mechanism = strings.TrimSpace(mechanism)
        switch mechanism {
        case "-all":
                spfHardFail = true
        case "+all":
                spfDangerous = true
        case "?all":
                spfNeutral = true
        }

        spfLookupCount = extractIntField(spf, "lookup_count")
        if spfLookupCount > 10 {
                spfLookupExceeded = true
        }
        return
}

func evaluateDMARCState(dmarc map[string]any) (dmarcOK, dmarcWarning, dmarcMissing bool, dmarcPolicy string, dmarcPct int, dmarcHasRua bool) {
        if isMissingRecord(dmarc) {
                dmarcMissing = true
                return
        }

        status, _ := dmarc["status"].(string)
        switch status {
        case "success":
                dmarcOK = true
        case "warning":
                dmarcWarning = true
                dmarcOK = true
        default:
                dmarcMissing = true
        }

        dmarcPolicy, _ = dmarc["policy"].(string)
        dmarcPct = extractIntFieldDefault(dmarc, "pct", 100)
        if rua, ok := dmarc["rua"].(string); ok && rua != "" {
                dmarcHasRua = true
        }
        return
}

func evaluateDKIMState(dkim map[string]any) (dkimOK, dkimProvider, dkimPartial, dkimWeakKeys, dkimThirdPartyOnly bool, primaryProvider string) {
        if isMissingRecord(dkim) {
                return
        }

        status, _ := dkim["status"].(string)
        switch status {
        case "success":
                dkimOK = true
        case "warning":
                dkimOK = true
        }

        if pp, ok := dkim["primary_provider"].(string); ok && pp != "" {
                primaryProvider = pp
                dkimProvider = true
        }

        dkimWeakKeys, dkimThirdPartyOnly = evaluateDKIMIssues(dkim)

        recordsFound := extractIntField(dkim, "records_found")
        if recordsFound > 0 && !dkimOK {
                dkimPartial = true
        }
        return
}

func evaluateSimpleProtocolState(analysis map[string]any, successField string) bool {
        if isMissingRecord(analysis) {
                return false
        }
        status, _ := analysis[successField].(string)
        return status == "success"
}

func evaluateProtocolStates(results map[string]any) protocolState {
        ps := protocolState{}

        spf, _ := results["spf_analysis"].(map[string]any)
        dmarc, _ := results["dmarc_analysis"].(map[string]any)
        dkim, _ := results["dkim_analysis"].(map[string]any)
        mtaSts, _ := results["mta_sts_analysis"].(map[string]any)
        tlsrpt, _ := results["tlsrpt_analysis"].(map[string]any)
        bimi, _ := results["bimi_analysis"].(map[string]any)
        dane, _ := results["dane_analysis"].(map[string]any)
        caa, _ := results["caa_analysis"].(map[string]any)
        dnssec, _ := results["dnssec_analysis"].(map[string]any)

        if nullMX, ok := results["has_null_mx"].(bool); ok {
                ps.isNoMailDomain = nullMX
        }
        if noMail, ok := results["is_no_mail_domain"].(bool); ok && noMail {
                ps.isNoMailDomain = true
        }

        ps.spfOK, ps.spfWarning, ps.spfMissing, ps.spfHardFail, ps.spfDangerous, ps.spfNeutral, ps.spfLookupExceeded, ps.spfLookupCount = evaluateSPFState(spf)
        ps.dmarcOK, ps.dmarcWarning, ps.dmarcMissing, ps.dmarcPolicy, ps.dmarcPct, ps.dmarcHasRua = evaluateDMARCState(dmarc)
        ps.dkimOK, ps.dkimProvider, ps.dkimPartial, ps.dkimWeakKeys, ps.dkimThirdPartyOnly, ps.primaryProvider = evaluateDKIMState(dkim)

        ps.caaOK = evaluateSimpleProtocolState(caa, "status")
        ps.mtaStsOK = evaluateSimpleProtocolState(mtaSts, "status")
        ps.tlsrptOK = evaluateSimpleProtocolState(tlsrpt, "status")
        ps.bimiOK = evaluateSimpleProtocolState(bimi, "status")

        if !isMissingRecord(dane) {
                if hasDane, ok := dane["has_dane"].(bool); ok && hasDane {
                        ps.daneOK = true
                }
        }

        if !isMissingRecord(dnssec) {
                status, _ := dnssec["status"].(string)
                switch status {
                case "success":
                        ps.dnssecOK = true
                case "error":
                        ps.dnssecBroken = true
                }
        }

        return ps
}

func isMissingRecord(m map[string]any) bool {
        if m == nil {
                return true
        }
        status, _ := m["status"].(string)
        return status == "error" || status == "missing" || status == "n/a"
}

func hasNonEmptyString(m map[string]any, key string) bool {
        if m == nil {
                return false
        }
        s, ok := m[key].(string)
        return ok && s != ""
}

func extractIntField(m map[string]any, key string) int {
        if m == nil {
                return 0
        }
        v, ok := m[key]
        if !ok {
                return 0
        }
        switch n := v.(type) {
        case int:
                return n
        case int64:
                return int(n)
        case float64:
                return int(n)
        case float32:
                return int(n)
        }
        return 0
}

func extractIntFieldDefault(m map[string]any, key string, defaultVal int) int {
        if m == nil {
                return defaultVal
        }
        v, ok := m[key]
        if !ok {
                return defaultVal
        }
        switch n := v.(type) {
        case int:
                return n
        case int64:
                return int(n)
        case float64:
                return int(n)
        case float32:
                return int(n)
        }
        return defaultVal
}

func evaluateDKIMIssues(dkim map[string]any) (weakKeys bool, thirdPartyOnly bool) {
        if dkim == nil {
                return false, false
        }

        if wk, ok := dkim["weak_keys"].(bool); ok && wk {
                weakKeys = true
        }
        if tpo, ok := dkim["third_party_only"].(bool); ok && tpo {
                thirdPartyOnly = true
        }

        if issues, ok := dkim["issues"].([]any); ok {
                for _, issue := range issues {
                        if s, ok := issue.(string); ok {
                                lower := strings.ToLower(s)
                                if strings.Contains(lower, "weak") || strings.Contains(lower, "1024") {
                                        weakKeys = true
                                }
                                if strings.Contains(lower, "third-party") || strings.Contains(lower, "third party") {
                                        thirdPartyOnly = true
                                }
                        }
                }
        }

        return weakKeys, thirdPartyOnly
}

func classifySPF(ps protocolState, acc *postureAccumulator) {
        if ps.spfMissing {
                acc.issues = append(acc.issues, "No SPF record found — domain is vulnerable to email spoofing")
                acc.recommendations = append(acc.recommendations, "Publish an SPF record to authorize legitimate mail senders")
                acc.absent = append(acc.absent, "SPF")
                return
        }

        if ps.spfDangerous {
                acc.issues = append(acc.issues, "SPF record uses +all — allows any server to send mail as this domain")
                acc.recommendations = append(acc.recommendations, "Change SPF mechanism from +all to ~all or -all")
                acc.configured = append(acc.configured, "SPF")
                return
        }

        if ps.spfLookupExceeded {
                acc.issues = append(acc.issues, fmt.Sprintf("SPF record exceeds 10-lookup limit (%d lookups)", ps.spfLookupCount))
                acc.recommendations = append(acc.recommendations, "Reduce SPF lookup count to 10 or fewer using IP-based mechanisms")
        }

        if ps.spfNeutral {
                acc.recommendations = append(acc.recommendations, "SPF uses ?all (neutral) — consider ~all or -all for stronger policy")
        }

        if ps.spfWarning && !ps.spfHardFail {
                acc.monitoring = append(acc.monitoring, "SPF configured with soft fail (~all) — consider upgrading to hard fail (-all)")
        }

        if ps.spfHardFail {
                acc.configured = append(acc.configured, "SPF (hard fail)")
        } else if ps.spfOK {
                acc.configured = append(acc.configured, "SPF")
        }
}

func classifyDMARC(ps protocolState, acc *postureAccumulator) {
        if ps.dmarcMissing {
                acc.issues = append(acc.issues, "No DMARC record found — domain has no policy against email spoofing")
                acc.recommendations = append(acc.recommendations, "Publish a DMARC record starting with p=none and rua reporting")
                acc.absent = append(acc.absent, "DMARC")
                return
        }

        if ps.dmarcOK && !ps.dmarcWarning {
                classifyDMARCSuccess(ps, acc)
        } else if ps.dmarcWarning {
                classifyDMARCWarning(ps, acc)
        }
}

func classifyDMARCSuccess(ps protocolState, acc *postureAccumulator) {
        switch ps.dmarcPolicy {
        case "reject":
                acc.configured = append(acc.configured, "DMARC (reject)")
        case "quarantine":
                if ps.dmarcPct >= 100 {
                        acc.configured = append(acc.configured, "DMARC (quarantine, 100%)")
                } else {
                        acc.configured = append(acc.configured, fmt.Sprintf("DMARC (quarantine, %d%%)", ps.dmarcPct))
                        acc.monitoring = append(acc.monitoring, fmt.Sprintf("DMARC quarantine policy only applies to %d%% of messages", ps.dmarcPct))
                        acc.recommendations = append(acc.recommendations, "Increase DMARC pct to 100 for full enforcement")
                }
        case "none":
                acc.configured = append(acc.configured, "DMARC (monitoring only)")
                if ps.dmarcHasRua {
                        acc.monitoring = append(acc.monitoring, "DMARC policy is 'none' (monitoring mode) — receiving aggregate reports")
                        acc.recommendations = append(acc.recommendations, "Review DMARC aggregate reports and move to quarantine or reject policy")
                } else {
                        acc.issues = append(acc.issues, "DMARC policy is 'none' with no reporting — provides no protection or visibility")
                        acc.recommendations = append(acc.recommendations, "Add rua tag to receive DMARC aggregate reports before enforcing policy")
                }
        default:
                acc.configured = append(acc.configured, "DMARC")
        }

        if !ps.dmarcHasRua && ps.dmarcPolicy != "none" {
                acc.recommendations = append(acc.recommendations, "Add DMARC aggregate reporting (rua) for visibility into email authentication")
        }
}

func classifyDMARCWarning(ps protocolState, acc *postureAccumulator) {
        acc.configured = append(acc.configured, "DMARC (with warnings)")
        acc.monitoring = append(acc.monitoring, "DMARC record has configuration warnings — review recommended")

        if ps.dmarcPolicy == "none" {
                acc.recommendations = append(acc.recommendations, "Move DMARC policy from 'none' to 'quarantine' or 'reject'")
        }
        if !ps.dmarcHasRua {
                acc.recommendations = append(acc.recommendations, "Enable DMARC aggregate reporting (rua) for authentication visibility")
        }
}

func classifyDKIMPosture(ds DKIMState, primaryProvider string, acc *postureAccumulator) {
        switch ds {
        case DKIMSuccess:
                acc.configured = append(acc.configured, "DKIM")
        case DKIMProviderInferred:
                acc.configured = append(acc.configured, fmt.Sprintf("DKIM (inferred via %s)", primaryProvider))
                acc.monitoring = append(acc.monitoring, "DKIM signing inferred from provider — could not directly verify selector")
        case DKIMThirdPartyOnly:
                acc.configured = append(acc.configured, "DKIM (third-party only)")
                acc.recommendations = append(acc.recommendations, "Configure DKIM signing for your primary domain selector in addition to third-party services")
        case DKIMWeakKeysOnly:
                acc.configured = append(acc.configured, "DKIM (weak keys)")
                acc.issues = append(acc.issues, "DKIM keys are weak (1024-bit or less) — vulnerable to brute-force attacks")
                acc.recommendations = append(acc.recommendations, "Upgrade DKIM keys to 2048-bit RSA or Ed25519")
        case DKIMNoMailDomain:
                acc.configured = append(acc.configured, "DKIM (not applicable — no-mail domain)")
        case DKIMInconclusive:
                acc.monitoring = append(acc.monitoring, "DKIM status is inconclusive — selector could not be verified")
                acc.absent = append(acc.absent, "DKIM (inconclusive)")
        case DKIMAbsent:
                acc.absent = append(acc.absent, "DKIM")
                acc.recommendations = append(acc.recommendations, "Configure DKIM signing to cryptographically authenticate outgoing email")
        }
}

func classifySimpleProtocols(ps protocolState, acc *postureAccumulator) {
        if ps.mtaStsOK {
                acc.configured = append(acc.configured, protocolMTASTS)
        } else {
                acc.absent = append(acc.absent, protocolMTASTS)
        }

        if ps.tlsrptOK {
                acc.configured = append(acc.configured, protocolTLSRPT)
        } else {
                acc.absent = append(acc.absent, protocolTLSRPT)
        }

        if ps.bimiOK {
                acc.configured = append(acc.configured, "BIMI")
        } else {
                acc.absent = append(acc.absent, "BIMI")
        }

        if ps.daneOK {
                acc.configured = append(acc.configured, "DANE")
        } else {
                acc.absent = append(acc.absent, "DANE")
        }

        if ps.dnssecOK {
                acc.configured = append(acc.configured, "DNSSEC")
        } else if ps.dnssecBroken {
                acc.issues = append(acc.issues, "DNSSEC validation is failing — DNS responses cannot be trusted")
                acc.recommendations = append(acc.recommendations, "Fix DNSSEC configuration or remove broken DS records")
        } else {
                acc.absent = append(acc.absent, "DNSSEC")
        }

        if ps.caaOK {
                acc.configured = append(acc.configured, "CAA")
        } else {
                acc.absent = append(acc.absent, "CAA")
        }
}

func classifyDanglingDNS(results map[string]any, acc *postureAccumulator) {
        dangling, ok := results["dangling_dns"].(map[string]any)
        if !ok {
                return
        }
        count := extractIntField(dangling, "dangling_count")
        if count > 0 {
                acc.issues = append(acc.issues, fmt.Sprintf("%d dangling DNS record(s) detected — potential subdomain takeover risk", count))
                acc.recommendations = append(acc.recommendations, "Review and remove dangling DNS records pointing to deprovisioned services")
        }
}

func classifyDMARCReportAuth(results map[string]any, acc *postureAccumulator) {
        reportAuth, ok := results["dmarc_report_auth"].(map[string]any)
        if !ok {
                return
        }

        issues, _ := reportAuth["issues"].([]string)
        for _, issue := range issues {
                acc.monitoring = append(acc.monitoring, issue)
        }

        externalDomains := extractExternalDomainMaps(reportAuth["external_domains"])
        for _, ed := range externalDomains {
                if authorized, ok := ed["authorized"].(bool); ok && !authorized {
                        domain, _ := ed["domain"].(string)
                        if domain != "" {
                                acc.recommendations = append(acc.recommendations, fmt.Sprintf("Authorize external DMARC reporting for %s or remove from rua/ruf", domain))
                        }
                }
        }
}

func extractExternalDomainMaps(raw any) []map[string]any {
        if raw == nil {
                return nil
        }
        if arr, ok := raw.([]map[string]any); ok {
                return arr
        }
        if arr, ok := raw.([]any); ok {
                result := make([]map[string]any, 0, len(arr))
                for _, item := range arr {
                        if m, ok := item.(map[string]any); ok {
                                result = append(result, m)
                        }
                }
                return result
        }
        return nil
}

func evaluateDeliberateMonitoring(ps protocolState, configuredCount int) (bool, string) {
        if ps.dmarcOK && ps.dmarcPolicy == "none" && ps.dmarcHasRua && ps.spfOK && configuredCount >= 3 {
                return true, "Domain appears to be in deliberate DMARC monitoring phase with aggregate reporting enabled"
        }
        return false, ""
}

func (a *Analyzer) CalculatePosture(results map[string]any) map[string]any {
        ps := evaluateProtocolStates(results)
        ds := classifyDKIMState(ps)

        acc := &postureAccumulator{
                issues:          []string{},
                recommendations: []string{},
                monitoring:      []string{},
                configured:      []string{},
                absent:          []string{},
        }

        classifySPF(ps, acc)
        classifyDMARC(ps, acc)
        classifyDKIMPosture(ds, ps.primaryProvider, acc)
        classifySimpleProtocols(ps, acc)
        classifyDanglingDNS(results, acc)
        classifyDMARCReportAuth(results, acc)

        hasSPF := !ps.spfMissing
        hasDMARC := !ps.dmarcMissing
        hasDKIM := ds.IsPresent()

        gi := gradeInput{
                hasSPF:     hasSPF,
                hasDMARC:   hasDMARC,
                hasDKIM:    hasDKIM,
                monitoring: acc.monitoring,
                configured: acc.configured,
                absent:     acc.absent,
        }

        state, icon, color, message := determineGrade(ps, ds, gi)

        score := computeInternalScore(ps, ds)

        verdicts := buildVerdicts(ps, ds, hasSPF, hasDMARC, hasDKIM)

        deliberate, deliberateNote := evaluateDeliberateMonitoring(ps, len(acc.configured))

        var criticalIssues []string
        if ps.dnssecBroken {
                criticalIssues = append(criticalIssues, "DNSSEC validation is failing")
        }
        if ps.spfMissing && ps.dmarcMissing {
                criticalIssues = append(criticalIssues, "No SPF and no DMARC — domain is completely unprotected against email spoofing")
        }

        grade := state
        label := state

        return map[string]any{
                "score":                      score,
                "grade":                      grade,
                "label":                      label,
                "state":                      state,
                "icon":                       icon,
                "color":                      color,
                "message":                    message,
                "issues":                     acc.issues,
                "critical_issues":            criticalIssues,
                "recommendations":            acc.recommendations,
                "monitoring":                 acc.monitoring,
                "configured":                 acc.configured,
                "absent":                     acc.absent,
                "deliberate_monitoring":      deliberate,
                "deliberate_monitoring_note": deliberateNote,
                "verdicts":                   verdicts,
        }
}

func determineGrade(ps protocolState, ds DKIMState, gi gradeInput) (state, icon, color, message string) {
        gi.corePresent = gi.hasSPF && gi.hasDMARC
        gi.dmarcFullEnforcing = ps.dmarcPolicy == "reject" || (ps.dmarcPolicy == "quarantine" && ps.dmarcPct >= 100)
        gi.dmarcPartialEnforcing = ps.dmarcPolicy == "quarantine" && ps.dmarcPct < 100
        gi.dmarcStrict = ps.dmarcPolicy == "reject"
        gi.hasCAA = ps.caaOK
        gi.dkimInconclusive = ds == DKIMInconclusive
        gi.isNoMail = ps.isNoMailDomain

        state, icon, color, message = classifyGrade(ps, gi)
        return
}

func classifyGrade(ps protocolState, gi gradeInput) (string, string, string, string) {
        if ps.dnssecBroken {
                return riskCritical, iconExclamationTriangle, "danger", "DNSSEC validation is broken — DNS responses may be tampered with"
        }

        if gi.isNoMail {
                return classifyNoMailGrade(ps, gi)
        }

        return classifyMailGrade(ps, gi)
}

func classifyMailGrade(ps protocolState, gi gradeInput) (string, string, string, string) {
        if !gi.hasSPF && !gi.hasDMARC {
                return riskCritical, iconExclamationTriangle, "danger", "No SPF or DMARC records — domain is unprotected against email spoofing"
        }

        if !gi.hasSPF || !gi.hasDMARC {
                return classifyMailPartial(gi)
        }

        return classifyMailCorePresent(ps, gi)
}

func classifyMailCorePresent(ps protocolState, gi gradeInput) (string, string, string, string) {
        if gi.dmarcFullEnforcing && gi.hasDKIM {
                state := riskLow
                msg := buildDescriptiveMessage(ps, gi.configured, gi.absent, gi.monitoring)
                return applyMonitoringSuffix(state, gi.monitoring), iconShieldAlt, "success", msg
        }

        if gi.dmarcFullEnforcing && !gi.hasDKIM {
                state := riskMedium
                msg := "SPF and DMARC enforcing but DKIM not confirmed"
                return applyMonitoringSuffix(state, gi.monitoring), iconShieldAlt, "info", msg
        }

        if gi.dmarcPartialEnforcing {
                state := riskMedium
                msg := fmt.Sprintf("DMARC quarantine at %d%% — not fully enforcing", ps.dmarcPct)
                return applyMonitoringSuffix(state, gi.monitoring), iconShieldAlt, "info", msg
        }

        if ps.dmarcPolicy == "none" {
                if ps.dmarcHasRua {
                        state := riskMedium
                        msg := "DMARC is in monitoring mode (p=none) with reporting enabled"
                        return applyMonitoringSuffix(state, gi.monitoring), iconShieldAlt, "info", msg
                }
                return riskHigh, iconExclamationTriangle, "warning", "DMARC policy is 'none' with no reporting — no protection or visibility"
        }

        state := riskMedium
        msg := buildDescriptiveMessage(ps, gi.configured, gi.absent, gi.monitoring)
        return applyMonitoringSuffix(state, gi.monitoring), iconShieldAlt, "info", msg
}

func classifyMailPartial(gi gradeInput) (string, string, string, string) {
        if gi.hasSPF && !gi.hasDMARC {
                return riskHigh, iconExclamationTriangle, "warning", "SPF present but no DMARC — spoofed emails may still be delivered"
        }
        return riskHigh, iconExclamationTriangle, "warning", "DMARC present but no SPF — mail authentication is incomplete"
}

func classifyNoMailGrade(ps protocolState, gi gradeInput) (string, string, string, string) {
        if gi.hasSPF && gi.hasDMARC {
                if gi.dmarcStrict || gi.dmarcFullEnforcing {
                        return riskLow, iconShieldAlt, "success", "No-mail domain properly configured with SPF and DMARC reject policy"
                }
                return riskMedium, iconShieldAlt, "info", "No-mail domain has SPF and DMARC but policy is not reject"
        }
        if gi.hasSPF || gi.hasDMARC {
                return riskHigh, iconExclamationTriangle, "warning", "No-mail domain is missing SPF or DMARC"
        }
        return riskCritical, iconExclamationTriangle, "danger", "No-mail domain has no email authentication records"
}

func applyMonitoringSuffix(state string, monitoring []string) string {
        if len(monitoring) > 0 {
                return state
        }
        return state
}

func buildDescriptiveMessage(ps protocolState, configured, absent, monitoring []string) string {
        parts := []string{}

        if len(configured) > 0 {
                parts = append(parts, fmt.Sprintf("%d protocols configured", len(configured)))
        }
        if len(absent) > 0 {
                parts = append(parts, fmt.Sprintf("%d not configured", len(absent)))
        }
        if len(monitoring) > 0 {
                parts = append(parts, fmt.Sprintf("%d need attention", len(monitoring)))
        }

        if len(parts) == 0 {
                return "Email security posture evaluated"
        }

        return strings.Join(parts, ", ")
}

func buildVerdicts(ps protocolState, ds DKIMState, hasSPF, hasDMARC, hasDKIM bool) map[string]any {
        verdicts := map[string]any{}

        buildEmailVerdict(ps, ds, hasSPF, hasDMARC, hasDKIM, verdicts)
        buildBrandVerdict(ps, verdicts)
        buildDNSVerdict(ps, verdicts)

        if ps.caaOK {
                verdicts["certificate_control"] = map[string]any{
                        "label": "Configured",
                        "color": "success",
                        "icon":  iconShieldAlt,
                }
        } else {
                verdicts["certificate_control"] = map[string]any{
                        "label": "Not Configured",
                        "color": "secondary",
                        "icon":  iconShieldAlt,
                }
        }

        verdicts["email_answer"] = buildEmailAnswer(ps, hasSPF, hasDMARC)

        return verdicts
}

func buildEmailAnswer(ps protocolState, hasSPF, hasDMARC bool) string {
        if ps.isNoMailDomain {
                return "No — null MX indicates no-mail domain"
        }
        if !hasSPF && !hasDMARC {
                return "Yes — no SPF or DMARC protection"
        }
        if hasSPF && hasDMARC && ps.dmarcPolicy == "reject" {
                return "No — SPF and DMARC reject policy enforced"
        }
        if hasSPF && hasDMARC && ps.dmarcPolicy == "quarantine" && ps.dmarcPct >= 100 {
                return "Unlikely — SPF and DMARC quarantine policy enforced"
        }
        if hasSPF && hasDMARC && ps.dmarcPolicy == "quarantine" {
                return "Partially — DMARC quarantine at limited percentage"
        }
        if hasSPF && hasDMARC && ps.dmarcPolicy == "none" {
                return "Yes — DMARC is monitor-only (p=none)"
        }
        if hasSPF && !hasDMARC {
                return "Likely — SPF alone cannot prevent spoofing"
        }
        if !hasSPF && hasDMARC {
                return "Partially — DMARC present but no SPF"
        }
        return "Uncertain — incomplete configuration"
}

func buildEmailVerdict(ps protocolState, ds DKIMState, hasSPF, hasDMARC, hasDKIM bool, verdicts map[string]any) {
        if hasSPF && hasDMARC && (ps.dmarcPolicy == "reject" || (ps.dmarcPolicy == "quarantine" && ps.dmarcPct >= 100)) {
                buildEnforcingEmailVerdict(ps, ds, verdicts)
                return
        }

        if hasSPF && !hasDMARC {
                verdicts["email_spoofing"] = map[string]any{
                        "label": "Basic",
                        "color": "warning",
                        "icon":  iconShieldAlt,
                }
                return
        }

        if !hasSPF && !hasDMARC {
                verdicts["email_spoofing"] = map[string]any{
                        "label": "Exposed",
                        "color": "danger",
                        "icon":  iconExclamationTriangle,
                }
                return
        }

        if hasSPF && hasDMARC {
                verdicts["email_spoofing"] = map[string]any{
                        "label": "Basic",
                        "color": "warning",
                        "icon":  iconShieldAlt,
                }
                return
        }

        verdicts["email_spoofing"] = map[string]any{
                "label": "Exposed",
                "color": "danger",
                "icon":  iconExclamationTriangle,
        }
}

func buildEnforcingEmailVerdict(ps protocolState, ds DKIMState, verdicts map[string]any) {
        verdicts["email_spoofing"] = map[string]any{
                "label": "Protected",
                "color": "success",
                "icon":  iconShieldAlt,
        }
}

func buildBrandVerdict(ps protocolState, verdicts map[string]any) {
        if ps.dmarcMissing {
                verdicts["brand_impersonation"] = map[string]any{
                        "label": "Exposed",
                        "color": "danger",
                        "icon":  iconExclamationTriangle,
                }
                return
        }

        if ps.dmarcPolicy == "reject" {
                verdicts["brand_impersonation"] = map[string]any{
                        "label": "Protected",
                        "color": "success",
                        "icon":  iconShieldAlt,
                }
                return
        }

        verdicts["brand_impersonation"] = map[string]any{
                "label": "Basic",
                "color": "warning",
                "icon":  iconShieldAlt,
        }
}

func buildDNSVerdict(ps protocolState, verdicts map[string]any) {
        if ps.dnssecOK {
                verdicts["dns_tampering"] = map[string]any{
                        "label": "Protected",
                        "color": "success",
                        "icon":  iconShieldAlt,
                }
        } else if ps.dnssecBroken {
                verdicts["dns_tampering"] = map[string]any{
                        "label": "Exposed",
                        "color": "danger",
                        "icon":  iconExclamationTriangle,
                }
        } else {
                verdicts["dns_tampering"] = map[string]any{
                        "label": "Not Configured",
                        "color": "secondary",
                        "icon":  iconShieldAlt,
                }
        }
}

func computeInternalScore(ps protocolState, ds DKIMState) int {
        score := 0
        score += computeSPFScore(ps)
        score += computeDMARCScore(ps)
        score += computeDKIMScore(ds)
        score += computeAuxScore(ps)
        if score > 100 {
                score = 100
        }
        return score
}

func computeSPFScore(ps protocolState) int {
        if ps.spfMissing {
                return 0
        }
        if ps.spfDangerous {
                return 5
        }
        if ps.spfHardFail {
                return 20
        }
        return 15
}

func computeDMARCScore(ps protocolState) int {
        if ps.dmarcMissing {
                return 0
        }
        switch ps.dmarcPolicy {
        case "reject":
                return 30
        case "quarantine":
                if ps.dmarcPct >= 100 {
                        return 25
                }
                return 20
        case "none":
                if ps.dmarcHasRua {
                        return 10
                }
                return 5
        }
        return 10
}

func computeDKIMScore(ds DKIMState) int {
        switch ds {
        case DKIMSuccess:
                return 15
        case DKIMProviderInferred:
                return 12
        case DKIMThirdPartyOnly:
                return 8
        case DKIMWeakKeysOnly:
                return 5
        case DKIMNoMailDomain:
                return 15
        }
        return 0
}

func computeAuxScore(ps protocolState) int {
        score := 0
        if ps.dnssecOK {
                score += 10
        }
        if ps.daneOK {
                score += 5
        }
        if ps.mtaStsOK {
                score += 5
        }
        if ps.tlsrptOK {
                score += 5
        }
        if ps.caaOK {
                score += 5
        }
        if ps.bimiOK {
                score += 5
        }
        return score
}
