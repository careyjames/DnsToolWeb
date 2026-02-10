package analyzer

import (
        "fmt"
        "strings"
)

var knownDKIMProviders = map[string]bool{
        "Google Workspace":  true,
        "Microsoft 365":     true,
        "Amazon SES":        true,
        "Proofpoint":        true,
        "Mimecast":          true,
        "Barracuda":         true,
        "Zoho Mail":         true,
        "Fastmail":          true,
        "ProtonMail":        true,
        "Cloudflare Email":  true,
        "Hornetsecurity":    true,
}

func isKnownDKIMProvider(provider interface{}) bool {
        s, ok := provider.(string)
        if !ok || s == "" || s == "Unknown" {
                return false
        }
        return knownDKIMProviders[s]
}

type protocolState struct {
        spfOK           bool
        spfWarning      bool
        spfHardFail     bool
        dmarcOK         bool
        dmarcWarning    bool
        dmarcPolicy     string
        dmarcPct        int
        dmarcHasRua     bool
        dkimOK          bool
        dkimProvider    bool
        dkimPartial     bool
        caaOK           bool
        mtaStsOK        bool
        tlsrptOK        bool
        bimiOK          bool
        daneOK          bool
        dnssecOK        bool
        primaryProvider string
}

func evaluateProtocolStates(results map[string]any) protocolState {
        spf := getMapResult(results, "spf_analysis")
        dmarc := getMapResult(results, "dmarc_analysis")
        dkim := getMapResult(results, "dkim_analysis")
        mtaSts := getMapResult(results, "mta_sts_analysis")
        tlsrpt := getMapResult(results, "tlsrpt_analysis")
        bimi := getMapResult(results, "bimi_analysis")
        dane := getMapResult(results, "dane_analysis")
        caa := getMapResult(results, "caa_analysis")
        dnssec := getMapResult(results, "dnssec_analysis")

        dmarcPolicy, _ := dmarc["policy"].(string)
        primaryProvider, _ := dkim["primary_provider"].(string)

        allMech, _ := spf["all_mechanism"].(string)

        dmarcPct := 100
        if p, ok := dmarc["pct"].(int); ok {
                dmarcPct = p
        }
        dmarcHasRua := false
        if rua, ok := dmarc["rua"].(string); ok && rua != "" {
                dmarcHasRua = true
        }

        return protocolState{
                spfOK:           spf["status"] == "success",
                spfWarning:      spf["status"] == "warning",
                spfHardFail:     allMech == "-all",
                dmarcOK:         dmarc["status"] == "success",
                dmarcWarning:    dmarc["status"] == "warning",
                dmarcPolicy:     dmarcPolicy,
                dmarcPct:        dmarcPct,
                dmarcHasRua:     dmarcHasRua,
                dkimOK:          dkim["status"] == "success",
                dkimProvider:    dkim["status"] == "info" && isKnownDKIMProvider(primaryProvider),
                dkimPartial:     dkim["status"] == "info" && !isKnownDKIMProvider(primaryProvider),
                caaOK:           caa["status"] == "success",
                mtaStsOK:        mtaSts["status"] == "success",
                tlsrptOK:        tlsrpt["status"] == "success",
                bimiOK:          bimi["status"] == "success",
                daneOK:          dane["has_dane"] == true,
                dnssecOK:        dnssec["status"] == "success",
                primaryProvider: primaryProvider,
        }
}

func (a *Analyzer) CalculatePosture(results map[string]any) map[string]any {
        ps := evaluateProtocolStates(results)

        var issues []string
        var recommendations []string
        var monitoring []string
        var configured []string
        var absent []string

        hasSPF := ps.spfOK || ps.spfWarning
        hasDMARC := ps.dmarcOK || ps.dmarcWarning
        hasDKIM := ps.dkimOK || ps.dkimProvider

        if ps.spfOK {
                configured = append(configured, "SPF")
        } else if ps.spfWarning {
                configured = append(configured, "SPF")
                issues = append(issues, "SPF needs attention")
        } else {
                absent = append(absent, "SPF")
                issues = append(issues, "No SPF record")
        }

        if ps.dmarcOK {
                if ps.dmarcPolicy == "reject" {
                        configured = append(configured, "DMARC (reject)")
                } else if ps.dmarcPolicy == "quarantine" {
                        configured = append(configured, "DMARC (quarantine)")
                } else {
                        configured = append(configured, "DMARC")
                }
        } else if ps.dmarcWarning {
                if ps.dmarcPolicy == "none" {
                        monitoring = append(monitoring, "DMARC in monitoring mode (p=none)")
                } else if ps.dmarcPct < 100 {
                        configured = append(configured, fmt.Sprintf("DMARC (%s, pct=%d%%)", ps.dmarcPolicy, ps.dmarcPct))
                        issues = append(issues, fmt.Sprintf("DMARC enforcement partial — only %d%% of mail subject to policy", ps.dmarcPct))
                } else {
                        issues = append(issues, "DMARC needs strengthening")
                }
        } else {
                absent = append(absent, "DMARC")
                issues = append(issues, "No DMARC record")
        }

        if hasDMARC && !ps.dmarcHasRua {
                recommendations = append(recommendations, "No DMARC aggregate reporting (rua) configured — unable to monitor authentication results")
        }

        if ps.dkimOK {
                configured = append(configured, "DKIM")
        } else if ps.dkimProvider {
                configured = append(configured, "DKIM (provider-verified)")
        } else if ps.dkimPartial {
                monitoring = append(monitoring, "DKIM (partial)")
        } else {
                absent = append(absent, "DKIM")
                issues = append(issues, "No DKIM found")
        }

        if ps.mtaStsOK {
                configured = append(configured, "MTA-STS")
        } else {
                absent = append(absent, "MTA-STS")
        }

        if ps.tlsrptOK {
                configured = append(configured, "TLS-RPT")
        } else {
                absent = append(absent, "TLS-RPT")
        }

        if ps.bimiOK {
                configured = append(configured, "BIMI")
        }

        if ps.daneOK {
                configured = append(configured, "DANE")
        }

        if ps.caaOK {
                configured = append(configured, "CAA")
        } else {
                absent = append(absent, "CAA")
                recommendations = append(recommendations, "No CAA records")
        }

        if ps.dnssecOK {
                configured = append(configured, "DNSSEC")
        } else {
                absent = append(absent, "DNSSEC")
        }

        state, icon, color, message := determineGrade(ps, hasSPF, hasDMARC, hasDKIM, monitoring, configured, absent)

        deliberateMonitoring := false
        deliberateMonitoringNote := ""
        if ps.dmarcPolicy == "none" {
                configuredCount := len(configured)
                hasReporting := ps.dmarcHasRua
                hasAdvancedControls := ps.dnssecOK || ps.daneOK || ps.mtaStsOK

                if configuredCount >= 3 && hasReporting {
                        deliberateMonitoring = true
                        deliberateMonitoringNote = "DMARC is in monitoring mode (p=none) with aggregate reporting active — this appears to be a deliberate deployment phase before enforcement"
                } else if configuredCount >= 3 && hasAdvancedControls {
                        deliberateMonitoring = true
                        deliberateMonitoringNote = "DMARC is in monitoring mode (p=none) with advanced security controls (DNSSEC/DANE/MTA-STS) deployed — this indicates sophisticated security management with deliberate monitoring"
                } else if configuredCount >= 3 {
                        deliberateMonitoring = true
                        deliberateMonitoringNote = "DMARC is in monitoring mode (p=none) — this appears intentional while gathering data before enforcement"
                }
        }

        score := computeInternalScore(ps)

        verdicts := buildVerdicts(ps, hasSPF, hasDMARC, hasDKIM)

        allIssues := append(issues, recommendations...)

        return map[string]any{
                "score":                      score,
                "grade":                      state,
                "label":                      message,
                "state":                      state,
                "icon":                       icon,
                "color":                      color,
                "message":                    message,
                "issues":                     allIssues,
                "critical_issues":            issues,
                "recommendations":            recommendations,
                "monitoring":                 monitoring,
                "configured":                 configured,
                "absent":                     absent,
                "deliberate_monitoring":      deliberateMonitoring,
                "deliberate_monitoring_note": deliberateMonitoringNote,
                "verdicts":                   verdicts,
        }
}

func determineGrade(ps protocolState, hasSPF, hasDMARC, hasDKIM bool, monitoring, configured, absent []string) (state, icon, color, message string) {
        corePresent := hasSPF && hasDMARC && hasDKIM
        dmarcFullEnforcing := (ps.dmarcPolicy == "reject" || ps.dmarcPolicy == "quarantine") && ps.dmarcPct == 100
        dmarcPartialEnforcing := (ps.dmarcPolicy == "reject" || ps.dmarcPolicy == "quarantine") && ps.dmarcPct < 100
        dmarcStrict := ps.dmarcPolicy == "reject" && ps.dmarcPct == 100
        hasCAA := ps.caaOK

        switch {
        case corePresent && dmarcStrict && hasCAA && ps.dnssecOK:
                state = "Informational"
                icon = "info-circle"
                color = "info"
                message = buildDescriptiveMessage(ps, configured, absent, monitoring)

        case corePresent && dmarcStrict && hasCAA:
                state = "Low"
                icon = "shield-alt"
                color = "success"
                message = buildDescriptiveMessage(ps, configured, absent, monitoring)

        case corePresent && dmarcFullEnforcing:
                state = "Low"
                icon = "shield-alt"
                color = "success"
                message = buildDescriptiveMessage(ps, configured, absent, monitoring)

        case corePresent && dmarcPartialEnforcing:
                state = "Medium"
                icon = "exclamation-triangle"
                color = "warning"
                message = fmt.Sprintf("Email authentication configured but DMARC enforcement is partial (pct=%d%%). Only %d%% of failing mail is subject to policy.", ps.dmarcPct, ps.dmarcPct)

        case corePresent && ps.dmarcPolicy == "none":
                state = "Medium"
                icon = "exclamation-triangle"
                color = "warning"
                message = "Email authentication configured but DMARC is in monitoring mode (p=none). Enforcement recommended after reviewing reports."

        case hasSPF && hasDMARC && !hasDKIM:
                state = "Medium"
                icon = "exclamation-triangle"
                color = "warning"
                message = "SPF and DMARC present but DKIM not verified. DKIM signing is required for full DMARC alignment."

        case hasSPF && !hasDMARC:
                state = "High"
                icon = "exclamation-triangle"
                color = "warning"
                message = "SPF configured but no DMARC policy. Without DMARC, SPF alone cannot prevent email spoofing."

        case !hasSPF && !hasDMARC && !hasDKIM:
                state = "Critical"
                icon = "times-circle"
                color = "danger"
                message = "No email authentication configured. This domain is fully vulnerable to email spoofing."

        default:
                state = "High"
                icon = "exclamation-triangle"
                color = "warning"
                message = "Partial email authentication. Critical security controls are missing."
        }

        if len(monitoring) > 0 && state != "Critical" && state != "High" {
                if !strings.Contains(state, "Monitoring") {
                        state += " Monitoring"
                }
        }

        return
}

func buildDescriptiveMessage(ps protocolState, configured, absent, monitoring []string) string {
        var parts []string

        if ps.dmarcPolicy == "reject" {
                parts = append(parts, "Email authentication with full DMARC enforcement")
        } else if ps.dmarcPolicy == "quarantine" {
                parts = append(parts, "Email authentication configured with DMARC quarantine policy")
        }

        var notConfigured []string
        for _, item := range absent {
                switch item {
                case "MTA-STS", "TLS-RPT", "DNSSEC", "BIMI":
                        notConfigured = append(notConfigured, item)
                }
        }

        if len(notConfigured) > 0 {
                parts = append(parts, fmt.Sprintf("%s not configured", strings.Join(notConfigured, ", ")))
        }

        if len(monitoring) > 0 {
                for _, m := range monitoring {
                        if strings.Contains(m, "DMARC") {
                                parts = append(parts, "DMARC in monitoring mode")
                        }
                }
        }

        if len(parts) == 0 {
                return "Comprehensive email and DNS security configured."
        }

        return strings.Join(parts, ". ") + "."
}

func buildVerdicts(ps protocolState, hasSPF, hasDMARC, hasDKIM bool) map[string]any {
        verdicts := make(map[string]any)

        if hasSPF && hasDMARC && (ps.dmarcPolicy == "reject" || ps.dmarcPolicy == "quarantine") && hasDKIM {
                verdicts["email"] = "DMARC policy is " + ps.dmarcPolicy + " — spoofed messages will be " +
                        map[string]string{"reject": "blocked", "quarantine": "flagged as spam"}[ps.dmarcPolicy] +
                        " by receiving servers."
                if hasDKIM {
                        verdicts["email"] = verdicts["email"].(string) + " DKIM keys verified" +
                                func() string {
                                        if ps.dkimProvider {
                                                return " (provider-verified for " + ps.primaryProvider + ")"
                                        }
                                        return " with strong cryptography"
                                }() + "."
                }
                verdicts["email_secure"] = ps.dmarcPolicy == "reject"
                if ps.dmarcPolicy == "reject" {
                        verdicts["email_answer"] = "No"
                } else {
                        verdicts["email_answer"] = "Mostly No"
                }
        } else if hasSPF && hasDMARC && ps.dmarcPolicy == "none" {
                verdicts["email"] = "Partial email authentication configured — some spoofed messages may be delivered. DMARC is in monitoring mode (p=none)."
                verdicts["email_secure"] = false
                verdicts["email_answer"] = "Partially"
        } else if hasSPF && !hasDMARC {
                verdicts["email"] = "SPF is configured but without DMARC, receiving servers may still accept spoofed messages."
                verdicts["email_secure"] = false
                verdicts["email_answer"] = "Yes"
        } else if !hasSPF && !hasDMARC {
                verdicts["email"] = "No email authentication — this domain can be impersonated by anyone."
                verdicts["email_secure"] = false
                verdicts["email_answer"] = "Yes"
        } else {
                verdicts["email"] = "Partial email authentication configured — some spoofed messages may be delivered."
                verdicts["email_secure"] = false
                verdicts["email_answer"] = "Partially"
        }

        if ps.bimiOK && ps.caaOK {
                verdicts["brand"] = "Attackers cannot easily spoof your logo or obtain fraudulent TLS certificates."
                verdicts["brand_secure"] = true
                verdicts["brand_answer"] = "No"
        } else if ps.caaOK {
                verdicts["brand"] = "Certificate issuance restricted via CAA. BIMI not configured for brand logo protection."
                verdicts["brand_secure"] = false
                verdicts["brand_answer"] = "Partially"
        } else if ps.bimiOK {
                verdicts["brand"] = "BIMI brand logo configured. CAA not configured — any CA can issue certificates."
                verdicts["brand_secure"] = false
                verdicts["brand_answer"] = "Partially"
        } else {
                verdicts["brand"] = "No brand protection configured. Any CA can issue certificates and no brand logo verification in place."
                verdicts["brand_secure"] = false
                verdicts["brand_answer"] = "Yes"
        }

        if ps.dnssecOK {
                verdicts["dns"] = "DNS responses are cryptographically signed and verified via DNSSEC."
                verdicts["dns_secure"] = true
                verdicts["domain_answer"] = "No"
        } else {
                verdicts["dns"] = "DNS responses are unsigned and could be spoofed. DNSSEC provides cryptographic verification."
                verdicts["dns_secure"] = false
                verdicts["domain_answer"] = "Yes"
        }

        return verdicts
}

func computeInternalScore(ps protocolState) int {
        score := 0
        if ps.spfOK {
                score += 20
        } else if ps.spfWarning {
                score += 10
        }
        if ps.dmarcOK {
                score += 25
                if ps.dmarcPolicy == "reject" {
                        score += 5
                } else if ps.dmarcPolicy == "quarantine" {
                        score += 3
                }
        } else if ps.dmarcWarning {
                score += 10
        }
        if ps.dkimOK {
                score += 20
        } else if ps.dkimProvider {
                score += 15
        } else if ps.dkimPartial {
                score += 5
        }
        if ps.mtaStsOK {
                score += 8
        }
        if ps.tlsrptOK {
                score += 4
        }
        if ps.bimiOK {
                score += 3
        }
        if ps.daneOK {
                score += 5
        }
        if ps.caaOK {
                score += 8
        }
        if ps.dnssecOK {
                score += 5
        }
        if score > 100 {
                score = 100
        }
        return score
}
