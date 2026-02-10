package analyzer

import (
	"fmt"
	"strings"
)

const (
	riskLow    = "Low Risk"
	riskMedium = "Medium Risk"
	riskHigh   = "High Risk"

	iconShieldAlt           = "shield-alt"
	iconExclamationTriangle = "exclamation-triangle"

	protocolMTASTS = "MTA-STS"
	protocolTLSRPT = "TLS-RPT"
)

var knownDKIMProviders = map[string]bool{
	"Google Workspace": true,
	"Microsoft 365":    true,
	"Amazon SES":       true,
	"Proofpoint":       true,
	"Mimecast":         true,
	"Barracuda":        true,
	"Zoho Mail":        true,
	"Fastmail":         true,
	"ProtonMail":       true,
	"Cloudflare Email": true,
	"Hornetsecurity":   true,
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

type postureAccumulator struct {
	issues          []string
	recommendations []string
	monitoring      []string
	configured      []string
	absent          []string
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

func classifySPF(ps protocolState, acc *postureAccumulator) {
	if ps.spfOK {
		acc.configured = append(acc.configured, "SPF")
		return
	}
	if ps.spfWarning {
		acc.configured = append(acc.configured, "SPF")
		acc.issues = append(acc.issues, "SPF needs attention")
		return
	}
	acc.absent = append(acc.absent, "SPF")
	acc.issues = append(acc.issues, "No SPF record")
}

func classifyDMARC(ps protocolState, acc *postureAccumulator) {
	if ps.dmarcOK {
		classifyDMARCSuccess(ps, acc)
		return
	}
	if ps.dmarcWarning {
		classifyDMARCWarning(ps, acc)
		return
	}
	acc.absent = append(acc.absent, "DMARC")
	acc.issues = append(acc.issues, "No DMARC record")
}

func classifyDMARCSuccess(ps protocolState, acc *postureAccumulator) {
	switch ps.dmarcPolicy {
	case "reject":
		acc.configured = append(acc.configured, "DMARC (reject)")
	case "quarantine":
		acc.configured = append(acc.configured, "DMARC (quarantine)")
	default:
		acc.configured = append(acc.configured, "DMARC")
	}
}

func classifyDMARCWarning(ps protocolState, acc *postureAccumulator) {
	if ps.dmarcPolicy == "none" {
		acc.monitoring = append(acc.monitoring, "DMARC in monitoring mode (p=none)")
		return
	}
	if ps.dmarcPct < 100 {
		acc.configured = append(acc.configured, fmt.Sprintf("DMARC (%s, pct=%d%%)", ps.dmarcPolicy, ps.dmarcPct))
		acc.issues = append(acc.issues, fmt.Sprintf("DMARC enforcement partial — only %d%% of mail subject to policy", ps.dmarcPct))
		return
	}
	acc.issues = append(acc.issues, "DMARC needs strengthening")
}

func classifyDKIM(ps protocolState, acc *postureAccumulator) {
	switch {
	case ps.dkimOK:
		acc.configured = append(acc.configured, "DKIM")
	case ps.dkimProvider:
		acc.configured = append(acc.configured, "DKIM (provider-verified)")
	case ps.dkimPartial:
		acc.monitoring = append(acc.monitoring, "DKIM (partial)")
	default:
		acc.absent = append(acc.absent, "DKIM")
		acc.issues = append(acc.issues, "No DKIM found")
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
	}
	if ps.daneOK {
		acc.configured = append(acc.configured, "DANE")
	}

	if ps.caaOK {
		acc.configured = append(acc.configured, "CAA")
	} else {
		acc.absent = append(acc.absent, "CAA")
		acc.recommendations = append(acc.recommendations, "No CAA records")
	}

	if ps.dnssecOK {
		acc.configured = append(acc.configured, "DNSSEC")
	} else {
		acc.absent = append(acc.absent, "DNSSEC")
	}
}

func evaluateDeliberateMonitoring(ps protocolState, configuredCount int) (bool, string) {
	if ps.dmarcPolicy != "none" {
		return false, ""
	}
	if configuredCount < 3 {
		return false, ""
	}

	if ps.dmarcHasRua {
		return true, "DMARC is in monitoring mode (p=none) with aggregate reporting active — this appears to be a deliberate deployment phase before enforcement"
	}
	if ps.dnssecOK || ps.daneOK || ps.mtaStsOK {
		return true, "DMARC is in monitoring mode (p=none) with advanced security controls (DNSSEC/DANE/MTA-STS) deployed — this indicates sophisticated security management with deliberate monitoring"
	}
	return true, "DMARC is in monitoring mode (p=none) — this appears intentional while gathering data before enforcement"
}

func (a *Analyzer) CalculatePosture(results map[string]any) map[string]any {
	ps := evaluateProtocolStates(results)

	acc := &postureAccumulator{}

	hasSPF := ps.spfOK || ps.spfWarning
	hasDMARC := ps.dmarcOK || ps.dmarcWarning
	hasDKIM := ps.dkimOK || ps.dkimProvider

	classifySPF(ps, acc)
	classifyDMARC(ps, acc)

	if hasDMARC && !ps.dmarcHasRua {
		acc.recommendations = append(acc.recommendations, "No DMARC aggregate reporting (rua) configured — unable to monitor authentication results")
	}

	classifyDKIM(ps, acc)
	classifySimpleProtocols(ps, acc)

	state, icon, color, message := determineGrade(ps, hasSPF, hasDMARC, hasDKIM, acc.monitoring, acc.configured, acc.absent)

	deliberateMonitoring, deliberateMonitoringNote := evaluateDeliberateMonitoring(ps, len(acc.configured))

	score := computeInternalScore(ps)
	verdicts := buildVerdicts(ps, hasSPF, hasDMARC, hasDKIM)
	allIssues := append(acc.issues, acc.recommendations...)

	return map[string]any{
		"score":                      score,
		"grade":                      state,
		"label":                      message,
		"state":                      state,
		"icon":                       icon,
		"color":                      color,
		"message":                    message,
		"issues":                     allIssues,
		"critical_issues":            acc.issues,
		"recommendations":            acc.recommendations,
		"monitoring":                 acc.monitoring,
		"configured":                 acc.configured,
		"absent":                     acc.absent,
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
		state = "Secure"
		icon = iconShieldAlt
		color = "success"
		message = buildDescriptiveMessage(ps, configured, absent, monitoring)

	case corePresent && dmarcStrict && hasCAA:
		state = "Low Risk"
		icon = iconShieldAlt
		color = "success"
		message = buildDescriptiveMessage(ps, configured, absent, monitoring)

	case corePresent && dmarcFullEnforcing:
		state = "Low Risk"
		icon = iconShieldAlt
		color = "success"
		message = buildDescriptiveMessage(ps, configured, absent, monitoring)

	case corePresent && dmarcPartialEnforcing:
		state = riskMedium
		icon = iconExclamationTriangle
		color = "warning"
		message = fmt.Sprintf("Email authentication configured but DMARC enforcement is partial (pct=%d%%). Only %d%% of failing mail is subject to policy.", ps.dmarcPct, ps.dmarcPct)

	case corePresent && ps.dmarcPolicy == "none":
		state = riskMedium
		icon = iconExclamationTriangle
		color = "warning"
		message = "Email authentication configured but DMARC is in monitoring mode (p=none). Enforcement recommended after reviewing reports."

	case hasSPF && hasDMARC && !hasDKIM:
		state = riskMedium
		icon = iconExclamationTriangle
		color = "warning"
		message = "SPF and DMARC present but DKIM not verified. DKIM signing is required for full DMARC alignment."

	case hasSPF && !hasDMARC:
		state = riskHigh
		icon = iconExclamationTriangle
		color = "warning"
		message = "SPF configured but no DMARC policy. Without DMARC, SPF alone cannot prevent email spoofing."

	case !hasSPF && !hasDMARC && !hasDKIM:
		state = "Critical Risk"
		icon = "times-circle"
		color = "danger"
		message = "No email authentication configured. This domain is fully vulnerable to email spoofing."

	default:
		state = riskHigh
		icon = iconExclamationTriangle
		color = "warning"
		message = "Partial email authentication. Critical security controls are missing."
	}

	if len(monitoring) > 0 && state != "Critical Risk" && state != riskHigh {
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
		case protocolMTASTS, protocolTLSRPT, "DNSSEC", "BIMI":
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
	buildEmailVerdict(ps, hasSPF, hasDMARC, hasDKIM, verdicts)
	buildBrandVerdict(ps, verdicts)
	buildDNSVerdict(ps, verdicts)
	return verdicts
}

func buildEmailVerdict(ps protocolState, hasSPF, hasDMARC, hasDKIM bool, verdicts map[string]any) {
	enforcing := ps.dmarcPolicy == "reject" || ps.dmarcPolicy == "quarantine"

	if hasSPF && hasDMARC && enforcing && hasDKIM {
		buildEnforcingEmailVerdict(ps, verdicts)
		return
	}
	if hasSPF && hasDMARC && ps.dmarcPolicy == "none" {
		verdicts["email"] = "Partial email authentication configured — some spoofed messages may be delivered. DMARC is in monitoring mode (p=none)."
		verdicts["email_secure"] = false
		verdicts["email_answer"] = "Partially"
		return
	}
	if hasSPF && !hasDMARC {
		verdicts["email"] = "SPF is configured but without DMARC, receiving servers may still accept spoofed messages."
		verdicts["email_secure"] = false
		verdicts["email_answer"] = "Yes"
		return
	}
	if !hasSPF && !hasDMARC {
		verdicts["email"] = "No email authentication — this domain can be impersonated by anyone."
		verdicts["email_secure"] = false
		verdicts["email_answer"] = "Yes"
		return
	}
	verdicts["email"] = "Partial email authentication configured — some spoofed messages may be delivered."
	verdicts["email_secure"] = false
	verdicts["email_answer"] = "Partially"
}

func buildEnforcingEmailVerdict(ps protocolState, verdicts map[string]any) {
	action := map[string]string{"reject": "blocked", "quarantine": "flagged as spam"}[ps.dmarcPolicy]
	msg := "DMARC policy is " + ps.dmarcPolicy + " — spoofed messages will be " + action + " by receiving servers."

	dkimSuffix := " with strong cryptography"
	if ps.dkimProvider {
		dkimSuffix = " (provider-verified for " + ps.primaryProvider + ")"
	}
	msg += " DKIM keys verified" + dkimSuffix + "."

	verdicts["email"] = msg
	verdicts["email_secure"] = ps.dmarcPolicy == "reject"
	if ps.dmarcPolicy == "reject" {
		verdicts["email_answer"] = "No"
	} else {
		verdicts["email_answer"] = "Mostly No"
	}
}

func buildBrandVerdict(ps protocolState, verdicts map[string]any) {
	switch {
	case ps.bimiOK && ps.caaOK:
		verdicts["brand"] = "Attackers cannot easily spoof your logo or obtain fraudulent TLS certificates."
		verdicts["brand_secure"] = true
		verdicts["brand_answer"] = "No"
	case ps.caaOK:
		verdicts["brand"] = "Certificate issuance restricted via CAA. BIMI not configured for brand logo protection."
		verdicts["brand_secure"] = false
		verdicts["brand_answer"] = "Partially"
	case ps.bimiOK:
		verdicts["brand"] = "BIMI brand logo configured. CAA not configured — any CA can issue certificates."
		verdicts["brand_secure"] = false
		verdicts["brand_answer"] = "Partially"
	default:
		verdicts["brand"] = "No brand protection configured. Any CA can issue certificates and no brand logo verification in place."
		verdicts["brand_secure"] = false
		verdicts["brand_answer"] = "Yes"
	}
}

func buildDNSVerdict(ps protocolState, verdicts map[string]any) {
	if ps.dnssecOK {
		verdicts["dns"] = "DNS responses are cryptographically signed and verified via DNSSEC."
		verdicts["dns_secure"] = true
		verdicts["domain_answer"] = "No"
	} else {
		verdicts["dns"] = "DNS responses are unsigned and could be spoofed. DNSSEC provides cryptographic verification."
		verdicts["dns_secure"] = false
		verdicts["domain_answer"] = "Yes"
	}
}

func computeInternalScore(ps protocolState) int {
	score := computeSPFScore(ps) + computeDMARCScore(ps) + computeDKIMScore(ps) + computeAuxScore(ps)
	if score > 100 {
		return 100
	}
	return score
}

func computeSPFScore(ps protocolState) int {
	if ps.spfOK {
		return 20
	}
	if ps.spfWarning {
		return 10
	}
	return 0
}

func computeDMARCScore(ps protocolState) int {
	if !ps.dmarcOK {
		if ps.dmarcWarning {
			return 10
		}
		return 0
	}
	base := 25
	switch ps.dmarcPolicy {
	case "reject":
		return base + 5
	case "quarantine":
		return base + 3
	}
	return base
}

func computeDKIMScore(ps protocolState) int {
	switch {
	case ps.dkimOK:
		return 20
	case ps.dkimProvider:
		return 15
	case ps.dkimPartial:
		return 5
	}
	return 0
}

func computeAuxScore(ps protocolState) int {
	score := 0
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
	return score
}
