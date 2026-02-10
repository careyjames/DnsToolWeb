package analyzer

import (
	"fmt"
	"strings"
)

const (
	severityCritical = "Critical"
	severityHigh     = "High"
	severityMedium   = "Medium"
	severityLow      = "Low"

	colorCritical = "danger"
	colorHigh     = "warning"
	colorMedium   = "info"
	colorLow      = "secondary"
)

type fix struct {
	Title         string
	Description   string
	DNSRecord     string
	RFC           string
	RFCURL        string
	Severity      string
	SeverityColor string
	SeverityOrder int
}

func (a *Analyzer) GenerateRemediation(results map[string]any) map[string]any {
	ps := evaluateProtocolStates(results)
	domain := extractDomain(results)

	var fixes []fix

	fixes = appendSPFFixes(fixes, ps, domain)
	fixes = appendDMARCFixes(fixes, ps, results, domain)
	fixes = appendDKIMFixes(fixes, ps, results, domain)
	fixes = appendCAAFixes(fixes, ps, domain)
	fixes = appendMTASTSFixes(fixes, ps, domain)
	fixes = appendTLSRPTFixes(fixes, ps, domain)
	fixes = appendDNSSECFixes(fixes, ps)
	fixes = appendBIMIFixes(fixes, ps, domain)

	sortFixes(fixes)

	topCount := 3
	if len(fixes) < topCount {
		topCount = len(fixes)
	}

	topFixes := make([]map[string]any, topCount)
	for i := 0; i < topCount; i++ {
		topFixes[i] = fixToMap(fixes[i])
	}

	allFixes := make([]map[string]any, len(fixes))
	for i := range fixes {
		allFixes[i] = fixToMap(fixes[i])
	}

	achievable := computeAchievablePosture(ps, fixes)

	return map[string]any{
		"top_fixes":          topFixes,
		"all_fixes":          allFixes,
		"fix_count":          float64(len(fixes)),
		"posture_achievable": achievable,
	}
}

func extractDomain(results map[string]any) string {
	if d, ok := results["domain"].(string); ok {
		return d
	}
	return "yourdomain.com"
}

func fixToMap(f fix) map[string]any {
	return map[string]any{
		"title":          f.Title,
		"fix":            f.Description,
		"dns_record":     f.DNSRecord,
		"rfc":            f.RFC,
		"rfc_url":        f.RFCURL,
		"severity_label": f.Severity,
		"severity_color": f.SeverityColor,
		"severity_order": f.SeverityOrder,
	}
}

func sortFixes(fixes []fix) {
	for i := 1; i < len(fixes); i++ {
		key := fixes[i]
		j := i - 1
		for j >= 0 && fixes[j].SeverityOrder > key.SeverityOrder {
			fixes[j+1] = fixes[j]
			j--
		}
		fixes[j+1] = key
	}
}

func appendSPFFixes(fixes []fix, ps protocolState, domain string) []fix {
	if ps.spfOK || ps.spfWarning {
		return fixes
	}
	return append(fixes, fix{
		Title:         "Publish SPF record",
		Description:   "SPF (Sender Policy Framework) tells receiving mail servers which IP addresses are authorized to send email for your domain. Without SPF, any server can claim to send as your domain.",
		DNSRecord:     fmt.Sprintf("%s TXT \"v=spf1 include:_spf.google.com ~all\"", domain),
		RFC:           "RFC 7208 §4",
		RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7208#section-4",
		Severity:      severityCritical,
		SeverityColor: colorCritical,
		SeverityOrder: 1,
	})
}

func appendDMARCFixes(fixes []fix, ps protocolState, results map[string]any, domain string) []fix {
	if ps.dmarcOK && ps.dmarcPolicy == "reject" {
		return fixes
	}

	if !ps.dmarcOK && !ps.dmarcWarning {
		return append(fixes, fix{
			Title:         "Publish DMARC policy",
			Description:   "DMARC (Domain-based Message Authentication, Reporting & Conformance) tells receivers how to handle messages that fail SPF/DKIM checks. Without DMARC, failed authentication checks are ignored.",
			DNSRecord:     fmt.Sprintf("_dmarc.%s TXT \"v=DMARC1; p=none; rua=mailto:dmarc-reports@%s\"", domain, domain),
			RFC:           "RFC 7489 §6.3",
			RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7489#section-6.3",
			Severity:      severityCritical,
			SeverityColor: colorCritical,
			SeverityOrder: 1,
		})
	}

	if ps.dmarcPolicy == "none" {
		return append(fixes, fix{
			Title:         "Escalate DMARC from monitoring to enforcement",
			Description:   "Change your DMARC policy from p=none to p=quarantine (then p=reject). Review your DMARC aggregate reports first to ensure legitimate senders pass authentication.",
			DNSRecord:     fmt.Sprintf("_dmarc.%s TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@%s\"", domain, domain),
			RFC:           "RFC 7489 §6.3",
			RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7489#section-6.3",
			Severity:      severityHigh,
			SeverityColor: colorHigh,
			SeverityOrder: 2,
		})
	}

	if ps.dmarcPolicy == "quarantine" {
		return append(fixes, fix{
			Title:         "Upgrade DMARC to reject policy",
			Description:   "Your DMARC policy is quarantine — spoofed messages are flagged. Upgrading to p=reject blocks them entirely. Review aggregate reports to confirm legitimate senders are aligned.",
			DNSRecord:     fmt.Sprintf("_dmarc.%s TXT \"v=DMARC1; p=reject; rua=mailto:dmarc-reports@%s\"", domain, domain),
			RFC:           "RFC 7489 §6.3",
			RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7489#section-6.3",
			Severity:      severityLow,
			SeverityColor: colorLow,
			SeverityOrder: 4,
		})
	}

	return fixes
}

func appendDKIMFixes(fixes []fix, ps protocolState, results map[string]any, domain string) []fix {
	if ps.dkimOK || ps.dkimProvider {
		return fixes
	}

	dkim := getMapResult(results, "dkim_analysis")
	provider, _ := dkim["primary_provider"].(string)

	if ps.dkimPartial && provider != "" && provider != "Unknown" {
		return append(fixes, fix{
			Title:         fmt.Sprintf("Enable DKIM for %s", provider),
			Description:   fmt.Sprintf("DKIM is only configured for third-party services, not your primary mail platform (%s). Enable DKIM signing in %s settings to cover all outbound mail.", provider, provider),
			DNSRecord:     fmt.Sprintf("selector1._domainkey.%s TXT \"v=DKIM1; k=rsa; p=<public_key>\"", domain),
			RFC:           "RFC 6376 §3.6",
			RFCURL:        "https://datatracker.ietf.org/doc/html/rfc6376#section-3.6",
			Severity:      severityMedium,
			SeverityColor: colorMedium,
			SeverityOrder: 3,
		})
	}

	return append(fixes, fix{
		Title:         "Configure DKIM signing",
		Description:   "DKIM (DomainKeys Identified Mail) adds a cryptographic signature to outgoing emails, proving they haven't been tampered with. Enable DKIM in your email provider's settings.",
		DNSRecord:     fmt.Sprintf("selector1._domainkey.%s TXT \"v=DKIM1; k=rsa; p=<public_key>\"", domain),
		RFC:           "RFC 6376 §3.6",
		RFCURL:        "https://datatracker.ietf.org/doc/html/rfc6376#section-3.6",
		Severity:      severityCritical,
		SeverityColor: colorCritical,
		SeverityOrder: 1,
	})
}

func appendCAAFixes(fixes []fix, ps protocolState, domain string) []fix {
	if ps.caaOK {
		return fixes
	}
	return append(fixes, fix{
		Title:         "Add CAA records",
		Description:   "Publish CAA DNS records to restrict which Certificate Authorities can issue TLS certificates for your domain. Specify your preferred CA (e.g., letsencrypt.org, digicert.com).",
		DNSRecord:     fmt.Sprintf("%s CAA 0 issue \"letsencrypt.org\"", domain),
		RFC:           "RFC 8659 §4",
		RFCURL:        "https://datatracker.ietf.org/doc/html/rfc8659#section-4",
		Severity:      severityMedium,
		SeverityColor: colorMedium,
		SeverityOrder: 3,
	})
}

func appendMTASTSFixes(fixes []fix, ps protocolState, domain string) []fix {
	if ps.mtaStsOK {
		return fixes
	}
	return append(fixes, fix{
		Title:         "Deploy MTA-STS policy",
		Description:   fmt.Sprintf("Publish an MTA-STS DNS record and host a policy file at https://mta-sts.%s/.well-known/mta-sts.txt. This tells senders to require TLS when delivering mail to your domain.", domain),
		DNSRecord:     fmt.Sprintf("_mta-sts.%s TXT \"v=STSv1; id=20240101\"", domain),
		RFC:           "RFC 8461 §3",
		RFCURL:        "https://datatracker.ietf.org/doc/html/rfc8461#section-3",
		Severity:      severityMedium,
		SeverityColor: colorMedium,
		SeverityOrder: 3,
	})
}

func appendTLSRPTFixes(fixes []fix, ps protocolState, domain string) []fix {
	if ps.tlsrptOK {
		return fixes
	}
	return append(fixes, fix{
		Title:         "Configure TLS-RPT reporting",
		Description:   "TLS-RPT (TLS Reporting) sends you reports about TLS connection failures when other servers try to deliver mail to your domain. Helps diagnose MTA-STS and STARTTLS issues.",
		DNSRecord:     fmt.Sprintf("_smtp._tls.%s TXT \"v=TLSRPTv1; rua=mailto:tls-reports@%s\"", domain, domain),
		RFC:           "RFC 8460 §3",
		RFCURL:        "https://datatracker.ietf.org/doc/html/rfc8460#section-3",
		Severity:      severityLow,
		SeverityColor: colorLow,
		SeverityOrder: 4,
	})
}

func appendDNSSECFixes(fixes []fix, ps protocolState) []fix {
	if ps.dnssecOK {
		return fixes
	}
	return append(fixes, fix{
		Title:         "Enable DNSSEC",
		Description:   "DNSSEC (DNS Security Extensions) cryptographically signs DNS responses, preventing attackers from forging DNS answers. Contact your DNS hosting provider to enable DNSSEC signing.",
		DNSRecord:     "",
		RFC:           "RFC 4033 §2",
		RFCURL:        "https://datatracker.ietf.org/doc/html/rfc4033#section-2",
		Severity:      severityLow,
		SeverityColor: colorLow,
		SeverityOrder: 4,
	})
}

func appendBIMIFixes(fixes []fix, ps protocolState, domain string) []fix {
	if ps.bimiOK {
		return fixes
	}
	if !ps.dmarcOK || (ps.dmarcPolicy != "reject" && ps.dmarcPolicy != "quarantine") {
		return fixes
	}
	return append(fixes, fix{
		Title:         "Configure BIMI brand logo",
		Description:   "Publish a BIMI DNS record pointing to your brand logo (SVG Tiny PS format). For full support in Gmail, you will also need a Verified Mark Certificate (VMC).",
		DNSRecord:     fmt.Sprintf("default._bimi.%s TXT \"v=BIMI1; l=https://%s/logo.svg\"", domain, domain),
		RFC:           "BIMI Spec",
		RFCURL:        "https://bimigroup.org/implementation-guide/",
		Severity:      severityLow,
		SeverityColor: colorLow,
		SeverityOrder: 4,
	})
}

func computeAchievablePosture(ps protocolState, fixes []fix) string {
	hasCritical := false
	hasHigh := false
	for _, f := range fixes {
		if f.Severity == severityCritical {
			hasCritical = true
		}
		if f.Severity == severityHigh {
			hasHigh = true
		}
	}

	if !hasCritical && !hasHigh {
		if len(fixes) <= 3 {
			return "SECURE"
		}
		return "STRONG"
	}

	if hasCritical {
		return "STRONG"
	}

	return "STRONG"
}

func buildMailPosture(results map[string]any) map[string]any {
	ps := evaluateProtocolStates(results)
	mp := make(map[string]any)

	hasSPF := ps.spfOK || ps.spfWarning
	hasDMARC := ps.dmarcOK || ps.dmarcWarning
	hasDKIM := ps.dkimOK || ps.dkimProvider

	if hasSPF && hasDMARC && (ps.dmarcPolicy == "reject") && hasDKIM {
		mp["verdict"] = "Protected"
		mp["badge"] = "success"
	} else if hasSPF && hasDMARC && ps.dmarcPolicy == "quarantine" && hasDKIM {
		mp["verdict"] = "Mostly Protected"
		mp["badge"] = "success"
	} else if hasSPF && hasDMARC && hasDKIM {
		mp["verdict"] = "Monitoring"
		mp["badge"] = "info"
	} else if hasSPF || hasDMARC {
		mp["verdict"] = "Partially"
		mp["badge"] = "warning"
	} else {
		mp["verdict"] = "Vulnerable"
		mp["badge"] = "danger"
	}

	dnsInfra := getMapResult(results, "dns_infrastructure")
	if tier, ok := dnsInfra["provider_tier"].(string); ok && tier == "enterprise" {
		mp["dns_tier"] = "enterprise"
	}

	return mp
}

func getVerdict(results map[string]any, key string) string {
	posture := getMapResult(results, "posture")
	verdicts, ok := posture["verdicts"].(map[string]any)
	if !ok {
		return ""
	}
	v, _ := verdicts[key].(string)
	return v
}

func countCoreIssues(fixes []fix) int {
	count := 0
	for _, f := range fixes {
		if f.Severity == severityCritical || f.Severity == severityHigh {
			count++
		}
	}
	return count
}

func hasSeverity(fixes []fix, severity string) bool {
	for _, f := range fixes {
		if f.Severity == severity {
			return true
		}
	}
	return false
}

func filterBySeverity(fixes []fix, severity string) []fix {
	var result []fix
	for _, f := range fixes {
		if f.Severity == severity {
			result = append(result, f)
		}
	}
	return result
}

func joinFixTitles(fixes []fix) string {
	titles := make([]string, len(fixes))
	for i, f := range fixes {
		titles[i] = f.Title
	}
	return strings.Join(titles, ", ")
}
