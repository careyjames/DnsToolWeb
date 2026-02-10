package analyzer

import "fmt"

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

func (a *Analyzer) CalculatePosture(results map[string]any) map[string]any {
	score := 0
	var issues []string
	var monitoring []string
	var configured []string
	var absent []string

	spf := getMapResult(results, "spf_analysis")
	dmarc := getMapResult(results, "dmarc_analysis")
	dkim := getMapResult(results, "dkim_analysis")
	mtaSts := getMapResult(results, "mta_sts_analysis")
	tlsrpt := getMapResult(results, "tlsrpt_analysis")
	bimi := getMapResult(results, "bimi_analysis")
	dane := getMapResult(results, "dane_analysis")
	caa := getMapResult(results, "caa_analysis")
	dnssec := getMapResult(results, "dnssec_analysis")

	switch spf["status"] {
	case "success":
		score += 20
		configured = append(configured, "SPF")
	case "warning":
		score += 10
		issues = append(issues, "SPF needs attention")
	default:
		absent = append(absent, "SPF")
		issues = append(issues, "No SPF record")
	}

	dmarcPolicy, _ := dmarc["policy"].(string)
	switch dmarc["status"] {
	case "success":
		score += 25
		if dmarcPolicy == "reject" {
			score += 5
			configured = append(configured, "DMARC (reject)")
		} else if dmarcPolicy == "quarantine" {
			score += 3
			configured = append(configured, "DMARC (quarantine)")
		} else {
			configured = append(configured, "DMARC")
		}
	case "warning":
		score += 10
		if dmarcPolicy == "none" {
			monitoring = append(monitoring, "DMARC in monitoring mode (p=none)")
		}
		issues = append(issues, "DMARC needs strengthening")
	default:
		absent = append(absent, "DMARC")
		issues = append(issues, "No DMARC record")
	}

	switch dkim["status"] {
	case "success":
		score += 20
		configured = append(configured, "DKIM")
	case "warning", "partial":
		score += 10
		issues = append(issues, "DKIM issues detected")
	case "info":
		if isKnownDKIMProvider(dkim["primary_provider"]) {
			score += 15
			configured = append(configured, "DKIM (provider-verified)")
		} else {
			score += 5
			monitoring = append(monitoring, "DKIM (partial)")
		}
	default:
		absent = append(absent, "DKIM")
		issues = append(issues, "No DKIM found")
	}

	if mtaSts["status"] == "success" {
		score += 8
		configured = append(configured, "MTA-STS")
	} else {
		absent = append(absent, "MTA-STS")
		issues = append(issues, "No MTA-STS")
	}

	if tlsrpt["status"] == "success" {
		score += 4
		configured = append(configured, "TLS-RPT")
	} else {
		absent = append(absent, "TLS-RPT")
	}

	if bimi["status"] == "success" {
		score += 3
		configured = append(configured, "BIMI")
	}

	if dane["has_dane"] == true {
		score += 5
		configured = append(configured, "DANE")
	}

	if caa["status"] == "success" {
		score += 8
		configured = append(configured, "CAA")
	} else {
		absent = append(absent, "CAA")
		issues = append(issues, "No CAA records")
	}

	if dnssec["status"] == "success" {
		score += 5
		configured = append(configured, "DNSSEC")
	} else {
		absent = append(absent, "DNSSEC")
		issues = append(issues, "No DNSSEC")
	}

	if score > 100 {
		score = 100
	}

	var state, icon, color, message string
	switch {
	case score >= 85:
		state = "STRONG"
		icon = "shield-alt"
		color = "success"
		message = fmt.Sprintf("Excellent security posture (%d/100)", score)
	case score >= 70:
		state = "STRONG"
		icon = "shield-alt"
		color = "success"
		message = fmt.Sprintf("Very good security posture (%d/100)", score)
	case score >= 55:
		state = "GOOD"
		icon = "check-circle"
		color = "info"
		message = fmt.Sprintf("Good security posture (%d/100)", score)
	case score >= 40:
		state = "FAIR"
		icon = "exclamation-triangle"
		color = "warning"
		message = fmt.Sprintf("Fair security posture (%d/100) — improvements recommended", score)
	case score >= 25:
		state = "WEAK"
		icon = "exclamation-triangle"
		color = "warning"
		message = fmt.Sprintf("Needs improvement (%d/100)", score)
	default:
		state = "CRITICAL"
		icon = "times-circle"
		color = "danger"
		message = fmt.Sprintf("Critical — immediate action needed (%d/100)", score)
	}

	if len(monitoring) > 0 {
		state += " Monitoring"
	}

	deliberateMonitoring := false
	deliberateMonitoringNote := ""
	if dmarcPolicy == "none" && len(configured) >= 3 {
		deliberateMonitoring = true
		deliberateMonitoringNote = "DMARC is in monitoring mode (p=none) — this appears intentional while gathering data before enforcement"
	}

	return map[string]any{
		"score":                      score,
		"grade":                      state,
		"label":                      message,
		"state":                      state,
		"icon":                       icon,
		"color":                      color,
		"message":                    message,
		"issues":                     issues,
		"monitoring":                 monitoring,
		"configured":                 configured,
		"absent":                     absent,
		"deliberate_monitoring":      deliberateMonitoring,
		"deliberate_monitoring_note": deliberateMonitoringNote,
	}
}
