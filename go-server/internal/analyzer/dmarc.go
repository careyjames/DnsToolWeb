package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var (
	dmarcPolicyRe    = regexp.MustCompile(`(?i)\bp=(\w+)`)
	dmarcSPRe        = regexp.MustCompile(`(?i)\bsp=(\w+)`)
	dmarcPctRe       = regexp.MustCompile(`(?i)\bpct=(\d+)`)
	dmarcASPFRe      = regexp.MustCompile(`(?i)\baspf=([rs])`)
	dmarcADKIMRe     = regexp.MustCompile(`(?i)\badkim=([rs])`)
	dmarcRUARe       = regexp.MustCompile(`(?i)\brua=([^;\s]+)`)
	dmarcRUFRe       = regexp.MustCompile(`(?i)\bruf=([^;\s]+)`)
	dmarcNPRe        = regexp.MustCompile(`(?i)\bnp=(\w+)`)
	dmarcTRe         = regexp.MustCompile(`(?i)\bt=([yn])`)
	dmarcPSDRe       = regexp.MustCompile(`(?i)\bpsd=([yn])`)
	mailtoExtractRe  = regexp.MustCompile(`(?i)mailto:([^,;\s]+)`)
)

func (a *Analyzer) AnalyzeDMARC(ctx context.Context, domain string) map[string]any {
	dmarcRecords := a.DNS.QueryDNS(ctx, "TXT", fmt.Sprintf("_dmarc.%s", domain))

	baseResult := map[string]any{
		"status":           "error",
		"message":          "No DMARC record found",
		"records":          []string{},
		"valid_records":    []string{},
		"dmarc_like":       []string{},
		"policy":           nil,
		"subdomain_policy": nil,
		"pct":              100,
		"aspf":             "relaxed",
		"adkim":            "relaxed",
		"rua":              nil,
		"ruf":              nil,
		"np_policy":        nil,
		"t_testing":        nil,
		"psd_flag":         nil,
		"dmarcbis_tags":    map[string]string{},
		"issues":           []string{},
	}

	if len(dmarcRecords) == 0 {
		return baseResult
	}

	var validDMARC []string
	var dmarcLike []string

	for _, record := range dmarcRecords {
		if record == "" {
			continue
		}
		lower := strings.ToLower(record)
		if strings.Contains(lower, "v=dmarc1") {
			validDMARC = append(validDMARC, record)
		} else if strings.Contains(lower, "dmarc") {
			dmarcLike = append(dmarcLike, record)
		}
	}

	var issues []string
	var policy *string
	var subdomainPolicy *string
	pct := 100
	aspf := "relaxed"
	adkim := "relaxed"
	var rua, ruf *string
	var npPolicy, tTesting, psdFlag *string

	var status, message string

	if len(validDMARC) == 0 {
		status = "error"
		message = "No valid DMARC record found"
	} else if len(validDMARC) > 1 {
		status = "warning"
		message = "Multiple DMARC records found (there should be only one)"
		issues = append(issues, "Multiple DMARC records")
	} else {
		record := validDMARC[0]
		recordLower := strings.ToLower(record)

		if m := dmarcPolicyRe.FindStringSubmatch(recordLower); m != nil {
			policy = &m[1]
		}

		if m := dmarcSPRe.FindStringSubmatch(recordLower); m != nil {
			subdomainPolicy = &m[1]
		}

		if m := dmarcPctRe.FindStringSubmatch(recordLower); m != nil {
			fmt.Sscanf(m[1], "%d", &pct)
		}

		if m := dmarcASPFRe.FindStringSubmatch(recordLower); m != nil {
			if m[1] == "s" {
				aspf = "strict"
			}
		}

		if m := dmarcADKIMRe.FindStringSubmatch(recordLower); m != nil {
			if m[1] == "s" {
				adkim = "strict"
			}
		}

		if m := dmarcRUARe.FindStringSubmatch(record); m != nil {
			rua = &m[1]
		}

		if m := dmarcRUFRe.FindStringSubmatch(record); m != nil {
			ruf = &m[1]
		}

		if m := dmarcNPRe.FindStringSubmatch(recordLower); m != nil {
			npPolicy = &m[1]
		}

		if m := dmarcTRe.FindStringSubmatch(recordLower); m != nil {
			tTesting = &m[1]
		}

		if m := dmarcPSDRe.FindStringSubmatch(recordLower); m != nil {
			psdFlag = &m[1]
		}

		if policy != nil {
			switch *policy {
			case "none":
				status = "warning"
				message = "DMARC in monitoring mode (p=none) - spoofed mail still delivered, no enforcement"
				issues = append(issues, "Policy p=none provides no protection - spoofed emails reach inboxes")
			case "reject":
				if pct < 100 {
					status = "warning"
					message = fmt.Sprintf("DMARC reject but only %d%% enforced - partial protection", pct)
					issues = append(issues, fmt.Sprintf("Only %d%% of mail subject to policy", pct))
				} else {
					status = "success"
					message = "DMARC policy reject (100%) - excellent protection"
				}
			case "quarantine":
				if pct < 100 {
					status = "warning"
					message = fmt.Sprintf("DMARC quarantine but only %d%% enforced - partial protection", pct)
					issues = append(issues, fmt.Sprintf("Only %d%% of mail subject to policy", pct))
				} else {
					status = "success"
					message = "DMARC policy quarantine (100%) - good protection"
				}
			default:
				status = "info"
				message = "DMARC record found but policy unclear"
			}
		} else {
			status = "info"
			message = "DMARC record found but policy unclear"
		}

		if policy != nil && (*policy == "reject" || *policy == "quarantine") {
			if subdomainPolicy != nil && *subdomainPolicy == "none" {
				issues = append(issues, fmt.Sprintf("Subdomains unprotected (sp=none while p=%s)", *policy))
			}
			if npPolicy == nil && subdomainPolicy == nil {
				issues = append(issues, "No np= tag (DMARCbis) — non-existent subdomains inherit p= policy but adding np=reject provides explicit protection against subdomain spoofing")
			}
		}

		if ruf != nil {
			issues = append(issues, "Forensic reports (ruf) configured - many providers ignore these")
		}
	}

	dmarcbisTags := map[string]string{}
	if npPolicy != nil {
		dmarcbisTags["np"] = *npPolicy
	}
	if tTesting != nil {
		dmarcbisTags["t"] = *tTesting
	}
	if psdFlag != nil {
		dmarcbisTags["psd"] = *psdFlag
	}

	result := map[string]any{
		"status":           status,
		"message":          message,
		"records":          dmarcRecords,
		"valid_records":    validDMARC,
		"dmarc_like":       dmarcLike,
		"policy":           policy,
		"subdomain_policy": subdomainPolicy,
		"pct":              pct,
		"aspf":             aspf,
		"adkim":            adkim,
		"rua":              rua,
		"ruf":              ruf,
		"np_policy":        npPolicy,
		"t_testing":        tTesting,
		"psd_flag":         psdFlag,
		"dmarcbis_tags":    dmarcbisTags,
		"issues":           issues,
	}

	if result["valid_records"] == nil {
		result["valid_records"] = []string{}
	}
	if result["dmarc_like"] == nil {
		result["dmarc_like"] = []string{}
	}
	if result["issues"] == nil {
		result["issues"] = []string{}
	}

	return result
}

func ExtractMailtoDomains(ruaString string) []string {
	if ruaString == "" {
		return nil
	}
	var domains []string
	matches := mailtoExtractRe.FindAllStringSubmatch(ruaString, -1)
	for _, m := range matches {
		addr := m[1]
		if idx := strings.Index(addr, "@"); idx >= 0 {
			d := strings.TrimRight(strings.TrimSpace(addr[idx+1:]), ".")
			if d != "" {
				domains = append(domains, strings.ToLower(d))
			}
		}
	}
	return domains
}
