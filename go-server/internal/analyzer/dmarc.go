package analyzer

import (
        "context"
        "fmt"
        "regexp"
        "strings"
)

var (
        dmarcPolicyRe   = regexp.MustCompile(`(?i)\bp=(\w+)`)
        dmarcSPRe       = regexp.MustCompile(`(?i)\bsp=(\w+)`)
        dmarcPctRe      = regexp.MustCompile(`(?i)\bpct=(\d+)`)
        dmarcASPFRe     = regexp.MustCompile(`(?i)\baspf=([rs])`)
        dmarcADKIMRe    = regexp.MustCompile(`(?i)\badkim=([rs])`)
        dmarcRUARe      = regexp.MustCompile(`(?i)\brua=([^;\s]+)`)
        dmarcRUFRe      = regexp.MustCompile(`(?i)\bruf=([^;\s]+)`)
        dmarcNPRe       = regexp.MustCompile(`(?i)\bnp=(\w+)`)
        dmarcTRe        = regexp.MustCompile(`(?i)\bt=([yn])`)
        dmarcPSDRe      = regexp.MustCompile(`(?i)\bpsd=([yn])`)
        mailtoExtractRe = regexp.MustCompile(`(?i)mailto:([^,;\s]+)`)
)

type dmarcTags struct {
        policy          *string
        subdomainPolicy *string
        pct             int
        aspf            string
        adkim           string
        rua             *string
        ruf             *string
        npPolicy        *string
        tTesting        *string
        psdFlag         *string
}

func parseDMARCTags(record string) dmarcTags {
        recordLower := strings.ToLower(record)
        tags := dmarcTags{pct: 100, aspf: "relaxed", adkim: "relaxed"}

        if m := dmarcPolicyRe.FindStringSubmatch(recordLower); m != nil {
                tags.policy = &m[1]
        }
        if m := dmarcSPRe.FindStringSubmatch(recordLower); m != nil {
                tags.subdomainPolicy = &m[1]
        }
        if m := dmarcPctRe.FindStringSubmatch(recordLower); m != nil {
                fmt.Sscanf(m[1], "%d", &tags.pct)
        }
        if m := dmarcASPFRe.FindStringSubmatch(recordLower); m != nil {
                if m[1] == "s" {
                        tags.aspf = "strict"
                }
        }
        if m := dmarcADKIMRe.FindStringSubmatch(recordLower); m != nil {
                if m[1] == "s" {
                        tags.adkim = "strict"
                }
        }
        if m := dmarcRUARe.FindStringSubmatch(record); m != nil {
                tags.rua = &m[1]
        }
        if m := dmarcRUFRe.FindStringSubmatch(record); m != nil {
                tags.ruf = &m[1]
        }
        if m := dmarcNPRe.FindStringSubmatch(recordLower); m != nil {
                tags.npPolicy = &m[1]
        }
        if m := dmarcTRe.FindStringSubmatch(recordLower); m != nil {
                tags.tTesting = &m[1]
        }
        if m := dmarcPSDRe.FindStringSubmatch(recordLower); m != nil {
                tags.psdFlag = &m[1]
        }

        return tags
}

func evaluateDMARCPolicy(tags dmarcTags) (string, string, []string) {
        var issues []string

        if tags.policy == nil {
                return "info", "DMARC record found but policy unclear", issues
        }

        var status, message string
        switch *tags.policy {
        case "none":
                status = "warning"
                message = "DMARC in monitoring mode (p=none) - spoofed mail still delivered, no enforcement"
                issues = append(issues, "Policy p=none provides no protection - spoofed emails reach inboxes")
        case "reject":
                if tags.pct < 100 {
                        status = "warning"
                        message = fmt.Sprintf("DMARC reject but only %d%% enforced - partial protection", tags.pct)
                        issues = append(issues, fmt.Sprintf("Only %d%% of mail subject to policy", tags.pct))
                } else {
                        status = "success"
                        message = "DMARC policy reject (100%) - excellent protection"
                }
        case "quarantine":
                if tags.pct < 100 {
                        status = "warning"
                        message = fmt.Sprintf("DMARC quarantine but only %d%% enforced - partial protection", tags.pct)
                        issues = append(issues, fmt.Sprintf("Only %d%% of mail subject to policy", tags.pct))
                } else {
                        status = "success"
                        message = "DMARC policy quarantine (100%) - good protection"
                }
        default:
                status = "info"
                message = "DMARC record found but policy unclear"
        }

        if *tags.policy == "reject" || *tags.policy == "quarantine" {
                if tags.subdomainPolicy != nil && *tags.subdomainPolicy == "none" {
                        issues = append(issues, fmt.Sprintf("Subdomains unprotected (sp=none while p=%s)", *tags.policy))
                }
                if tags.npPolicy == nil && tags.subdomainPolicy == nil {
                        issues = append(issues, "No np= tag (DMARCbis) — non-existent subdomains inherit p= policy but adding np=reject provides explicit protection against subdomain spoofing")
                }
        }

        if tags.ruf != nil {
                issues = append(issues, "Forensic reports (ruf) configured - many providers ignore these")
        }

        return status, message, issues
}

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

        var status, message string
        var issues []string
        tags := dmarcTags{pct: 100, aspf: "relaxed", adkim: "relaxed"}

        if len(validDMARC) == 0 {
                status = "error"
                message = "No valid DMARC record found"
        } else if len(validDMARC) > 1 {
                status = "warning"
                message = "Multiple DMARC records found (there should be only one)"
                issues = append(issues, "Multiple DMARC records")
        } else {
                tags = parseDMARCTags(validDMARC[0])
                status, message, issues = evaluateDMARCPolicy(tags)
        }

        dmarcbisTags := map[string]string{}
        if tags.npPolicy != nil {
                dmarcbisTags["np"] = *tags.npPolicy
        }
        if tags.tTesting != nil {
                dmarcbisTags["t"] = *tags.tTesting
        }
        if tags.psdFlag != nil {
                dmarcbisTags["psd"] = *tags.psdFlag
        }

        result := map[string]any{
                "status":           status,
                "message":          message,
                "records":          dmarcRecords,
                "valid_records":    validDMARC,
                "dmarc_like":       dmarcLike,
                "policy":           derefStr(tags.policy),
                "subdomain_policy": derefStr(tags.subdomainPolicy),
                "pct":              tags.pct,
                "aspf":             tags.aspf,
                "adkim":            tags.adkim,
                "rua":              derefStr(tags.rua),
                "ruf":              derefStr(tags.ruf),
                "np_policy":        derefStr(tags.npPolicy),
                "t_testing":        derefStr(tags.tTesting),
                "psd_flag":         derefStr(tags.psdFlag),
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
