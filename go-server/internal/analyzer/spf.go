package analyzer

import (
        "context"
        "fmt"
        "regexp"
        "strings"
)

var (
        spfIncludeRe  = regexp.MustCompile(`(?i)include:([^\s]+)`)
        spfAMechRe    = regexp.MustCompile(`(?i)\ba[:/]`)
        spfMXMechRe   = regexp.MustCompile(`(?i)\bmx[:/\s]`)
        spfPTRMechRe  = regexp.MustCompile(`(?i)\bptr[:/\s]`)
        spfExistsRe   = regexp.MustCompile(`(?i)exists:`)
        spfRedirectRe = regexp.MustCompile(`(?i)redirect=([^\s]+)`)
        spfAllRe      = regexp.MustCompile(`(?i)([+\-~?]?)all\b`)
)

func parseSPFMechanisms(spfRecord string) (int, []string, []string, *string, *string, []string, bool) {
        spfLower := strings.ToLower(spfRecord)
        lookupCount := 0
        var lookupMechanisms []string
        var includes []string
        var permissiveness *string
        var allMechanism *string
        var issues []string
        noMailIntent := false

        includeMatches := spfIncludeRe.FindAllStringSubmatch(spfLower, -1)
        for _, m := range includeMatches {
                includes = append(includes, m[1])
                lookupMechanisms = append(lookupMechanisms, fmt.Sprintf("include:%s", m[1]))
        }
        lookupCount += len(includeMatches)

        aMatches := spfAMechRe.FindAllString(spfLower, -1)
        lookupCount += len(aMatches)
        if len(aMatches) > 0 {
                lookupMechanisms = append(lookupMechanisms, "a mechanism")
        }

        mxMatches := spfMXMechRe.FindAllString(spfLower, -1)
        lookupCount += len(mxMatches)
        if len(mxMatches) > 0 {
                lookupMechanisms = append(lookupMechanisms, "mx mechanism")
        }

        ptrMatches := spfPTRMechRe.FindAllString(spfLower, -1)
        lookupCount += len(ptrMatches)
        if len(ptrMatches) > 0 {
                lookupMechanisms = append(lookupMechanisms, "ptr mechanism (deprecated)")
                issues = append(issues, "PTR mechanism used (deprecated, slow)")
        }

        existsMatches := spfExistsRe.FindAllString(spfLower, -1)
        lookupCount += len(existsMatches)
        if len(existsMatches) > 0 {
                lookupMechanisms = append(lookupMechanisms, "exists mechanism")
        }

        redirectMatch := spfRedirectRe.FindStringSubmatch(spfLower)
        if redirectMatch != nil {
                lookupCount++
                lookupMechanisms = append(lookupMechanisms, fmt.Sprintf("redirect:%s", redirectMatch[1]))
        }

        allMatch := spfAllRe.FindStringSubmatch(spfLower)
        if allMatch != nil {
                qualifier := allMatch[1]
                if qualifier == "" {
                        qualifier = "+"
                }
                am := qualifier + "all"
                allMechanism = &am

                switch qualifier {
                case "+", "":
                        p := "DANGEROUS"
                        permissiveness = &p
                        issues = append(issues, "+all allows anyone to send as your domain")
                case "?":
                        p := "NEUTRAL"
                        permissiveness = &p
                        issues = append(issues, "?all provides no protection")
                case "~":
                        p := "SOFT"
                        permissiveness = &p
                case "-":
                        p := "STRICT"
                        permissiveness = &p
                }
        }

        hasSenders := len(includeMatches) > 0 || len(aMatches) > 0 || len(mxMatches) > 0
        if permissiveness != nil && *permissiveness == "STRICT" && hasSenders {
                issues = append(issues, "RFC 7489 §10.1: -all may cause rejection before DMARC evaluation, preventing DKIM from being checked")
        }

        normalized := strings.Join(strings.Fields(strings.TrimSpace(spfLower)), " ")
        if normalized == "v=spf1 -all" || normalized == "\"v=spf1 -all\"" {
                noMailIntent = true
        }

        return lookupCount, lookupMechanisms, includes, permissiveness, allMechanism, issues, noMailIntent
}

func buildSPFVerdict(lookupCount int, permissiveness *string, noMailIntent bool, validSPF, spfLike []string) (string, string) {
        if len(validSPF) > 1 {
                return "error", "Multiple SPF records found - this causes SPF to fail (RFC 7208)"
        }
        if len(validSPF) == 0 {
                if len(spfLike) > 0 {
                        return "warning", "No valid SPF record found"
                }
                return "error", "No valid SPF record found"
        }

        if lookupCount > 10 {
                return "warning", fmt.Sprintf("SPF exceeds lookup limit (%d/10 lookups)", lookupCount)
        }
        if lookupCount == 10 {
                return "warning", "SPF at lookup limit (10/10 lookups) - no room for growth"
        }
        if permissiveness != nil && *permissiveness == "DANGEROUS" {
                return "error", "SPF uses +all - anyone can send as this domain"
        }
        if permissiveness != nil && *permissiveness == "NEUTRAL" {
                return "warning", "SPF uses ?all - provides no protection"
        }

        if noMailIntent {
                return "success", "Valid SPF (no mail allowed) - domain declares it sends no email"
        }
        if permissiveness != nil && *permissiveness == "STRICT" {
                return "success", fmt.Sprintf("SPF valid with strict enforcement (-all), %d/10 lookups", lookupCount)
        }
        if permissiveness != nil && *permissiveness == "SOFT" {
                return "success", fmt.Sprintf("SPF valid with industry-standard soft fail (~all), %d/10 lookups", lookupCount)
        }
        return "success", fmt.Sprintf("SPF valid, %d/10 lookups", lookupCount)
}

func (a *Analyzer) AnalyzeSPF(ctx context.Context, domain string) map[string]any {
        txtRecords := a.DNS.QueryDNS(ctx, "TXT", domain)

        baseResult := map[string]any{
                "status":            "error",
                "message":           "No TXT records found",
                "records":           []string{},
                "valid_records":     []string{},
                "spf_like":          []string{},
                "lookup_count":      0,
                "lookup_mechanisms": []string{},
                "permissiveness":    nil,
                "all_mechanism":     nil,
                "issues":            []string{},
                "includes":          []string{},
                "no_mail_intent":    false,
        }

        if len(txtRecords) == 0 {
                return baseResult
        }

        var validSPF []string
        var spfLike []string

        for _, record := range txtRecords {
                if record == "" {
                        continue
                }
                lower := strings.ToLower(record)
                if strings.Contains(lower, "v=spf1") {
                        validSPF = append(validSPF, record)
                } else if strings.Contains(lower, "spf") {
                        spfLike = append(spfLike, record)
                }
        }

        var issues []string
        lookupCount := 0
        var lookupMechanisms []string
        var permissiveness *string
        var allMechanism *string
        var includes []string
        noMailIntent := false

        var status, message string

        if len(validSPF) > 1 {
                issues = append(issues, "Multiple SPF records (hard fail)")
        }

        if len(validSPF) == 1 {
                lookupCount, lookupMechanisms, includes, permissiveness, allMechanism, issues, noMailIntent = parseSPFMechanisms(validSPF[0])

                if lookupCount > 10 {
                        issues = append(issues, fmt.Sprintf("Exceeds 10 DNS lookup limit (%d lookups)", lookupCount))
                } else if lookupCount == 10 {
                        issues = append(issues, "At lookup limit (10/10)")
                }
        }

        status, message = buildSPFVerdict(lookupCount, permissiveness, noMailIntent, validSPF, spfLike)

        result := map[string]any{
                "status":            status,
                "message":           message,
                "records":           txtRecords,
                "valid_records":     validSPF,
                "spf_like":          spfLike,
                "lookup_count":      lookupCount,
                "lookup_mechanisms": lookupMechanisms,
                "permissiveness":    derefStr(permissiveness),
                "all_mechanism":     derefStr(allMechanism),
                "issues":            issues,
                "includes":          includes,
                "no_mail_intent":    noMailIntent,
        }

        if result["valid_records"] == nil {
                result["valid_records"] = []string{}
        }
        if result["spf_like"] == nil {
                result["spf_like"] = []string{}
        }
        if result["lookup_mechanisms"] == nil {
                result["lookup_mechanisms"] = []string{}
        }
        if result["issues"] == nil {
                result["issues"] = []string{}
        }
        if result["includes"] == nil {
                result["includes"] = []string{}
        }

        return result
}
