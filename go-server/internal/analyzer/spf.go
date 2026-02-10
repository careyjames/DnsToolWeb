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

type spfMechanismResult struct {
        lookupCount      int
        lookupMechanisms []string
        includes         []string
        issues           []string
}

func countSPFLookupMechanisms(spfLower string) spfMechanismResult {
        var r spfMechanismResult

        includeMatches := spfIncludeRe.FindAllStringSubmatch(spfLower, -1)
        for _, m := range includeMatches {
                r.includes = append(r.includes, m[1])
                r.lookupMechanisms = append(r.lookupMechanisms, fmt.Sprintf("include:%s", m[1]))
        }
        r.lookupCount += len(includeMatches)

        aMatches := spfAMechRe.FindAllString(spfLower, -1)
        r.lookupCount += len(aMatches)
        if len(aMatches) > 0 {
                r.lookupMechanisms = append(r.lookupMechanisms, "a mechanism")
        }

        mxMatches := spfMXMechRe.FindAllString(spfLower, -1)
        r.lookupCount += len(mxMatches)
        if len(mxMatches) > 0 {
                r.lookupMechanisms = append(r.lookupMechanisms, "mx mechanism")
        }

        ptrMatches := spfPTRMechRe.FindAllString(spfLower, -1)
        r.lookupCount += len(ptrMatches)
        if len(ptrMatches) > 0 {
                r.lookupMechanisms = append(r.lookupMechanisms, "ptr mechanism (deprecated)")
                r.issues = append(r.issues, "PTR mechanism used (deprecated, slow)")
        }

        existsMatches := spfExistsRe.FindAllString(spfLower, -1)
        r.lookupCount += len(existsMatches)
        if len(existsMatches) > 0 {
                r.lookupMechanisms = append(r.lookupMechanisms, "exists mechanism")
        }

        redirectMatch := spfRedirectRe.FindStringSubmatch(spfLower)
        if redirectMatch != nil {
                r.lookupCount++
                r.lookupMechanisms = append(r.lookupMechanisms, fmt.Sprintf("redirect:%s", redirectMatch[1]))
        }

        return r
}

func classifyAllQualifier(spfLower string) (*string, *string, []string) {
        allMatch := spfAllRe.FindStringSubmatch(spfLower)
        if allMatch == nil {
                return nil, nil, nil
        }

        qualifier := allMatch[1]
        if qualifier == "" {
                qualifier = "+"
        }
        am := qualifier + "all"

        var issues []string
        var p string
        switch qualifier {
        case "+", "":
                p = "DANGEROUS"
                issues = append(issues, "+all allows anyone to send as your domain")
        case "?":
                p = "NEUTRAL"
                issues = append(issues, "?all provides no protection")
        case "~":
                p = "SOFT"
        case "-":
                p = "STRICT"
        }

        return &p, &am, issues
}

func parseSPFMechanisms(spfRecord string) (int, []string, []string, *string, *string, []string, bool) {
        spfLower := strings.ToLower(spfRecord)

        r := countSPFLookupMechanisms(spfLower)
        permissiveness, allMechanism, allIssues := classifyAllQualifier(spfLower)
        issues := append(r.issues, allIssues...)

        hasSenders := len(r.includes) > 0 || len(spfAMechRe.FindAllString(spfLower, -1)) > 0 || len(spfMXMechRe.FindAllString(spfLower, -1)) > 0
        if permissiveness != nil && *permissiveness == "STRICT" && hasSenders {
                issues = append(issues, "RFC 7489 §10.1: -all may cause rejection before DMARC evaluation, preventing DKIM from being checked")
        }

        noMailIntent := false
        normalized := strings.Join(strings.Fields(strings.TrimSpace(spfLower)), " ")
        if normalized == "v=spf1 -all" || normalized == "\"v=spf1 -all\"" {
                noMailIntent = true
        }

        return r.lookupCount, r.lookupMechanisms, r.includes, permissiveness, allMechanism, issues, noMailIntent
}

func buildSPFVerdict(lookupCount int, permissiveness *string, noMailIntent bool, validSPF, spfLike []string) (string, string) {
        if len(validSPF) > 1 {
                return "error", "Multiple SPF records found - this causes SPF to fail (RFC 7208)"
        }
        if len(validSPF) == 0 {
                if len(spfLike) > 0 {
                        return "warning", "SPF-like record found but not valid — check syntax"
                }
                return "warning", "No SPF record found"
        }

        if lookupCount > 10 {
                return "error", fmt.Sprintf("SPF exceeds 10 DNS lookup limit (%d/10) — PermError per RFC 7208 §4.6.4", lookupCount)
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

func classifySPFRecords(records []string) (validSPF, spfLike []string) {
        for _, record := range records {
                if record == "" {
                        continue
                }
                lower := strings.ToLower(strings.TrimSpace(record))
                if lower == "v=spf1" || strings.HasPrefix(lower, "v=spf1 ") {
                        validSPF = append(validSPF, record)
                } else if strings.Contains(lower, "spf") {
                        spfLike = append(spfLike, record)
                }
        }
        return
}

func evaluateSPFRecordSet(validSPF []string) (int, []string, []string, *string, *string, []string, bool) {
        var issues []string
        lookupCount := 0
        var lookupMechanisms []string
        var permissiveness *string
        var allMechanism *string
        var includes []string
        noMailIntent := false

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

        return lookupCount, lookupMechanisms, includes, permissiveness, allMechanism, issues, noMailIntent
}

func (a *Analyzer) AnalyzeSPF(ctx context.Context, domain string) map[string]any {
        txtRecords := a.DNS.QueryDNS(ctx, "TXT", domain)

        baseResult := map[string]any{
                "status":            "warning",
                "message":           "No SPF record found",
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

        validSPF, spfLike := classifySPFRecords(txtRecords)
        lookupCount, lookupMechanisms, includes, permissiveness, allMechanism, issues, noMailIntent := evaluateSPFRecordSet(validSPF)
        status, message := buildSPFVerdict(lookupCount, permissiveness, noMailIntent, validSPF, spfLike)

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

        ensureStringSlices(result, "valid_records", "spf_like", "lookup_mechanisms", "issues", "includes")

        return result
}
