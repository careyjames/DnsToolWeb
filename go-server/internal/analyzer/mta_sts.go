package analyzer

import (
        "context"
        "fmt"
        "regexp"
        "strings"
)

var mtaStsIDRe = regexp.MustCompile(`(?i)id=([^;\s]+)`)

func (a *Analyzer) AnalyzeMTASTS(ctx context.Context, domain string) map[string]any {
        mtaStsDomain := fmt.Sprintf("_mta-sts.%s", domain)
        records := a.DNS.QueryDNS(ctx, "TXT", mtaStsDomain)

        baseResult := map[string]any{
                "status":         "warning",
                "message":        "No MTA-STS record found",
                "record":         nil,
                "dns_id":         nil,
                "mode":           nil,
                "policy":         nil,
                "policy_mode":    nil,
                "policy_max_age": nil,
                "policy_mx":      []string{},
                "policy_fetched": false,
                "policy_error":   nil,
                "hosting_cname":  nil,
        }

        if len(records) == 0 {
                return baseResult
        }

        var validRecords []string
        for _, r := range records {
                if strings.HasPrefix(strings.ToLower(r), "v=stsv1") {
                        validRecords = append(validRecords, r)
                }
        }

        if len(validRecords) == 0 {
                baseResult["message"] = "No valid MTA-STS record found"
                return baseResult
        }

        record := validRecords[0]
        var dnsID *string
        if m := mtaStsIDRe.FindStringSubmatch(record); m != nil {
                dnsID = &m[1]
        }

        var hostingCNAME *string
        mtaStsHost := fmt.Sprintf("mta-sts.%s", domain)
        cnameRecords := a.DNS.QueryDNS(ctx, "CNAME", mtaStsHost)
        if len(cnameRecords) > 0 {
                cname := strings.TrimRight(cnameRecords[0], ".")
                hostingCNAME = &cname
        }

        policyURL := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)
        policyData := a.fetchMTASTSPolicy(ctx, policyURL)

        var mode *string
        if policyData["fetched"].(bool) {
                if m, ok := policyData["mode"].(string); ok && m != "" {
                        mode = &m
                }
        }

        var policyIssues []string
        hasVersion, _ := policyData["has_version"].(bool)

        var status, message string
        if policyData["fetched"].(bool) && mode != nil {
                if !hasVersion {
                        policyIssues = append(policyIssues, "Policy file missing required 'version: STSv1' field (RFC 8461 §3.2)")
                }

                switch *mode {
                case "enforce":
                        status = "success"
                        mxList := policyData["mx"].([]string)
                        if len(mxList) > 0 {
                                message = fmt.Sprintf("MTA-STS enforced - TLS required for %d mail server(s)", len(mxList))
                        } else {
                                message = "MTA-STS enforced - TLS required for mail delivery"
                        }
                case "testing":
                        status = "warning"
                        message = "MTA-STS in testing mode - TLS failures reported but not enforced"
                case "none":
                        status = "warning"
                        message = "MTA-STS policy disabled (mode=none)"
                default:
                        status = "success"
                        message = "MTA-STS policy found"
                }

                if !hasVersion && status == "success" {
                        status = "warning"
                        message += " (missing version field in policy)"
                }
        } else if policyData["error"] != nil {
                status = "warning"
                message = "MTA-STS DNS record found but policy file inaccessible"
        } else {
                status = "success"
                message = "MTA-STS record found"
        }

        return map[string]any{
                "status":         status,
                "message":        message,
                "record":         record,
                "dns_id":         derefStr(dnsID),
                "mode":           derefStr(mode),
                "policy":         policyData["raw"],
                "policy_mode":    policyData["mode"],
                "policy_max_age": policyData["max_age"],
                "policy_mx":      policyData["mx"],
                "policy_fetched": policyData["fetched"],
                "policy_error":   policyData["error"],
                "hosting_cname":  derefStr(hostingCNAME),
                "policy_issues":  policyIssues,
        }
}

func (a *Analyzer) fetchMTASTSPolicy(ctx context.Context, policyURL string) map[string]any {
        result := map[string]any{
                "fetched": false,
                "raw":     nil,
                "mode":    nil,
                "max_age": nil,
                "mx":      []string{},
                "error":   nil,
        }

        resp, err := a.HTTP.Get(ctx, policyURL)
        if err != nil {
                errMsg := classifyHTTPError(err, 50)
                if strings.Contains(err.Error(), "tls") || strings.Contains(err.Error(), "certificate") {
                        errMsg = "SSL certificate error"
                }
                result["error"] = errMsg
                return result
        }

        body, err := a.HTTP.ReadBody(resp, 1<<20)
        if err != nil {
                result["error"] = "Failed to read response"
                return result
        }

        if resp.StatusCode != 200 {
                result["error"] = fmt.Sprintf("HTTP %d", resp.StatusCode)
                return result
        }

        policyText := string(body)
        result["fetched"] = true
        result["raw"] = policyText

        var mxPatterns []string
        hasVersion := false
        for _, line := range strings.Split(policyText, "\n") {
                line = strings.TrimSpace(line)
                lower := strings.ToLower(line)
                if strings.HasPrefix(lower, "version:") {
                        ver := strings.TrimSpace(line[8:])
                        if strings.EqualFold(ver, "STSv1") {
                                hasVersion = true
                        }
                        result["policy_version"] = ver
                } else if strings.HasPrefix(lower, "mode:") {
                        result["mode"] = strings.TrimSpace(strings.ToLower(line[5:]))
                } else if strings.HasPrefix(lower, "max_age:") {
                        var maxAge int
                        fmt.Sscanf(strings.TrimSpace(line[8:]), "%d", &maxAge)
                        if maxAge > 0 {
                                result["max_age"] = maxAge
                        }
                } else if strings.HasPrefix(lower, "mx:") {
                        mx := strings.TrimSpace(line[3:])
                        if mx != "" {
                                mxPatterns = append(mxPatterns, mx)
                        }
                }
        }
        result["mx"] = mxPatterns
        result["has_version"] = hasVersion

        return result
}
