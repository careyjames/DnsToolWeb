// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
package analyzer

import (
        "fmt"
        "net"
        "regexp"
        "strings"
        "time"
)

type EmailHeaderAnalysis struct {
        RawHeaders string

        From       string
        ReturnPath string
        ReplyTo    string
        To         string
        Subject    string
        Date       string
        MessageID  string

        SPFResult    AuthResult
        DKIMResults  []AuthResult
        DMARCResult  AuthResult
        ARCChain     []ARCSet

        ReceivedHops []ReceivedHop
        HopCount     int

        AlignmentFromReturnPath string
        AlignmentFromDKIM       string

        Flags    []HeaderFlag
        Summary  string
        Verdict  string
}

type AuthResult struct {
        Result     string
        Domain     string
        Detail     string
        Confidence string
}

type ARCSet struct {
        Instance int
        AMS      string
        AS       string
        AAR      string
}

type ReceivedHop struct {
        Index     int
        From      string
        By        string
        With      string
        Timestamp string
        IP        string
        IsPrivate bool
        Delay     string
}

type HeaderFlag struct {
        Severity string
        Category string
        Message  string
}

func AnalyzeEmailHeaders(raw string) *EmailHeaderAnalysis {
        result := &EmailHeaderAnalysis{
                RawHeaders: raw,
        }

        unfolded := unfoldHeaders(raw)
        headers := parseHeaderFields(unfolded)

        result.From = extractHeader(headers, "from")
        result.ReturnPath = extractHeader(headers, "return-path")
        result.ReplyTo = extractHeader(headers, "reply-to")
        result.To = extractHeader(headers, "to")
        result.Subject = extractHeader(headers, "subject")
        result.Date = extractHeader(headers, "date")
        result.MessageID = extractHeader(headers, "message-id")

        parseAuthenticationResults(headers, result)
        parseARCChain(headers, result)
        parseReceivedChain(headers, result)
        checkAlignment(result)
        generateFlags(result)
        generateVerdict(result)

        return result
}

func unfoldHeaders(raw string) string {
        raw = strings.ReplaceAll(raw, "\r\n", "\n")
        re := regexp.MustCompile(`\n[ \t]+`)
        return re.ReplaceAllString(raw, " ")
}

func parseHeaderFields(unfolded string) []headerField {
        var fields []headerField
        lines := strings.Split(unfolded, "\n")

        re := regexp.MustCompile(`^([A-Za-z][A-Za-z0-9\-]*)\s*:\s*(.*)$`)

        for _, line := range lines {
                if m := re.FindStringSubmatch(line); m != nil {
                        fields = append(fields, headerField{
                                Name:  strings.ToLower(strings.TrimSpace(m[1])),
                                Value: strings.TrimSpace(m[2]),
                        })
                }
        }
        return fields
}

type headerField struct {
        Name  string
        Value string
}

func extractHeader(fields []headerField, name string) string {
        for _, f := range fields {
                if f.Name == name {
                        return f.Value
                }
        }
        return ""
}

func extractAllHeaders(fields []headerField, name string) []string {
        var vals []string
        for _, f := range fields {
                if f.Name == name {
                        vals = append(vals, f.Value)
                }
        }
        return vals
}

func parseAuthenticationResults(fields []headerField, result *EmailHeaderAnalysis) {
        arHeaders := extractAllHeaders(fields, "authentication-results")

        for _, ar := range arHeaders {
                parts := strings.Split(ar, ";")
                for _, part := range parts {
                        part = strings.TrimSpace(part)
                        lower := strings.ToLower(part)

                        if strings.HasPrefix(lower, "spf=") {
                                result.SPFResult = parseAuthPart(part, "spf")
                        } else if strings.HasPrefix(lower, "dkim=") {
                                result.DKIMResults = append(result.DKIMResults, parseAuthPart(part, "dkim"))
                        } else if strings.HasPrefix(lower, "dmarc=") {
                                result.DMARCResult = parseAuthPart(part, "dmarc")
                        }
                }
        }

        if result.SPFResult.Result == "" || (len(result.DKIMResults) == 0 && result.DMARCResult.Result == "") {
                scanRawForAuthResults(result)
        }

        if result.SPFResult.Result == "" {
                spfReceived := extractHeader(fields, "received-spf")
                if spfReceived != "" {
                        lower := strings.ToLower(spfReceived)
                        for _, status := range []string{"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"} {
                                if strings.HasPrefix(lower, status) {
                                        result.SPFResult = AuthResult{
                                                Result:     status,
                                                Detail:     spfReceived,
                                                Confidence: "Observed",
                                        }
                                        break
                                }
                        }
                }
        }
}

func scanRawForAuthResults(result *EmailHeaderAnalysis) {
        raw := result.RawHeaders
        lower := strings.ToLower(raw)

        spfRe := regexp.MustCompile(`(?i)\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b`)
        dkimRe := regexp.MustCompile(`(?i)\bdkim=(pass|fail|none|neutral|temperror|permerror)\b`)
        dmarcRe := regexp.MustCompile(`(?i)\bdmarc=(pass|fail|none|temperror|permerror)\b`)

        _ = lower

        if result.SPFResult.Result == "" {
                if m := spfRe.FindStringSubmatch(raw); m != nil {
                        result.SPFResult = AuthResult{
                                Result:     strings.ToLower(m[1]),
                                Confidence: "Observed",
                                Detail:     "Extracted from raw header scan",
                        }
                }
        }
        if len(result.DKIMResults) == 0 {
                if m := dkimRe.FindStringSubmatch(raw); m != nil {
                        headerDomainRe := regexp.MustCompile(`(?i)header\.d=([^\s;]+)`)
                        domain := ""
                        if dm := headerDomainRe.FindStringSubmatch(raw); dm != nil {
                                domain = dm[1]
                        }
                        result.DKIMResults = append(result.DKIMResults, AuthResult{
                                Result:     strings.ToLower(m[1]),
                                Domain:     domain,
                                Confidence: "Observed",
                                Detail:     "Extracted from raw header scan",
                        })
                }
        }
        if result.DMARCResult.Result == "" {
                if m := dmarcRe.FindStringSubmatch(raw); m != nil {
                        headerFromRe := regexp.MustCompile(`(?i)header\.from=([^\s;]+)`)
                        domain := ""
                        if dm := headerFromRe.FindStringSubmatch(raw); dm != nil {
                                domain = dm[1]
                        }
                        result.DMARCResult = AuthResult{
                                Result:     strings.ToLower(m[1]),
                                Domain:     domain,
                                Confidence: "Observed",
                                Detail:     "Extracted from raw header scan",
                        }
                }
        }
}

func parseAuthPart(part string, authType string) AuthResult {
        ar := AuthResult{Confidence: "Observed"}

        eqIdx := strings.Index(part, "=")
        if eqIdx == -1 {
                return ar
        }

        remainder := strings.TrimSpace(part[eqIdx+1:])
        spaceIdx := strings.IndexAny(remainder, " \t(")
        if spaceIdx > 0 {
                ar.Result = strings.ToLower(remainder[:spaceIdx])
                ar.Detail = strings.TrimSpace(remainder[spaceIdx:])
        } else {
                ar.Result = strings.ToLower(remainder)
        }

        headerDomainRe := regexp.MustCompile(`(?i)header\.\w+=([^\s;]+)`)
        if m := headerDomainRe.FindStringSubmatch(part); m != nil {
                ar.Domain = m[1]
        }

        return ar
}

func parseARCChain(fields []headerField, result *EmailHeaderAnalysis) {
        amsHeaders := extractAllHeaders(fields, "arc-message-signature")
        asHeaders := extractAllHeaders(fields, "arc-seal")
        aarHeaders := extractAllHeaders(fields, "arc-authentication-results")

        count := len(amsHeaders)
        if len(asHeaders) > count {
                count = len(asHeaders)
        }
        if len(aarHeaders) > count {
                count = len(aarHeaders)
        }

        for i := 0; i < count; i++ {
                arc := ARCSet{Instance: i + 1}
                if i < len(amsHeaders) {
                        arc.AMS = amsHeaders[i]
                }
                if i < len(asHeaders) {
                        arc.AS = asHeaders[i]
                }
                if i < len(aarHeaders) {
                        arc.AAR = aarHeaders[i]
                }
                result.ARCChain = append(result.ARCChain, arc)
        }
}

func parseReceivedChain(fields []headerField, result *EmailHeaderAnalysis) {
        received := extractAllHeaders(fields, "received")
        result.HopCount = len(received)

        var timestamps []time.Time

        for i, r := range received {
                hop := ReceivedHop{
                        Index: i + 1,
                }

                fromRe := regexp.MustCompile(`(?i)from\s+(\S+)`)
                if m := fromRe.FindStringSubmatch(r); m != nil {
                        hop.From = m[1]
                }

                byRe := regexp.MustCompile(`(?i)by\s+(\S+)`)
                if m := byRe.FindStringSubmatch(r); m != nil {
                        hop.By = m[1]
                }

                withRe := regexp.MustCompile(`(?i)with\s+(E?SMTP\S*)`)
                if m := withRe.FindStringSubmatch(r); m != nil {
                        hop.With = m[1]
                }

                ipRe := regexp.MustCompile(`\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]`)
                if m := ipRe.FindStringSubmatch(r); m != nil {
                        hop.IP = m[1]
                        ip := net.ParseIP(hop.IP)
                        if ip != nil {
                                hop.IsPrivate = ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
                        }
                }

                if semiIdx := strings.LastIndex(r, ";"); semiIdx != -1 {
                        dateStr := strings.TrimSpace(r[semiIdx+1:])
                        hop.Timestamp = dateStr
                        if t, err := parseEmailDate(dateStr); err == nil {
                                timestamps = append(timestamps, t)
                        } else {
                                timestamps = append(timestamps, time.Time{})
                        }
                } else {
                        timestamps = append(timestamps, time.Time{})
                }

                result.ReceivedHops = append(result.ReceivedHops, hop)
        }

        for i := range result.ReceivedHops {
                if i < len(timestamps)-1 && !timestamps[i].IsZero() && !timestamps[i+1].IsZero() {
                        delay := timestamps[i+1].Sub(timestamps[i]).Abs()
                        if delay < time.Second {
                                result.ReceivedHops[i].Delay = "<1s"
                        } else if delay < time.Minute {
                                result.ReceivedHops[i].Delay = fmt.Sprintf("%.0fs", delay.Seconds())
                        } else if delay < time.Hour {
                                result.ReceivedHops[i].Delay = fmt.Sprintf("%.1fm", delay.Minutes())
                        } else {
                                result.ReceivedHops[i].Delay = fmt.Sprintf("%.1fh", delay.Hours())
                        }
                }
        }
}

func parseEmailDate(s string) (time.Time, error) {
        formats := []string{
                time.RFC1123Z,
                time.RFC1123,
                "Mon, 2 Jan 2006 15:04:05 -0700",
                "Mon, 2 Jan 2006 15:04:05 -0700 (MST)",
                "2 Jan 2006 15:04:05 -0700",
                "Mon, 02 Jan 2006 15:04:05 -0700",
                "Mon, 02 Jan 2006 15:04:05 MST",
        }
        s = strings.TrimSpace(s)
        parenIdx := strings.LastIndex(s, "(")
        clean := s
        if parenIdx > 0 {
                clean = strings.TrimSpace(s[:parenIdx])
        }
        for _, f := range formats {
                if t, err := time.Parse(f, clean); err == nil {
                        return t, nil
                }
        }
        return time.Time{}, fmt.Errorf("unparseable date: %s", s)
}

func checkAlignment(result *EmailHeaderAnalysis) {
        fromDomain := extractDomainFromEmailAddress(result.From)
        returnPathDomain := extractDomainFromEmailAddress(result.ReturnPath)

        if fromDomain != "" && returnPathDomain != "" {
                if strings.EqualFold(fromDomain, returnPathDomain) {
                        result.AlignmentFromReturnPath = "aligned"
                } else if strings.HasSuffix(strings.ToLower(returnPathDomain), "."+strings.ToLower(fromDomain)) ||
                        strings.HasSuffix(strings.ToLower(fromDomain), "."+strings.ToLower(returnPathDomain)) {
                        result.AlignmentFromReturnPath = "relaxed"
                } else {
                        result.AlignmentFromReturnPath = "misaligned"
                }
        }

        if len(result.DKIMResults) > 0 && fromDomain != "" {
                aligned := false
                for _, dkim := range result.DKIMResults {
                        if dkim.Domain != "" {
                                dkimDomain := strings.TrimPrefix(dkim.Domain, "@")
                                if strings.EqualFold(dkimDomain, fromDomain) ||
                                        strings.HasSuffix(strings.ToLower(dkimDomain), "."+strings.ToLower(fromDomain)) ||
                                        strings.HasSuffix(strings.ToLower(fromDomain), "."+strings.ToLower(dkimDomain)) {
                                        aligned = true
                                        break
                                }
                        }
                }
                if aligned {
                        result.AlignmentFromDKIM = "aligned"
                } else {
                        result.AlignmentFromDKIM = "misaligned"
                }
        }
}

func extractDomainFromEmailAddress(addr string) string {
        addr = strings.TrimSpace(addr)
        addr = strings.Trim(addr, "<>")
        if atIdx := strings.LastIndex(addr, "@"); atIdx >= 0 {
                return addr[atIdx+1:]
        }
        if angleIdx := strings.Index(addr, "<"); angleIdx >= 0 {
                inner := addr[angleIdx+1:]
                if closeIdx := strings.Index(inner, ">"); closeIdx >= 0 {
                        inner = inner[:closeIdx]
                }
                if atIdx := strings.LastIndex(inner, "@"); atIdx >= 0 {
                        return inner[atIdx+1:]
                }
        }
        return ""
}

func generateFlags(result *EmailHeaderAnalysis) {
        if result.SPFResult.Result == "fail" || result.SPFResult.Result == "softfail" {
                result.Flags = append(result.Flags, HeaderFlag{
                        Severity: "danger",
                        Category: "SPF",
                        Message:  fmt.Sprintf("SPF check returned %s — the sending server may not be authorized to send email for this domain.", result.SPFResult.Result),
                })
        } else if result.SPFResult.Result == "none" {
                result.Flags = append(result.Flags, HeaderFlag{
                        Severity: "warning",
                        Category: "SPF",
                        Message:  "No SPF record found for the sending domain — any server can claim to send from this domain.",
                })
        } else if result.SPFResult.Result == "" {
                result.Flags = append(result.Flags, HeaderFlag{
                        Severity: "info",
                        Category: "SPF",
                        Message:  "No SPF result observed in this header — the receiving server may not have checked SPF, or the result was not recorded.",
                })
        }

        allDKIMPass := true
        if len(result.DKIMResults) > 0 {
                for _, d := range result.DKIMResults {
                        if d.Result != "pass" {
                                allDKIMPass = false
                                result.Flags = append(result.Flags, HeaderFlag{
                                        Severity: "danger",
                                        Category: "DKIM",
                                        Message:  fmt.Sprintf("DKIM verification returned %s for %s — the email's cryptographic signature did not validate.", d.Result, d.Domain),
                                })
                        }
                }
                if allDKIMPass {
                        result.Flags = append(result.Flags, HeaderFlag{
                                Severity: "success",
                                Category: "DKIM",
                                Message:  "All DKIM signatures passed verification.",
                        })
                }
        } else {
                result.Flags = append(result.Flags, HeaderFlag{
                        Severity: "info",
                        Category: "DKIM",
                        Message:  "No DKIM result observed in this header.",
                })
        }

        if result.DMARCResult.Result == "fail" {
                result.Flags = append(result.Flags, HeaderFlag{
                        Severity: "danger",
                        Category: "DMARC",
                        Message:  "DMARC check failed — the email did not pass the domain owner's authentication policy.",
                })
        } else if result.DMARCResult.Result == "" {
                result.Flags = append(result.Flags, HeaderFlag{
                        Severity: "info",
                        Category: "DMARC",
                        Message:  "No DMARC result observed in this header.",
                })
        }

        if result.AlignmentFromReturnPath == "misaligned" {
                fromDomain := extractDomainFromEmailAddress(result.From)
                rpDomain := extractDomainFromEmailAddress(result.ReturnPath)
                result.Flags = append(result.Flags, HeaderFlag{
                        Severity: "warning",
                        Category: "Alignment",
                        Message:  fmt.Sprintf("From domain (%s) does not match Return-Path domain (%s) — this can indicate forwarding, mailing lists, or spoofing.", fromDomain, rpDomain),
                })
        }

        if result.ReplyTo != "" {
                replyDomain := extractDomainFromEmailAddress(result.ReplyTo)
                fromDomain := extractDomainFromEmailAddress(result.From)
                if replyDomain != "" && fromDomain != "" && !strings.EqualFold(replyDomain, fromDomain) {
                        result.Flags = append(result.Flags, HeaderFlag{
                                Severity: "warning",
                                Category: "Reply-To",
                                Message:  fmt.Sprintf("Reply-To domain (%s) differs from From domain (%s) — replies will go to a different domain.", replyDomain, fromDomain),
                        })
                }
        }

        for _, hop := range result.ReceivedHops {
                if hop.IP != "" && !hop.IsPrivate {
                        if hop.From != "" && strings.Contains(strings.ToLower(hop.From), "unknown") {
                                result.Flags = append(result.Flags, HeaderFlag{
                                        Severity: "warning",
                                        Category: "Routing",
                                        Message:  fmt.Sprintf("Hop %d: Sending server identified as 'unknown' (IP: %s) — the server did not provide a valid hostname.", hop.Index, hop.IP),
                                })
                        }
                }
        }

        if result.HopCount > 8 {
                result.Flags = append(result.Flags, HeaderFlag{
                        Severity: "info",
                        Category: "Routing",
                        Message:  fmt.Sprintf("This email traversed %d hops — an unusually long delivery path. This may indicate forwarding chains or mailing list processing.", result.HopCount),
                })
        }
}

func generateVerdict(result *EmailHeaderAnalysis) {
        dangerCount := 0
        warningCount := 0
        for _, f := range result.Flags {
                if f.Severity == "danger" {
                        dangerCount++
                } else if f.Severity == "warning" {
                        warningCount++
                }
        }

        if dangerCount > 0 {
                result.Verdict = "suspicious"
                result.Summary = "Authentication failures observed — this email may not be from who it claims to be."
        } else if warningCount > 0 {
                result.Verdict = "caution"
                result.Summary = "Some findings need attention — review the details below to determine if this is expected behavior (like forwarding or mailing lists)."
        } else {
                result.Verdict = "clean"
                result.Summary = "No authentication failures or suspicious indicators observed in this header."
        }
}
