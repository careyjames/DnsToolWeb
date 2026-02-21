// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "encoding/base64"
        "fmt"
        "io"
        "mime/quotedprintable"
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

        BodyStripped     bool
        BodyIndicators   []PhishingIndicator
        HasBodyAnalysis  bool

        BigQuestions    []BigQuestion
        HasBigQuestions bool

        SourceFormat         string

        SpamFlagged          bool
        SpamFlagSources      []string
        BCCDelivery          bool
        BCCRecipient         string
        OriginatingIP        string
        DMARCPolicy          string
        SenderBrandMismatch  bool
        SenderBrandMismatchDetail string

        SubjectScamIndicators []PhishingIndicator
        HasSubjectAnalysis    bool
        MicrosoftSCL          int
        MicrosoftSCLFound     bool
}

type BigQuestion struct {
        Question   string
        Answer     string
        Severity   string
        Icon       string
}

type PhishingIndicator struct {
        Category    string
        Severity    string
        Description string
        Evidence    string
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

func SeparateHeadersAndBody(raw string) (headers string, body string, hadBody bool) {
        normalized := strings.ReplaceAll(raw, "\r\n", "\n")

        separators := []string{"\n\n"}
        for _, sep := range separators {
                idx := strings.Index(normalized, sep)
                if idx >= 0 {
                        candidate := strings.TrimSpace(normalized[:idx])
                        remainder := strings.TrimSpace(normalized[idx+len(sep):])

                        if hasHeaderFields(candidate) && remainder != "" {
                                return candidate, remainder, true
                        }
                }
        }

        return strings.TrimSpace(raw), "", false
}

func hasHeaderFields(text string) bool {
        re := regexp.MustCompile(`(?m)^[A-Za-z][A-Za-z0-9\-]*\s*:`)
        matches := re.FindAllString(text, -1)
        return len(matches) >= 2
}

func AnalyzeEmailHeaders(raw string) *EmailHeaderAnalysis {
        headerPart, body, hadBody := SeparateHeadersAndBody(raw)

        result := &EmailHeaderAnalysis{
                RawHeaders:   headerPart,
                BodyStripped: hadBody,
        }

        unfolded := unfoldHeaders(headerPart)
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
        detectHeaderIntelligence(headers, result)
        analyzeSubjectLine(result)
        generateFlags(result)

        if hadBody && body != "" {
                decodedBody := decodeEmailBody(body, headers)
                result.BodyIndicators = scanBodyForPhishingIndicators(decodedBody)
                result.HasBodyAnalysis = len(result.BodyIndicators) > 0
        }

        generateBigQuestions(result)
        generateVerdict(result)

        return result
}

func unfoldHeaders(raw string) string {
        raw = strings.ReplaceAll(raw, "\r\n", "\n")
        headerFieldRe := regexp.MustCompile(`^[ \t]+([A-Za-z][A-Za-z0-9\-]*)\s*:`)

        lines := strings.Split(raw, "\n")
        var result []string
        for i, line := range lines {
                if i == 0 {
                        result = append(result, line)
                        continue
                }
                if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
                        if headerFieldRe.MatchString(line) {
                                result = append(result, strings.TrimLeft(line, " \t"))
                        } else {
                                result[len(result)-1] += " " + strings.TrimLeft(line, " \t")
                        }
                } else {
                        result = append(result, line)
                }
        }
        return strings.Join(result, "\n")
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
        spfRe := regexp.MustCompile(`(?i)\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b`)
        dkimRe := regexp.MustCompile(`(?i)\bdkim=(pass|fail|none|neutral|temperror|permerror)\b`)
        dmarcRe := regexp.MustCompile(`(?i)\bdmarc=(pass|fail|none|temperror|permerror)\b`)

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

        if result.SpamFlagged {
                result.Flags = append(result.Flags, HeaderFlag{
                        Severity: "danger",
                        Category: "Spam Detection",
                        Message:  "The receiving mail server flagged this email as spam/junk based on automated content analysis and sender reputation checks.",
                })
        }

        if result.BCCDelivery {
                result.Flags = append(result.Flags, HeaderFlag{
                        Severity: "warning",
                        Category: "BCC Delivery",
                        Message:  fmt.Sprintf("You (%s) were not listed in the To or CC fields — you received this via BCC. Mass scam campaigns commonly hide the full recipient list.", result.BCCRecipient),
                })
        }

        if result.OriginatingIP != "" {
                result.Flags = append(result.Flags, HeaderFlag{
                        Severity: "info",
                        Category: "Originating IP",
                        Message:  fmt.Sprintf("The sender's originating IP was %s — this reveals where the sender was when they composed the email, which may differ from the mail server location.", result.OriginatingIP),
                })
        }

        if result.DMARCPolicy == "none" {
                result.Flags = append(result.Flags, HeaderFlag{
                        Severity: "warning",
                        Category: "DMARC Policy",
                        Message:  "The sender's domain uses DMARC p=none — this means even if authentication fails, receiving servers take no enforcement action. This domain could be spoofed freely.",
                })
        }

        for _, ind := range result.SubjectScamIndicators {
                result.Flags = append(result.Flags, HeaderFlag{
                        Severity: ind.Severity,
                        Category: "Subject Line: " + ind.Category,
                        Message:  ind.Description,
                })
        }

        if result.SenderBrandMismatch {
                result.Flags = append(result.Flags, HeaderFlag{
                        Severity: "danger",
                        Category: "Brand Mismatch",
                        Message:  result.SenderBrandMismatchDetail + " — legitimate brand communications come from their own domains.",
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

        phishingDanger := 0
        for _, ind := range result.BodyIndicators {
                if ind.Severity == "danger" {
                        phishingDanger++
                }
        }

        subjectDanger := 0
        for _, ind := range result.SubjectScamIndicators {
                if ind.Severity == "danger" {
                        subjectDanger++
                }
        }

        bigQuestionDanger := 0
        for _, q := range result.BigQuestions {
                if q.Severity == "danger" {
                        bigQuestionDanger++
                }
        }

        if dangerCount > 0 || phishingDanger >= 2 || subjectDanger >= 2 || bigQuestionDanger >= 2 || (result.SpamFlagged && (phishingDanger >= 1 || subjectDanger >= 1)) {
                result.Verdict = "suspicious"
                if result.SpamFlagged && subjectDanger >= 1 {
                        result.Summary = "This email was flagged as spam and the subject line contains scam indicators — treat with extreme caution."
                } else if result.SpamFlagged && phishingDanger >= 1 {
                        result.Summary = "This email was flagged as spam by the receiving server and contains content indicators associated with scam campaigns — treat with extreme caution."
                } else if subjectDanger >= 2 {
                        result.Summary = "Multiple scam indicators observed in the subject line — this pattern is characteristic of tech support scams, fake invoice campaigns, or phishing."
                } else if phishingDanger >= 2 && dangerCount == 0 {
                        result.Summary = "Templated mass-mail indicators observed in the email body — this pattern is commonly associated with scam or phishing campaigns."
                } else if result.SenderBrandMismatch {
                        result.Summary = "The email references a brand that does not match the sending domain — this is a common impersonation technique."
                } else {
                        result.Summary = "Suspicious indicators observed — review the findings below carefully before trusting this email."
                }
        } else if warningCount > 0 || len(result.BodyIndicators) > 0 || result.HasSubjectAnalysis || result.SpamFlagged {
                result.Verdict = "caution"
                result.Summary = "Some findings need attention — review the details below to determine if this is expected behavior (like forwarding or mailing lists)."
        } else {
                result.Verdict = "clean"
                result.Summary = "No authentication failures or suspicious indicators observed in this header."
        }
}

func scanBodyForPhishingIndicators(body string) []PhishingIndicator {
        var indicators []PhishingIndicator
        lower := strings.ToLower(body)

        btcRe := regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`)
        btcBech32Re := regexp.MustCompile(`\bbc1[a-zA-HJ-NP-Z0-9]{25,90}\b`)
        ethRe := regexp.MustCompile(`\b0x[0-9a-fA-F]{40}\b`)
        xmrRe := regexp.MustCompile(`\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`)

        var cryptoMatches []string
        if m := btcRe.FindString(body); m != "" {
                cryptoMatches = append(cryptoMatches, "BTC: "+m[:12]+"...")
        }
        if m := btcBech32Re.FindString(body); m != "" {
                cryptoMatches = append(cryptoMatches, "BTC: "+m[:12]+"...")
        }
        if m := ethRe.FindString(body); m != "" {
                cryptoMatches = append(cryptoMatches, "ETH: "+m[:12]+"...")
        }
        if m := xmrRe.FindString(body); m != "" {
                cryptoMatches = append(cryptoMatches, "XMR: "+m[:12]+"...")
        }
        if len(cryptoMatches) > 0 {
                indicators = append(indicators, PhishingIndicator{
                        Category:    "Cryptocurrency Address",
                        Severity:    "danger",
                        Description: "Cryptocurrency wallet address observed in email body — commonly found in sextortion and ransomware emails.",
                        Evidence:    strings.Join(cryptoMatches, ", "),
                })
        }

        sextortionPhrases := []string{
                "recorded you", "webcam", "compromising video", "compromising photos",
                "intimate moments", "visited adult", "adult website", "porn",
                "masturbat", "sexual", "nude", "naked video", "camera was activated",
                "your device was compromised", "installed malware", "trojan",
                "i have access to your", "i hacked", "i got access",
        }
        var sextortionMatches []string
        for _, phrase := range sextortionPhrases {
                if strings.Contains(lower, phrase) {
                        sextortionMatches = append(sextortionMatches, phrase)
                }
        }
        if len(sextortionMatches) >= 2 {
                indicators = append(indicators, PhishingIndicator{
                        Category:    "Sextortion Language",
                        Severity:    "danger",
                        Description: "Multiple sextortion/blackmail phrases observed — this pattern matches well-known mass-mail extortion templates. These emails are typically sent in bulk and contain no real personal information.",
                        Evidence:    "Phrases matched: " + strings.Join(sextortionMatches, ", "),
                })
        } else if len(sextortionMatches) == 1 {
                indicators = append(indicators, PhishingIndicator{
                        Category:    "Suspicious Language",
                        Severity:    "warning",
                        Description: "A phrase commonly associated with extortion emails was observed.",
                        Evidence:    "Phrase matched: " + sextortionMatches[0],
                })
        }

        urgencyPhrases := []string{
                "within 48 hours", "within 24 hours", "within 72 hours",
                "final warning", "last chance", "time is running out",
                "act now", "act immediately", "immediate action required",
                "your account will be", "account will be suspended",
                "account will be closed", "account will be terminated",
                "failure to comply", "legal action", "law enforcement",
                "you have been selected",
        }
        var urgencyMatches []string
        for _, phrase := range urgencyPhrases {
                if strings.Contains(lower, phrase) {
                        urgencyMatches = append(urgencyMatches, phrase)
                }
        }
        if len(urgencyMatches) >= 2 {
                indicators = append(indicators, PhishingIndicator{
                        Category:    "Urgency Pressure",
                        Severity:    "danger",
                        Description: "Multiple urgency/pressure phrases observed — a hallmark of social engineering and scam emails designed to bypass rational thinking.",
                        Evidence:    "Phrases matched: " + strings.Join(urgencyMatches, ", "),
                })
        } else if len(urgencyMatches) == 1 {
                indicators = append(indicators, PhishingIndicator{
                        Category:    "Urgency Language",
                        Severity:    "warning",
                        Description: "An urgency phrase was observed — common in phishing and scam emails, though sometimes used in legitimate communications.",
                        Evidence:    "Phrase matched: " + urgencyMatches[0],
                })
        }

        genericGreetings := []string{
                "dear user", "dear customer", "dear client",
                "dear sir", "dear madam", "dear sir/madam",
                "dear valued customer", "dear account holder",
                "dear friend", "hello friend",
        }
        for _, greeting := range genericGreetings {
                if strings.Contains(lower, greeting) {
                        indicators = append(indicators, PhishingIndicator{
                                Category:    "Generic Greeting",
                                Severity:    "warning",
                                Description: "Generic greeting with no personalization — mass-produced emails typically use generic addresses because the sender does not know the recipient's name.",
                                Evidence:    "Greeting: " + greeting,
                        })
                        break
                }
        }

        paymentPhrases := []string{
                "send payment", "transfer funds", "wire transfer",
                "bitcoin payment", "pay the amount", "payment of $",
                "send $", "send the money", "pay within",
                "payment is required", "fee of $", "pay a fine",
        }
        for _, phrase := range paymentPhrases {
                if strings.Contains(lower, phrase) {
                        indicators = append(indicators, PhishingIndicator{
                                Category:    "Payment Demand",
                                Severity:    "danger",
                                Description: "Payment demand language observed in email body.",
                                Evidence:    "Phrase matched: " + phrase,
                        })
                        break
                }
        }

        impersonation := []string{
                "microsoft support", "apple support", "apple id",
                "google security", "paypal security", "amazon security",
                "irs ", "internal revenue", "social security",
                "bank of america", "wells fargo", "chase bank",
                "tech support", "customer support team",
                "geek squad", "norton", "mcafee",
        }
        for _, phrase := range impersonation {
                if strings.Contains(lower, phrase) {
                        indicators = append(indicators, PhishingIndicator{
                                Category:    "Brand Impersonation",
                                Severity:    "warning",
                                Description: "A well-known brand or service name was mentioned in the body — verify through official channels rather than clicking links in the email.",
                                Evidence:    "Brand reference: " + phrase,
                        })
                        break
                }
        }

        urlRe := regexp.MustCompile(`https?://[^\s<>"']+`)
        urls := urlRe.FindAllString(body, -1)
        if len(urls) > 5 {
                indicators = append(indicators, PhishingIndicator{
                        Category:    "High URL Density",
                        Severity:    "warning",
                        Description: fmt.Sprintf("%d URLs observed in email body — high link density can indicate phishing or spam content.", len(urls)),
                        Evidence:    fmt.Sprintf("%d unique URLs found", len(urls)),
                })
        }

        if len(urls) > 0 {
                phishHits := CheckURLsAgainstOpenPhish(urls)
                indicators = append(indicators, phishHits...)
        }

        capsRe := regexp.MustCompile(`[A-Z]{5,}`)
        capsMatches := capsRe.FindAllString(body, -1)
        exclamationCount := strings.Count(body, "!!!")
        if len(capsMatches) > 3 || exclamationCount > 2 {
                indicators = append(indicators, PhishingIndicator{
                        Category:    "Aggressive Formatting",
                        Severity:    "info",
                        Description: "Excessive capitalization or exclamation marks observed — often used in scam emails to create emotional urgency.",
                        Evidence:    fmt.Sprintf("%d ALL-CAPS words, %d triple-exclamations", len(capsMatches), exclamationCount),
                })
        }

        lotteryPhrases := []string{
                "you have won", "you won", "lottery win", "prize winner",
                "claim your prize", "claim your winnings", "lucky winner",
                "congratulations! you", "your email won", "your email was selected",
                "winning notification", "award notification",
                "ticket number", "winning number", "reference number",
                "batch number", "lucky number",
                "unclaimed fund", "unclaimed prize", "abandoned fund",
                "next of kin", "beneficiary", "inheritance",
                "send your name", "send your names", "send your address",
                "send your full name", "send your details",
                "verification purpose", "for verification",
                "contact agent", "contact our agent", "claims agent",
                "facebook lottery", "google lottery", "microsoft lottery",
                "coca cola", "coca-cola lottery",
                "united nations", "world bank", "imf",
                "automated draw", "random draw", "random selection",
        }
        var lotteryMatches []string
        for _, phrase := range lotteryPhrases {
                if strings.Contains(lower, phrase) {
                        lotteryMatches = append(lotteryMatches, phrase)
                }
        }
        if len(lotteryMatches) >= 2 {
                indicators = append(indicators, PhishingIndicator{
                        Category:    "Lottery / Advance-Fee Fraud",
                        Severity:    "danger",
                        Description: "Multiple lottery/prize fraud phrases observed — this pattern matches 419-style advance-fee scams. No legitimate lottery contacts winners by unsolicited email.",
                        Evidence:    "Phrases matched: " + strings.Join(lotteryMatches, ", "),
                })
        } else if len(lotteryMatches) == 1 {
                indicators = append(indicators, PhishingIndicator{
                        Category:    "Possible Prize Scam",
                        Severity:    "warning",
                        Description: "A phrase associated with lottery or prize-based scams was observed.",
                        Evidence:    "Phrase matched: " + lotteryMatches[0],
                })
        }

        socialEngPhrases := []string{
                "cash flow", "financing that fits", "securing funding",
                "no pressure to commit", "expansion", "growth potential",
                "should i forward", "business loan", "credit line",
                "pre-approved", "pre approved", "guaranteed approval",
                "unsolicited offer", "investment opportunity",
        }
        var socialEngMatches []string
        for _, phrase := range socialEngPhrases {
                if strings.Contains(lower, phrase) {
                        socialEngMatches = append(socialEngMatches, phrase)
                }
        }
        if len(socialEngMatches) >= 3 {
                indicators = append(indicators, PhishingIndicator{
                        Category:    "Targeted Social Engineering",
                        Severity:    "danger",
                        Description: "Multiple business-targeted social engineering phrases observed — this pattern matches unsolicited business funding scams that use information from public web presence to appear legitimate.",
                        Evidence:    "Phrases matched: " + strings.Join(socialEngMatches, ", "),
                })
        } else if len(socialEngMatches) >= 1 {
                indicators = append(indicators, PhishingIndicator{
                        Category:    "Unsolicited Business Contact",
                        Severity:    "warning",
                        Description: "Phrases associated with unsolicited business offers or funding scams observed. These emails often reference publicly available information about your company to appear credible.",
                        Evidence:    "Phrases matched: " + strings.Join(socialEngMatches, ", "),
                })
        }

        contactRe := regexp.MustCompile(`(?i)(?:please\s+)?contact\s*:\s*([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})`)
        if m := contactRe.FindStringSubmatch(body); m != nil {
                contactEmail := m[1]
                indicators = append(indicators, PhishingIndicator{
                        Category:    "Suspicious Contact Method",
                        Severity:    "warning",
                        Description: "A freemail or non-organizational contact address was embedded in the body — legitimate organizations use their own domains for communication.",
                        Evidence:    "Contact email: " + contactEmail,
                })
        }

        return indicators
}

func decodeEmailBody(body string, headers []headerField) string {
        cte := strings.ToLower(extractHeader(headers, "content-transfer-encoding"))
        contentType := strings.ToLower(extractHeader(headers, "content-type"))

        decoded := body

        if strings.Contains(cte, "base64") {
                cleaned := strings.Map(func(r rune) rune {
                        if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
                                return -1
                        }
                        return r
                }, body)
                if b, err := base64.StdEncoding.DecodeString(cleaned); err == nil {
                        decoded = string(b)
                }
        } else if strings.Contains(cte, "quoted-printable") {
                reader := quotedprintable.NewReader(strings.NewReader(body))
                if b, err := io.ReadAll(reader); err == nil {
                        decoded = string(b)
                }
        }

        if strings.Contains(contentType, "text/html") {
                decoded = stripHTMLTags(decoded)
        }

        return decoded
}

func stripHTMLTags(html string) string {
        scriptRe := regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
        html = scriptRe.ReplaceAllString(html, " ")
        styleRe := regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
        html = styleRe.ReplaceAllString(html, " ")

        tagRe := regexp.MustCompile(`<[^>]+>`)
        text := tagRe.ReplaceAllString(html, " ")

        entityMap := map[string]string{
                "&nbsp;": " ", "&amp;": "&", "&lt;": "<", "&gt;": ">",
                "&quot;": "\"", "&#39;": "'", "&apos;": "'",
                "&mdash;": "—", "&ndash;": "–", "&rsquo;": "'",
                "&lsquo;": "'", "&rdquo;": "\"", "&ldquo;": "\"",
        }
        for entity, replacement := range entityMap {
                text = strings.ReplaceAll(text, entity, replacement)
        }

        numEntityRe := regexp.MustCompile(`&#(\d+);`)
        text = numEntityRe.ReplaceAllStringFunc(text, func(s string) string {
                return " "
        })

        spaceRe := regexp.MustCompile(`\s+`)
        text = spaceRe.ReplaceAllString(text, " ")

        return strings.TrimSpace(text)
}

func detectHeaderIntelligence(headers []headerField, result *EmailHeaderAnalysis) {
        spamHeaders := map[string]string{
                "x-spam-flag":      "yes",
                "x-suspected-spam": "true",
                "x-spam-status":    "yes",
                "x-clx-spam":       "true",
        }
        for headerName, triggerVal := range spamHeaders {
                val := extractHeader(headers, headerName)
                if strings.EqualFold(strings.TrimSpace(val), triggerVal) {
                        result.SpamFlagged = true
                        result.SpamFlagSources = append(result.SpamFlagSources, headerName+": "+val)
                }
        }

        appleAction := extractHeader(headers, "x-apple-action")
        if strings.Contains(strings.ToUpper(appleAction), "JUNK") {
                result.SpamFlagged = true
                result.SpamFlagSources = append(result.SpamFlagSources, "X-Apple-Action: "+appleAction)
        }

        moveFolder := extractHeader(headers, "x-apple-movetofolder")
        if strings.EqualFold(strings.TrimSpace(moveFolder), "Junk") {
                result.SpamFlagged = true
                result.SpamFlagSources = append(result.SpamFlagSources, "X-Apple-MoveToFolder: "+moveFolder)
        }

        barracudaScore := extractHeader(headers, "x-barracuda-spam-score")
        if barracudaScore != "" {
                result.SpamFlagSources = append(result.SpamFlagSources, "X-Barracuda-Spam-Score: "+barracudaScore)
        }
        barracudaStatus := extractHeader(headers, "x-barracuda-spam-status")
        if strings.EqualFold(strings.TrimSpace(barracudaStatus), "yes") {
                result.SpamFlagged = true
                result.SpamFlagSources = append(result.SpamFlagSources, "X-Barracuda-Spam-Status: "+barracudaStatus)
        }

        mimecastVerdict := extractHeader(headers, "x-mimecast-spam-score")
        if mimecastVerdict != "" {
                result.SpamFlagSources = append(result.SpamFlagSources, "X-Mimecast-Spam-Score: "+mimecastVerdict)
        }

        ppSpam := extractHeader(headers, "x-proofpoint-spam-details-enc")
        if ppSpam != "" {
                result.SpamFlagSources = append(result.SpamFlagSources, "X-Proofpoint-Spam-Details: present")
        }

        msAntispam := extractHeader(headers, "x-forefront-antispam-report")
        if msAntispam != "" {
                sclRe := regexp.MustCompile(`(?i)\bSCL:(\d+)`)
                if m := sclRe.FindStringSubmatch(msAntispam); m != nil {
                        sclVal := 0
                        fmt.Sscanf(m[1], "%d", &sclVal)
                        result.MicrosoftSCL = sclVal
                        result.MicrosoftSCLFound = true
                        if sclVal >= 5 {
                                result.SpamFlagged = true
                                result.SpamFlagSources = append(result.SpamFlagSources, fmt.Sprintf("Microsoft SCL: %d (5+ = spam)", sclVal))
                        }
                }
        }

        clxScore := extractHeader(headers, "x-clx-score")
        if clxScore != "" {
                clxVal := 0
                fmt.Sscanf(strings.TrimSpace(clxScore), "%d", &clxVal)
                if clxVal < -100 {
                        result.SpamFlagSources = append(result.SpamFlagSources, fmt.Sprintf("Proofpoint CLX Score: %d (very negative = suspicious)", clxVal))
                }
        }

        origRecipient := extractHeader(headers, "original-recipient")
        deliveredTo := extractHeader(headers, "delivered-to")
        toField := result.To
        if toField != "" {
                toAddresses := extractAllEmailAddresses(toField)
                actualRecip := ""
                if origRecipient != "" {
                        actualRecip = extractFirstEmailFromField(origRecipient)
                } else if deliveredTo != "" {
                        actualRecip = deliveredTo
                }

                if actualRecip != "" {
                        actualLower := strings.ToLower(strings.TrimSpace(actualRecip))
                        found := false
                        for _, to := range toAddresses {
                                if strings.ToLower(to) == actualLower {
                                        found = true
                                        break
                                }
                        }
                        if !found {
                                result.BCCDelivery = true
                                result.BCCRecipient = actualRecip
                        }
                }
        }

        origIP := extractHeader(headers, "x-originating-ip")
        if origIP != "" {
                result.OriginatingIP = strings.Trim(strings.TrimSpace(origIP), "[]")
        }

        dmarcPolicy := extractHeader(headers, "x-dmarc-policy")
        if dmarcPolicy != "" {
                policyRe := regexp.MustCompile(`(?i)\bp=(none|quarantine|reject)\b`)
                if m := policyRe.FindStringSubmatch(dmarcPolicy); m != nil {
                        result.DMARCPolicy = strings.ToLower(m[1])
                }
        }

        fromDomain := extractDomainFromEmailAddress(result.From)
        subjectLower := strings.ToLower(result.Subject)
        fromLower := strings.ToLower(result.From)

        subjectNormalized := normalizeHomoglyphs(subjectLower)

        brandChecks := map[string][]string{
                "Facebook/Meta": {"facebook", "meta inc", "meta lottery"},
                "Google":        {"google", "gmail"},
                "Microsoft":     {"microsoft", "outlook", "office 365"},
                "Apple":         {"apple inc", "apple id", "icloud"},
                "Amazon":        {"amazon"},
                "PayPal":        {"paypal"},
                "Netflix":       {"netflix"},
                "Bank of America": {"bank of america"},
                "Wells Fargo":   {"wells fargo"},
                "Chase":         {"chase bank"},
                "Geek Squad":    {"geek squad"},
                "Norton":        {"norton"},
                "McAfee":        {"mcafee"},
        }

        fromDomainLower := strings.ToLower(fromDomain)
        for brand, keywords := range brandChecks {
                for _, kw := range keywords {
                        if strings.Contains(subjectLower, kw) || strings.Contains(fromLower, kw) || strings.Contains(subjectNormalized, kw) {
                                brandDomain := strings.ToLower(strings.Split(brand, "/")[0])
                                brandDomain = strings.ReplaceAll(brandDomain, " ", "")
                                if !strings.Contains(fromDomainLower, brandDomain) {
                                        result.SenderBrandMismatch = true
                                        result.SenderBrandMismatchDetail = fmt.Sprintf("References '%s' but sent from %s", brand, fromDomain)
                                        break
                                }
                        }
                }
                if result.SenderBrandMismatch {
                        break
                }
        }
}

func normalizeHomoglyphs(s string) string {
        replacements := map[rune]rune{
                '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
                '7': 't', '8': 'b', '9': 'g',
                '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
                '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
                '\u00e0': 'a', '\u00e1': 'a', '\u00e8': 'e', '\u00e9': 'e',
                '\u00f2': 'o', '\u00f3': 'o', '\u00ec': 'i', '\u00ed': 'i',
        }

        runes := []rune(s)
        for i, r := range runes {
                if repl, ok := replacements[r]; ok {
                        runes[i] = repl
                }
        }

        upperReplacements := map[rune]rune{
                'O': 'o', 'I': 'l', 'L': 'l',
        }
        for i, r := range runes {
                if repl, ok := upperReplacements[r]; ok {
                        runes[i] = repl
                }
        }

        return string(runes)
}

func analyzeSubjectLine(result *EmailHeaderAnalysis) {
        if result.Subject == "" {
                return
        }

        subject := result.Subject
        subjectLower := strings.ToLower(subject)

        phoneRe := regexp.MustCompile(`\b\d[\d\s\-\.O]{6,}\d\b`)
        if phoneRe.MatchString(subject) {
                hasLetterSubstitution := false
                matches := phoneRe.FindAllString(subject, -1)
                for _, m := range matches {
                        if strings.ContainsAny(m, "OoIl") {
                                hasLetterSubstitution = true
                        }
                }
                severity := "warning"
                desc := "A phone number was detected in the subject line — legitimate organizations rarely embed phone numbers in email subjects."
                if hasLetterSubstitution {
                        severity = "danger"
                        desc = "A phone number with letter-for-digit substitution was detected in the subject line (e.g., 'O' instead of '0'). This is a deliberate obfuscation technique used by tech support scammers to bypass spam filters."
                }
                result.SubjectScamIndicators = append(result.SubjectScamIndicators, PhishingIndicator{
                        Category:    "Phone Number in Subject",
                        Severity:    severity,
                        Description: desc,
                        Evidence:    "Matched: " + strings.Join(matches, ", "),
                })
        }

        moneyRe := regexp.MustCompile(`(?i)\$\s*[\d,]+\.?\d*\s*(?:USD|usd)?|\b[\d,]+\.?\d*\s*(?:USD|GBP|EUR)\b`)
        if moneyMatches := moneyRe.FindAllString(subject, -1); len(moneyMatches) > 0 {
                result.SubjectScamIndicators = append(result.SubjectScamIndicators, PhishingIndicator{
                        Category:    "Payment Amount in Subject",
                        Severity:    "warning",
                        Description: "A monetary amount appears in the subject line — fake payment confirmation is a common scam trigger designed to provoke an urgent call to a fraudulent support number.",
                        Evidence:    "Amount: " + strings.Join(moneyMatches, ", "),
                })
        }

        normalized := normalizeHomoglyphs(subject)
        if normalized != strings.ToLower(subject) {
                original := strings.ToLower(subject)
                var diffs []string
                origRunes := []rune(original)
                normRunes := []rune(normalized)
                for i := 0; i < len(origRunes) && i < len(normRunes); i++ {
                        if origRunes[i] != normRunes[i] {
                                diffs = append(diffs, fmt.Sprintf("'%c'→'%c'", origRunes[i], normRunes[i]))
                        }
                }
                if len(diffs) > 0 {
                        result.SubjectScamIndicators = append(result.SubjectScamIndicators, PhishingIndicator{
                                Category:    "Homoglyph Obfuscation",
                                Severity:    "danger",
                                Description: "Characters in the subject line appear to use look-alike substitutions (homoglyphs) — this is a deliberate technique to evade spam filters and disguise brand names. For example, capital 'I' instead of lowercase 'l', or letter 'O' instead of number '0'.",
                                Evidence:    "Substitutions detected: " + strings.Join(diffs, ", "),
                        })
                }
        }

        scamSubjectPhrases := []string{
                "you authorized", "authorized payment", "authorized a payment",
                "your payment of", "payment confirmation",
                "transaction id", "order confirmation",
                "your account has been", "account suspended",
                "verify your account", "verify your identity",
                "unusual activity", "suspicious activity",
                "unauthorized transaction", "unauthorized access",
                "refund of", "refund has been",
                "invoice", "receipt for your payment",
                "your subscription", "renewal notice",
                "security alert", "security notice",
                "action required", "immediate action",
        }
        var subjectPhraseMatches []string
        for _, phrase := range scamSubjectPhrases {
                if strings.Contains(subjectLower, phrase) {
                        subjectPhraseMatches = append(subjectPhraseMatches, phrase)
                }
        }
        if len(subjectPhraseMatches) >= 2 {
                result.SubjectScamIndicators = append(result.SubjectScamIndicators, PhishingIndicator{
                        Category:    "Scam Subject Pattern",
                        Severity:    "danger",
                        Description: "Multiple scam-associated phrases observed in the subject line — this combination is characteristic of phishing, fake invoice, and tech support scam campaigns.",
                        Evidence:    "Phrases: " + strings.Join(subjectPhraseMatches, ", "),
                })
        } else if len(subjectPhraseMatches) == 1 {
                result.SubjectScamIndicators = append(result.SubjectScamIndicators, PhishingIndicator{
                        Category:    "Suspicious Subject Phrase",
                        Severity:    "warning",
                        Description: "A phrase commonly associated with scam or phishing emails was observed in the subject line.",
                        Evidence:    "Phrase: " + subjectPhraseMatches[0],
                })
        }

        result.HasSubjectAnalysis = len(result.SubjectScamIndicators) > 0
}

func extractAllEmailAddresses(s string) []string {
        re := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
        return re.FindAllString(s, -1)
}

func extractFirstEmailFromField(s string) string {
        re := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
        if m := re.FindString(s); m != "" {
                return m
        }
        return strings.TrimSpace(s)
}

func generateBigQuestions(result *EmailHeaderAnalysis) {
        allAuthPass := result.SPFResult.Result == "pass" && result.DMARCResult.Result == "pass"
        hasDKIMPass := false
        for _, d := range result.DKIMResults {
                if d.Result == "pass" {
                        hasDKIMPass = true
                        break
                }
        }
        allAuthPass = allAuthPass && hasDKIMPass

        if allAuthPass && result.SpamFlagged && result.HasSubjectAnalysis {
                result.BigQuestions = append(result.BigQuestions, BigQuestion{
                        Question: "How did a scam email pass every authentication check?",
                        Answer:   "This is a sophisticated attack pattern: scammers use legitimate services (Microsoft 365, Google Workspace, etc.) to send emails that genuinely pass SPF, DKIM, and DMARC — because the infrastructure IS legitimate. The fraud is in the content, not the sender. The subject line contains obfuscated phone numbers, fake payment amounts, or look-alike brand names designed to trick you into calling a fraudulent support line. Your email provider's spam filter caught it, but the authentication system alone never could — it was designed to verify identity, not intent. Never call numbers or click links from unsolicited emails, even if they appear to come from a trusted service.",
                        Severity: "danger",
                        Icon:     "shield-halved",
                })
        } else if allAuthPass && result.SpamFlagged {
                result.BigQuestions = append(result.BigQuestions, BigQuestion{
                        Question: "How can SPF, DKIM, and DMARC all pass but this still be spam?",
                        Answer:   "Authentication only verifies the sending server was authorized by the domain — it says nothing about the content. Spammers use legitimate email services (like free mail providers) to send from real accounts that pass all checks. The content is fraudulent, not the infrastructure.",
                        Severity: "danger",
                        Icon:     "shield-halved",
                })
        } else if allAuthPass && result.HasSubjectAnalysis {
                result.BigQuestions = append(result.BigQuestions, BigQuestion{
                        Question: "All authentication passed — so why are there scam indicators in the subject?",
                        Answer:   "Scammers can trigger legitimate notification emails from real services (Microsoft, PayPal, etc.) as bait. The email is authentically from that service, but the subject line has been weaponized — containing fake phone numbers, payment amounts, or obfuscated brand names to lure you into calling a fraudulent support line. Never call numbers from unsolicited emails.",
                        Severity: "danger",
                        Icon:     "shield-halved",
                })
        }

        if allAuthPass && (result.HasBodyAnalysis || result.SenderBrandMismatch) && !result.SpamFlagged && !result.HasSubjectAnalysis {
                result.BigQuestions = append(result.BigQuestions, BigQuestion{
                        Question: "All authentication checks passed — does that mean this email is safe?",
                        Answer:   "No. SPF/DKIM/DMARC verify identity, not intent. A scammer using a legitimate email provider will pass all authentication checks. Always evaluate the content independently of the authentication results.",
                        Severity: "warning",
                        Icon:     "shield-halved",
                })
        }

        if result.BCCDelivery {
                result.BigQuestions = append(result.BigQuestions, BigQuestion{
                        Question: "Why was this email delivered to you if you're not in the To field?",
                        Answer:   fmt.Sprintf("You received this as a BCC (blind carbon copy) recipient. The email was addressed to '%s' but delivered to %s. Mass-mail campaigns and scams commonly use BCC to send to many recipients while hiding the full list.", result.To, result.BCCRecipient),
                        Severity: "warning",
                        Icon:     "eye",
                })
        }

        if result.OriginatingIP != "" {
                fromDomain := extractDomainFromEmailAddress(result.From)
                result.BigQuestions = append(result.BigQuestions, BigQuestion{
                        Question: "Does the sender's actual location match who they claim to be?",
                        Answer:   fmt.Sprintf("The X-Originating-IP header reveals the sender connected from %s when composing this email via %s. This IP may not match the organization the email claims to represent. Look up this IP to check the geographic location and ownership.", result.OriginatingIP, fromDomain),
                        Severity: "info",
                        Icon:     "globe",
                })
        }

        if result.DMARCPolicy == "none" {
                fromDomain := extractDomainFromEmailAddress(result.From)
                result.BigQuestions = append(result.BigQuestions, BigQuestion{
                        Question: "Is the sender's domain protected against spoofing?",
                        Answer:   fmt.Sprintf("The DMARC policy for %s is set to p=none — this means even if authentication fails, no action is taken. Anyone could spoof this domain with no consequences. A strong DMARC policy (p=reject or p=quarantine) would prevent this.", fromDomain),
                        Severity: "warning",
                        Icon:     "lock-open",
                })
        }

        if result.SenderBrandMismatch {
                result.BigQuestions = append(result.BigQuestions, BigQuestion{
                        Question: "Does the sender actually represent the brand mentioned?",
                        Answer:   result.SenderBrandMismatchDetail + ". Legitimate communications from major brands come from their own domains. Using a different domain to impersonate a brand is a hallmark of phishing and scam campaigns.",
                        Severity: "danger",
                        Icon:     "masks-theater",
                })
        }

        if result.SpamFlagged && len(result.SpamFlagSources) > 0 {
                result.BigQuestions = append(result.BigQuestions, BigQuestion{
                        Question: "Has the email provider already identified this as spam?",
                        Answer:   "Yes. The receiving mail server or email provider flagged this email as spam or junk before you even saw it. Headers detected: " + strings.Join(result.SpamFlagSources, "; ") + ". This is an automated determination based on content analysis, sender reputation, and pattern matching.",
                        Severity: "danger",
                        Icon:     "flag",
                })
        }

        if result.AlignmentFromReturnPath == "misaligned" && (result.SPFResult.Result == "pass" || result.DMARCResult.Result == "pass") {
                fromDomain := extractDomainFromEmailAddress(result.From)
                rpDomain := extractDomainFromEmailAddress(result.ReturnPath)
                if fromDomain != "" && rpDomain != "" {
                        result.BigQuestions = append(result.BigQuestions, BigQuestion{
                                Question: "Why does the From address not match the Return-Path?",
                                Answer:   fmt.Sprintf("The visible sender shows %s, but bounces go to %s. This sometimes indicates forwarding or mailing lists, but is also a common spoofing technique where the attacker controls the envelope sender but displays a different identity.", fromDomain, rpDomain),
                                Severity: "info",
                                Icon:     "arrows-left-right",
                        })
                }
        }

        if result.HopCount >= 5 {
                result.BigQuestions = append(result.BigQuestions, BigQuestion{
                        Question: "Why did this email take so many hops to reach you?",
                        Answer:   fmt.Sprintf("This email passed through %d servers before delivery. While some hops may be normal (internal routing, spam filters, forwarding), an unusually long delivery chain can indicate the email was relayed through multiple systems to obscure its origin.", result.HopCount),
                        Severity: "info",
                        Icon:     "route",
                })
        }

        result.HasBigQuestions = len(result.BigQuestions) > 0
}
