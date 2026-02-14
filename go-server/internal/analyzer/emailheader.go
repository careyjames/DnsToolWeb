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

        BodyStripped     bool
        BodyIndicators   []PhishingIndicator
        HasBodyAnalysis  bool
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
        generateFlags(result)

        if hadBody && body != "" {
                result.BodyIndicators = scanBodyForPhishingIndicators(body)
                result.HasBodyAnalysis = len(result.BodyIndicators) > 0
        }

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

        phishingDanger := 0
        for _, ind := range result.BodyIndicators {
                if ind.Severity == "danger" {
                        phishingDanger++
                }
        }

        if dangerCount > 0 || phishingDanger >= 2 {
                result.Verdict = "suspicious"
                if phishingDanger >= 2 && dangerCount == 0 {
                        result.Summary = "Templated mass-mail indicators observed in the email body — this pattern is commonly associated with scam or phishing campaigns."
                } else {
                        result.Summary = "Authentication failures observed — this email may not be from who it claims to be."
                }
        } else if warningCount > 0 || len(result.BodyIndicators) > 0 {
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

        return indicators
}
