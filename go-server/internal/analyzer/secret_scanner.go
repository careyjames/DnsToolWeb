// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "context"
        "fmt"
        "io"
        "log/slog"
        "net/http"
        "regexp"
        "strings"
        "time"

        "dnstool/go-server/internal/dnsclient"

        "golang.org/x/net/html"
)

type SecretScanner struct {
        HTTP *dnsclient.SafeHTTPClient
}

type SecretFinding struct {
        Type       string `json:"type"`
        Location   string `json:"location"`
        Redacted   string `json:"redacted"`
        Confidence string `json:"confidence"`
        Context    string `json:"context"`
        Severity   string `json:"severity"`
}

type secretPattern struct {
        Name       string
        Re         *regexp.Regexp
        Severity   string
        Confidence string
        MinLen     int
}

var secretPatterns = []secretPattern{
        {Name: "AWS Access Key ID", Re: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), Severity: "critical", Confidence: "high", MinLen: 20},
        {Name: "AWS Secret Access Key", Re: regexp.MustCompile(`(?i)(?:aws|amazon)(?:.{0,30})?(?:secret|key)(?:.{0,10})?[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`), Severity: "critical", Confidence: "high", MinLen: 40},
        {Name: "Google API Key", Re: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), Severity: "high", Confidence: "high", MinLen: 39},
        {Name: "Stripe Secret Key", Re: regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,}\b`), Severity: "critical", Confidence: "high", MinLen: 32},
        {Name: "Stripe Publishable Key", Re: regexp.MustCompile(`\bpk_live_[0-9a-zA-Z]{24,}\b`), Severity: "medium", Confidence: "high", MinLen: 32},
        {Name: "Slack Token", Re: regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z\-]{10,}\b`), Severity: "critical", Confidence: "high", MinLen: 15},
        {Name: "GitHub Token", Re: regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36,}\b`), Severity: "critical", Confidence: "high", MinLen: 40},
        {Name: "Private Key", Re: regexp.MustCompile(`-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|ENCRYPTED)?\s*PRIVATE\s+KEY-----`), Severity: "critical", Confidence: "high", MinLen: 27},
        {Name: "Database Connection String", Re: regexp.MustCompile(`\b(?:postgres|mysql|mongodb(?:\+srv)?)://[^\s"'<>]{10,}\b`), Severity: "critical", Confidence: "high", MinLen: 20},
        {Name: "Basic Auth in URL", Re: regexp.MustCompile(`https?://[^\s/:@]+:[^\s/@]{3,}@[^\s"'<>]+`), Severity: "critical", Confidence: "high", MinLen: 15},
        {Name: "Mailgun API Key", Re: regexp.MustCompile(`\bkey-[0-9a-zA-Z]{32}\b`), Severity: "critical", Confidence: "medium", MinLen: 36},
        {Name: "Twilio API Key", Re: regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`), Severity: "critical", Confidence: "medium", MinLen: 34},
        {Name: "SendGrid API Key", Re: regexp.MustCompile(`\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b`), Severity: "critical", Confidence: "high", MinLen: 69},
        {Name: "Heroku API Key", Re: regexp.MustCompile(`(?i)heroku(?:.{0,20})?[=:]\s*['"]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['"]?`), Severity: "high", Confidence: "medium", MinLen: 36},
        {Name: "Generic Bearer Token", Re: regexp.MustCompile(`(?i)(?:authorization|bearer|token|api[_-]?key)\s*[=:]\s*['"]?(?:Bearer\s+)?([A-Za-z0-9\-_.]{32,})['"]?`), Severity: "high", Confidence: "medium", MinLen: 32},
}

var placeholderPatterns = regexp.MustCompile(`(?i)(?:example|sample|dummy|test|placeholder|your[_-]?|xxx+|change[_-]?me|insert[_-]?|replace|todo|fixme|REDACTED|demo|fake)`)

func NewSecretScanner(httpClient *dnsclient.SafeHTTPClient) *SecretScanner {
        return &SecretScanner{HTTP: httpClient}
}

func (s *SecretScanner) Scan(ctx context.Context, domain string) map[string]any {
        findings := []SecretFinding{}
        scannedURLs := []string{}

        pageBody, pageURL := s.fetchMainPage(ctx, domain)
        if pageBody != "" {
                scannedURLs = append(scannedURLs, pageURL)
                findings = s.scanContent(pageBody, pageURL, findings)

                scriptURLs := extractScriptSources(pageBody, domain)
                for i, scriptURL := range scriptURLs {
                        if i >= 8 {
                                break
                        }
                        scriptBody := s.fetchResource(ctx, scriptURL)
                        if scriptBody != "" {
                                scannedURLs = append(scannedURLs, scriptURL)
                                findings = s.scanContent(scriptBody, scriptURL, findings)
                        }
                }
        }

        findings = deduplicateFindings(findings)

        status := "clear"
        message := "No exposed secrets detected in public page source"
        if len(findings) > 0 {
                status = "exposed"
                message = fmt.Sprintf("%d potential secret(s) found in publicly accessible source", len(findings))
        }

        findingsMaps := make([]map[string]any, len(findings))
        for i, f := range findings {
                findingsMaps[i] = map[string]any{
                        "type":       f.Type,
                        "location":   f.Location,
                        "redacted":   f.Redacted,
                        "confidence": f.Confidence,
                        "context":    f.Context,
                        "severity":   f.Severity,
                }
        }

        return map[string]any{
                "status":       status,
                "message":      message,
                "finding_count": len(findings),
                "findings":     findingsMaps,
                "scanned_urls": scannedURLs,
        }
}

func (s *SecretScanner) fetchMainPage(ctx context.Context, domain string) (string, string) {
        for _, scheme := range []string{"https", "http"} {
                u := fmt.Sprintf("%s://%s/", scheme, domain)
                ctx2, cancel := context.WithTimeout(ctx, 8*time.Second)
                resp, err := s.HTTP.Get(ctx2, u)
                cancel()
                if err != nil {
                        continue
                }
                defer resp.Body.Close()
                if resp.StatusCode != http.StatusOK {
                        continue
                }
                ct := resp.Header.Get("Content-Type")
                if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/xhtml") {
                        continue
                }
                body, err := s.HTTP.ReadBody(resp, 2*1024*1024)
                if err != nil {
                        slog.Debug("secret_scanner: read body error", "url", u, "error", err)
                        continue
                }
                return string(body), u
        }
        return "", ""
}

func (s *SecretScanner) fetchResource(ctx context.Context, url string) string {
        ctx2, cancel := context.WithTimeout(ctx, 6*time.Second)
        defer cancel()
        resp, err := s.HTTP.Get(ctx2, url)
        if err != nil {
                return ""
        }
        defer resp.Body.Close()
        if resp.StatusCode != http.StatusOK {
                return ""
        }
        body, err := s.HTTP.ReadBody(resp, 4*1024*1024)
        if err != nil {
                return ""
        }
        return string(body)
}

func (s *SecretScanner) scanContent(body, sourceURL string, findings []SecretFinding) []SecretFinding {
        shortURL := shortenURL(sourceURL)

        for _, pat := range secretPatterns {
                matches := pat.Re.FindAllStringIndex(body, 20)
                for _, loc := range matches {
                        matched := body[loc[0]:loc[1]]

                        if len(matched) < pat.MinLen {
                                continue
                        }

                        if placeholderPatterns.MatchString(matched) {
                                continue
                        }

                        if pat.Name == "Basic Auth in URL" && isMinifiedJSFalsePositive(matched) {
                                continue
                        }

                        contextSnippet := extractContext(body, loc[0], loc[1])
                        if isInCommentOrDocumentation(contextSnippet) {
                                continue
                        }

                        findings = append(findings, SecretFinding{
                                Type:       pat.Name,
                                Location:   shortURL,
                                Redacted:   redactSecret(matched),
                                Confidence: pat.Confidence,
                                Context:    sanitizeContext(contextSnippet),
                                Severity:   pat.Severity,
                        })
                }
        }
        return findings
}

var hostDotPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)

func isMinifiedJSFalsePositive(matched string) bool {
        atIdx := strings.Index(matched, "@")
        if atIdx < 0 {
                return false
        }
        hostPart := matched[atIdx+1:]
        if slashIdx := strings.IndexAny(hostPart, "/?#"); slashIdx > 0 {
                hostPart = hostPart[:slashIdx]
        }
        if !strings.Contains(hostPart, ".") {
                return true
        }
        if !hostDotPattern.MatchString(hostPart) {
                return true
        }
        return false
}

func extractScriptSources(htmlBody, domain string) []string {
        var sources []string
        tokenizer := html.NewTokenizer(strings.NewReader(htmlBody))
        for {
                tt := tokenizer.Next()
                if tt == html.ErrorToken {
                        if tokenizer.Err() == io.EOF {
                                break
                        }
                        break
                }
                if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
                        tn, hasAttr := tokenizer.TagName()
                        if string(tn) != "script" || !hasAttr {
                                continue
                        }
                        var src string
                        for {
                                key, val, more := tokenizer.TagAttr()
                                if string(key) == "src" {
                                        src = string(val)
                                }
                                if !more {
                                        break
                                }
                        }
                        if src == "" {
                                continue
                        }
                        if strings.HasPrefix(src, "//") {
                                src = "https:" + src
                        } else if strings.HasPrefix(src, "/") {
                                src = fmt.Sprintf("https://%s%s", domain, src)
                        } else if !strings.HasPrefix(src, "http") {
                                src = fmt.Sprintf("https://%s/%s", domain, src)
                        }
                        if isSameOrigin(src, domain) {
                                sources = append(sources, src)
                        }
                }
        }
        return sources
}

func isSameOrigin(url, domain string) bool {
        lower := strings.ToLower(url)
        host := strings.ToLower(domain)
        return strings.Contains(lower, "://"+host+"/") ||
                strings.Contains(lower, "://"+host+":") ||
                strings.HasSuffix(lower, "://"+host)
}

func redactSecret(secret string) string {
        if len(secret) <= 8 {
                return "****"
        }
        if strings.HasPrefix(secret, "-----BEGIN") {
                return "-----BEGIN [PRIVATE KEY REDACTED]-----"
        }
        prefix := secret[:4]
        suffix := secret[len(secret)-4:]
        return prefix + strings.Repeat("*", 8) + suffix
}

func extractContext(body string, start, end int) string {
        ctxStart := start - 40
        if ctxStart < 0 {
                ctxStart = 0
        }
        ctxEnd := end + 40
        if ctxEnd > len(body) {
                ctxEnd = len(body)
        }
        return body[ctxStart:ctxEnd]
}

func sanitizeContext(ctx string) string {
        ctx = strings.ReplaceAll(ctx, "\n", " ")
        ctx = strings.ReplaceAll(ctx, "\r", " ")
        ctx = strings.ReplaceAll(ctx, "\t", " ")
        for strings.Contains(ctx, "  ") {
                ctx = strings.ReplaceAll(ctx, "  ", " ")
        }
        ctx = strings.TrimSpace(ctx)
        if len(ctx) > 120 {
                ctx = ctx[:120] + "..."
        }
        return ctx
}

func isInCommentOrDocumentation(ctx string) bool {
        lower := strings.ToLower(ctx)
        docPatterns := []string{
                "// example", "/* example", "<!-- example",
                "// sample", "/* sample", "<!-- sample",
                "documentation", "readme", "tutorial",
                "// todo", "// fixme", "placeholder",
        }
        for _, p := range docPatterns {
                if strings.Contains(lower, p) {
                        return true
                }
        }
        return false
}

func shortenURL(url string) string {
        for _, prefix := range []string{"https://", "http://"} {
                if strings.HasPrefix(url, prefix) {
                        url = url[len(prefix):]
                        break
                }
        }
        if len(url) > 80 {
                url = url[:77] + "..."
        }
        return url
}

func deduplicateFindings(findings []SecretFinding) []SecretFinding {
        seen := make(map[string]bool)
        var deduped []SecretFinding
        for _, f := range findings {
                key := f.Type + "|" + f.Redacted
                if seen[key] {
                        continue
                }
                seen[key] = true
                deduped = append(deduped, f)
        }
        return deduped
}
