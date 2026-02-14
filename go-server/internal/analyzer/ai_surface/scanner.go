package ai_surface

import (
        "bufio"
        "context"
        "fmt"
        "io"
        "log/slog"
        "net/http"
        "strings"

        "dnstool/go-server/internal/dnsclient"
)

type Scanner struct {
        HTTP *dnsclient.SafeHTTPClient
}

func NewScanner(httpClient *dnsclient.SafeHTTPClient) *Scanner {
        return &Scanner{HTTP: httpClient}
}

type Evidence struct {
        Type       string `json:"type"`
        Source     string `json:"source"`
        Detail     string `json:"detail"`
        Severity   string `json:"severity"`
        Confidence string `json:"confidence"`
}

type ScanResult struct {
        Status    string         `json:"status"`
        Message   string         `json:"message"`
        LLMSTxt   map[string]any `json:"llms_txt"`
        RobotsTxt map[string]any `json:"robots_txt"`
        Poisoning map[string]any `json:"poisoning"`
        Hidden    map[string]any `json:"hidden_prompts"`
        Evidence  []Evidence     `json:"evidence"`
        Summary   map[string]any `json:"summary"`
}

var aiCrawlers = []string{
        "GPTBot", "ChatGPT-User", "CCBot", "Google-Extended",
        "anthropic-ai", "ClaudeBot", "Claude-Web",
        "Bytespider", "Diffbot", "FacebookBot",
        "Omgilibot", "Applebot-Extended", "PerplexityBot",
        "YouBot", "Amazonbot",
}

func (s *Scanner) Scan(ctx context.Context, domain string) map[string]any {
        evidence := []Evidence{}

        llmsResult := s.checkLLMSTxt(ctx, domain, &evidence)
        robotsResult := s.checkRobotsTxt(ctx, domain, &evidence)
        poisoningResult := s.checkPoisoning(ctx, domain, &evidence)
        hiddenResult := s.checkHiddenPrompts(ctx, domain, &evidence)

        results := map[string]any{
                "llms_txt":       llmsResult,
                "robots_txt":     robotsResult,
                "poisoning":      poisoningResult,
                "hidden_prompts": hiddenResult,
                "evidence":       convertEvidenceSlice(evidence),
        }

        summary := buildSummary(results, evidence)
        results["status"] = summary["status"]
        results["message"] = summary["message"]
        results["summary"] = summary

        return results
}

func (s *Scanner) fetchLLMSTxt(ctx context.Context, domain string, evidence *[]Evidence) (found bool, url string, fields map[string]any) {
        for _, scheme := range []string{"https", "http"} {
                for _, path := range []string{"/.well-known/llms.txt", "/llms.txt"} {
                        u := fmt.Sprintf("%s://%s%s", scheme, domain, path)
                        resp, err := s.HTTP.Get(ctx, u)
                        if err != nil {
                                continue
                        }
                        defer resp.Body.Close()

                        if resp.StatusCode != http.StatusOK {
                                continue
                        }

                        body, err := s.HTTP.ReadBody(resp, 64*1024)
                        if err != nil {
                                continue
                        }
                        content := string(body)
                        if len(content) <= 10 {
                                continue
                        }

                        *evidence = append(*evidence, Evidence{
                                Type:       "llms_txt_found",
                                Source:     u,
                                Detail:     "llms.txt file found providing structured LLM context",
                                Severity:   "info",
                                Confidence: "Observed",
                        })
                        slog.Info("AI Surface: llms.txt found", "domain", domain, "url", u)
                        return true, u, parseLLMSTxtFields(content)
                }
        }
        return false, "", nil
}

func (s *Scanner) fetchLLMSFullTxt(ctx context.Context, domain string, evidence *[]Evidence) (found bool, fullURL string) {
        for _, scheme := range []string{"https", "http"} {
                for _, path := range []string{"/.well-known/llms-full.txt", "/llms-full.txt"} {
                        u := fmt.Sprintf("%s://%s%s", scheme, domain, path)
                        resp, err := s.HTTP.Get(ctx, u)
                        if err != nil {
                                continue
                        }
                        defer resp.Body.Close()

                        if resp.StatusCode != http.StatusOK {
                                continue
                        }

                        body, err := s.HTTP.ReadBody(resp, 1024)
                        if err != nil {
                                continue
                        }
                        if len(body) <= 10 {
                                continue
                        }

                        *evidence = append(*evidence, Evidence{
                                Type:       "llms_full_txt_found",
                                Source:     u,
                                Detail:     "llms-full.txt also found (extended LLM context)",
                                Severity:   "info",
                                Confidence: "Observed",
                        })
                        return true, u
                }
        }
        return false, ""
}

func (s *Scanner) checkLLMSTxt(ctx context.Context, domain string, evidence *[]Evidence) map[string]any {
        result := map[string]any{
                "found":      false,
                "full_found": false,
                "url":        nil,
                "full_url":   nil,
                "fields":     map[string]any{},
                "evidence":   []map[string]any{},
        }

        if found, url, fields := s.fetchLLMSTxt(ctx, domain, evidence); found {
                result["found"] = true
                result["url"] = url
                result["fields"] = fields
        }

        if found, fullURL := s.fetchLLMSFullTxt(ctx, domain, evidence); found {
                result["full_found"] = true
                result["full_url"] = fullURL
        }

        return result
}

func parseLLMSTxtFields(content string) map[string]any {
        fields := map[string]any{}
        scanner := bufio.NewScanner(strings.NewReader(content))
        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if strings.HasPrefix(line, "#") || line == "" {
                        continue
                }
                if idx := strings.Index(line, ":"); idx > 0 {
                        key := strings.TrimSpace(line[:idx])
                        val := strings.TrimSpace(line[idx+1:])
                        if val != "" {
                                fields[strings.ToLower(key)] = val
                        }
                }
        }
        return fields
}

func (s *Scanner) checkRobotsTxt(ctx context.Context, domain string, evidence *[]Evidence) map[string]any {
        result := map[string]any{
                "found":              false,
                "url":                nil,
                "blocks_ai_crawlers": false,
                "allows_ai_crawlers": false,
                "blocked_crawlers":   []string{},
                "allowed_crawlers":   []string{},
                "directives":         []map[string]any{},
                "evidence":           []map[string]any{},
        }

        for _, scheme := range []string{"https", "http"} {
                url := fmt.Sprintf("%s://%s/robots.txt", scheme, domain)
                resp, err := s.HTTP.Get(ctx, url)
                if err != nil {
                        continue
                }
                defer resp.Body.Close()

                if resp.StatusCode == http.StatusOK {
                        body, err := s.HTTP.ReadBody(resp, 128*1024)
                        if err != nil {
                                continue
                        }
                        content := string(body)
                        if len(content) < 5 {
                                continue
                        }

                        result["found"] = true
                        result["url"] = url

                        blocked, allowed, directives := parseRobotsTxtForAI(content)
                        result["blocked_crawlers"] = blocked
                        result["allowed_crawlers"] = allowed
                        result["directives"] = directives

                        if len(blocked) > 0 {
                                result["blocks_ai_crawlers"] = true
                                *evidence = append(*evidence, Evidence{
                                        Type:       "robots_txt_blocks_ai",
                                        Source:     url,
                                        Detail:     fmt.Sprintf("robots.txt blocks %d AI crawler(s): %s", len(blocked), strings.Join(blocked, ", ")),
                                        Severity:   "info",
                                        Confidence: "Observed",
                                })
                        } else {
                                result["allows_ai_crawlers"] = true
                                *evidence = append(*evidence, Evidence{
                                        Type:       "robots_txt_no_ai_blocks",
                                        Source:     url,
                                        Detail:     "robots.txt found but no AI-specific blocking directives",
                                        Severity:   "low",
                                        Confidence: "Observed",
                                })
                        }
                        slog.Info("AI Surface: robots.txt analyzed", "domain", domain, "blocked", len(blocked))
                        break
                }
        }

        return result
}

func processRobotsDirective(line, lower string, currentAgents []string, blockedSet, allowedSet map[string]bool, blocked, allowed []string, directives []map[string]any) ([]string, []string, []map[string]any) {
        for _, agent := range currentAgents {
                if strings.HasPrefix(lower, "disallow:") {
                        disallowPath := strings.TrimSpace(line[len("disallow:"):])
                        if disallowPath != "" && !blockedSet[agent] {
                                blockedSet[agent] = true
                                blocked = append(blocked, agent)
                                directives = append(directives, map[string]any{
                                        "agent":     agent,
                                        "directive": "Disallow",
                                        "path":      disallowPath,
                                })
                        }
                } else if strings.HasPrefix(lower, "allow:") {
                        allowPath := strings.TrimSpace(line[len("allow:"):])
                        if allowPath != "" && !allowedSet[agent] {
                                allowedSet[agent] = true
                                allowed = append(allowed, agent)
                        }
                }
        }
        return blocked, allowed, directives
}

func parseRobotsTxtForAI(content string) (blocked []string, allowed []string, directives []map[string]any) {
        scanner := bufio.NewScanner(strings.NewReader(content))
        var currentAgents []string
        blockedSet := map[string]bool{}
        allowedSet := map[string]bool{}

        aiCrawlerSet := map[string]bool{}
        for _, c := range aiCrawlers {
                aiCrawlerSet[strings.ToLower(c)] = true
        }

        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if strings.HasPrefix(line, "#") || line == "" {
                        continue
                }

                lower := strings.ToLower(line)

                if strings.HasPrefix(lower, "user-agent:") {
                        agent := strings.TrimSpace(line[len("user-agent:"):])
                        agentLower := strings.ToLower(agent)
                        if len(currentAgents) > 0 && !strings.HasPrefix(strings.ToLower(currentAgents[0]), strings.ToLower(agent)) {
                                currentAgents = nil
                        }
                        if aiCrawlerSet[agentLower] {
                                currentAgents = append(currentAgents, agent)
                        }
                        continue
                }

                if len(currentAgents) == 0 {
                        continue
                }

                blocked, allowed, directives = processRobotsDirective(line, lower, currentAgents, blockedSet, allowedSet, blocked, allowed, directives)
        }

        return blocked, allowed, directives
}

func scanForPrefillLinks(content string) []map[string]any {
        iocs := []map[string]any{}
        prefillPatterns := []string{
                "chat.openai.com/chat?prompt=",
                "chatgpt.com/?prompt=",
                "claude.ai/chat?q=",
                "bard.google.com/?q=",
                "copilot.microsoft.com/?q=",
        }
        for _, pattern := range prefillPatterns {
                if strings.Contains(strings.ToLower(content), strings.ToLower(pattern)) {
                        iocs = append(iocs, map[string]any{
                                "type":   "prefilled_prompt_link",
                                "detail": fmt.Sprintf("Found prefilled AI prompt link pattern: %s", pattern),
                        })
                }
        }
        return iocs
}

func (s *Scanner) checkPoisoning(ctx context.Context, domain string, evidence *[]Evidence) map[string]any {
        result := map[string]any{
                "status":    "success",
                "message":   "No AI recommendation poisoning indicators found",
                "ioc_count": 0,
                "iocs":      []map[string]any{},
                "evidence":  []map[string]any{},
        }

        for _, scheme := range []string{"https", "http"} {
                url := fmt.Sprintf("%s://%s/", scheme, domain)
                resp, err := s.HTTP.Get(ctx, url)
                if err != nil {
                        continue
                }
                defer resp.Body.Close()

                if resp.StatusCode != http.StatusOK {
                        continue
                }

                body, err := s.HTTP.ReadBody(resp, 512*1024)
                if err != nil {
                        continue
                }

                iocs := scanForPrefillLinks(string(body))

                if len(iocs) > 0 {
                        result["ioc_count"] = len(iocs)
                        result["iocs"] = iocs
                        result["status"] = "warning"
                        result["message"] = fmt.Sprintf("%d AI recommendation poisoning indicator(s) found", len(iocs))
                        for _, ioc := range iocs {
                                *evidence = append(*evidence, Evidence{
                                        Type:       "poisoning_ioc",
                                        Source:     url,
                                        Detail:     ioc["detail"].(string),
                                        Severity:   "medium",
                                        Confidence: "Observed",
                                })
                        }
                }
                break
        }

        return result
}

func scanForHiddenPrompts(content string) []map[string]any {
        artifacts := []map[string]any{}

        hiddenPatterns := []struct {
                pattern string
                method  string
        }{
                {"display:none", "CSS hidden element"},
                {"visibility:hidden", "CSS visibility hidden"},
                {"position:absolute;left:-9999", "Off-screen positioning"},
                {"aria-hidden=\"true\"", "ARIA hidden"},
        }

        promptKeywords := []string{
                "you are a", "ignore previous", "system prompt",
                "act as", "pretend you", "respond as if",
        }

        lower := strings.ToLower(content)
        for _, hp := range hiddenPatterns {
                if !strings.Contains(lower, hp.pattern) {
                        continue
                }
                idx := strings.Index(lower, hp.pattern)
                if idx < 0 {
                        continue
                }
                start := idx
                end := idx + 500
                if end > len(lower) {
                        end = len(lower)
                }
                nearby := lower[start:end]
                for _, kw := range promptKeywords {
                        if strings.Contains(nearby, kw) {
                                artifacts = append(artifacts, map[string]any{
                                        "method": hp.method,
                                        "detail": fmt.Sprintf("Hidden element with prompt keyword '%s' detected near %s pattern", kw, hp.method),
                                })
                        }
                }
        }

        return artifacts
}

func (s *Scanner) checkHiddenPrompts(ctx context.Context, domain string, evidence *[]Evidence) map[string]any {
        result := map[string]any{
                "status":         "success",
                "message":        "No hidden prompt-like artifacts detected",
                "artifact_count": 0,
                "artifacts":      []map[string]any{},
                "evidence":       []map[string]any{},
        }

        for _, scheme := range []string{"https", "http"} {
                url := fmt.Sprintf("%s://%s/", scheme, domain)
                resp, err := s.HTTP.Get(ctx, url)
                if err != nil {
                        continue
                }
                defer resp.Body.Close()

                if resp.StatusCode != http.StatusOK {
                        continue
                }

                body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
                if err != nil {
                        continue
                }

                artifacts := scanForHiddenPrompts(string(body))

                if len(artifacts) > 0 {
                        result["artifact_count"] = len(artifacts)
                        result["artifacts"] = artifacts
                        result["status"] = "warning"
                        result["message"] = fmt.Sprintf("%d hidden prompt artifact(s) found", len(artifacts))
                        for _, a := range artifacts {
                                *evidence = append(*evidence, Evidence{
                                        Type:       "hidden_prompt",
                                        Source:     url,
                                        Detail:     a["detail"].(string),
                                        Severity:   "high",
                                        Confidence: "Observed",
                                })
                        }
                }
                break
        }

        return result
}

func convertEvidenceSlice(evidence []Evidence) []map[string]any {
        result := make([]map[string]any, 0, len(evidence))
        for _, e := range evidence {
                result = append(result, map[string]any{
                        "type":       e.Type,
                        "source":     e.Source,
                        "detail":     e.Detail,
                        "severity":   e.Severity,
                        "confidence": e.Confidence,
                })
        }
        return result
}

func convertEvidenceToMaps(result map[string]any) {}

func buildSummary(results map[string]any, evidence []Evidence) map[string]any {
        llms := results["llms_txt"].(map[string]any)
        robots := results["robots_txt"].(map[string]any)
        poisoning := results["poisoning"].(map[string]any)
        hidden := results["hidden_prompts"].(map[string]any)

        hasLLMS, _ := llms["found"].(bool)
        blocksAI, _ := robots["blocks_ai_crawlers"].(bool)
        allowsAI, _ := robots["allows_ai_crawlers"].(bool)
        iocCount := 0
        if v, ok := poisoning["ioc_count"].(int); ok {
                iocCount = v
        }
        hiddenCount := 0
        if v, ok := hidden["artifact_count"].(int); ok {
                hiddenCount = v
        }

        status := "info"
        message := "No significant AI surface findings"

        if iocCount > 0 || hiddenCount > 0 {
                status = "warning"
                message = "AI-related risks detected — review recommended"
        } else if hasLLMS || blocksAI {
                status = "success"
                message = "AI governance signals observed"
        } else if allowsAI {
                status = "info"
                message = "No AI governance measures detected"
        }

        return map[string]any{
                "status":          status,
                "message":         message,
                "has_llms_txt":    hasLLMS,
                "blocks_ai":       blocksAI,
                "allows_ai":       allowsAI,
                "poisoning_count": iocCount,
                "hidden_count":    hiddenCount,
                "total_evidence":  len(evidence),
        }
}
