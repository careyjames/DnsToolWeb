// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "context"
        "fmt"
        "log/slog"
        "strings"
        "time"

        "dnstool/go-server/internal/dnsclient"
)

type ExposureScanner struct {
        HTTP *dnsclient.SafeHTTPClient
}

type ExposureFinding struct {
        Path       string `json:"path"`
        Status     int    `json:"status"`
        Severity   string `json:"severity"`
        Category   string `json:"category"`
        Detail     string `json:"detail"`
        Risk       string `json:"risk"`
        Remediation string `json:"remediation"`
}

type exposureCheck struct {
        Path        string
        Category    string
        Severity    string
        Risk        string
        Remediation string
        SuccessOn   []int
        ContentCheck func(body string) bool
}

var exposureChecks = []exposureCheck{
        {
                Path:        "/.env",
                Category:    "Environment File",
                Severity:    "critical",
                Risk:        "May contain database credentials, API keys, and application secrets",
                Remediation: "Block access via web server config (deny all for dotfiles) or remove from web root",
                SuccessOn:   []int{200},
                ContentCheck: func(body string) bool {
                        lower := strings.ToLower(body)
                        return strings.Contains(lower, "db_") || strings.Contains(lower, "database") ||
                                strings.Contains(lower, "password") || strings.Contains(lower, "secret") ||
                                strings.Contains(lower, "api_key") || strings.Contains(lower, "app_key") ||
                                strings.Contains(lower, "=") && (strings.Contains(lower, "host") || strings.Contains(lower, "user"))
                },
        },
        {
                Path:        "/.git/config",
                Category:    "Git Repository",
                Severity:    "critical",
                Risk:        "Exposed .git directory allows full source code download including commit history",
                Remediation: "Block access to .git directory in web server config or remove from web root",
                SuccessOn:   []int{200},
                ContentCheck: func(body string) bool {
                        return strings.Contains(body, "[core]") || strings.Contains(body, "[remote")
                },
        },
        {
                Path:        "/.git/HEAD",
                Category:    "Git Repository",
                Severity:    "critical",
                Risk:        "Confirms .git directory exposure — full repository can likely be reconstructed",
                Remediation: "Block access to .git directory in web server config",
                SuccessOn:   []int{200},
                ContentCheck: func(body string) bool {
                        return strings.HasPrefix(strings.TrimSpace(body), "ref: refs/")
                },
        },
        {
                Path:        "/.DS_Store",
                Category:    "Directory Listing",
                Severity:    "medium",
                Risk:        "macOS directory metadata reveals internal file and folder names",
                Remediation: "Remove .DS_Store files from web root and add to .gitignore",
                SuccessOn:   []int{200},
                ContentCheck: func(body string) bool {
                        return len(body) > 4 && body[:4] == "\x00\x00\x00\x01"
                },
        },
        {
                Path:        "/server-status",
                Category:    "Server Info",
                Severity:    "high",
                Risk:        "Apache server-status page reveals active connections, client IPs, and request URLs",
                Remediation: "Restrict mod_status to localhost only or disable in production",
                SuccessOn:   []int{200},
                ContentCheck: func(body string) bool {
                        lower := strings.ToLower(body)
                        return strings.Contains(lower, "apache server status") || strings.Contains(lower, "server uptime")
                },
        },
        {
                Path:        "/server-info",
                Category:    "Server Info",
                Severity:    "high",
                Risk:        "Apache server-info page reveals module configuration, loaded modules, and compile settings",
                Remediation: "Restrict mod_info to localhost only or disable in production",
                SuccessOn:   []int{200},
                ContentCheck: func(body string) bool {
                        lower := strings.ToLower(body)
                        return strings.Contains(lower, "apache server information") || strings.Contains(lower, "server settings")
                },
        },
        {
                Path:        "/wp-config.php.bak",
                Category:    "Backup File",
                Severity:    "critical",
                Risk:        "WordPress config backup exposes database credentials and secret keys in plain text",
                Remediation: "Remove all backup files from web root; never store backups in publicly accessible directories",
                SuccessOn:   []int{200},
                ContentCheck: func(body string) bool {
                        return strings.Contains(body, "DB_NAME") || strings.Contains(body, "DB_PASSWORD") || strings.Contains(body, "wp-settings.php")
                },
        },
        {
                Path:        "/phpinfo.php",
                Category:    "Server Info",
                Severity:    "high",
                Risk:        "phpinfo() reveals PHP version, extensions, environment variables, and server paths",
                Remediation: "Remove phpinfo.php from production servers",
                SuccessOn:   []int{200},
                ContentCheck: func(body string) bool {
                        lower := strings.ToLower(body)
                        return strings.Contains(lower, "php version") || strings.Contains(lower, "phpinfo()")
                },
        },
}

func NewExposureScanner(httpClient *dnsclient.SafeHTTPClient) *ExposureScanner {
        return &ExposureScanner{HTTP: httpClient}
}

func (e *ExposureScanner) Scan(ctx context.Context, domain string) map[string]any {
        var findings []ExposureFinding
        var checkedPaths []string

        baseURL := ""
        for _, scheme := range []string{"https", "http"} {
                testURL := fmt.Sprintf("%s://%s/", scheme, domain)
                testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
                resp, err := e.HTTP.Get(testCtx, testURL)
                cancel()
                if err != nil {
                        continue
                }
                resp.Body.Close()
                if resp.StatusCode < 500 {
                        baseURL = fmt.Sprintf("%s://%s", scheme, domain)
                        break
                }
        }

        if baseURL == "" {
                return map[string]any{
                        "status":        "unreachable",
                        "message":       "Domain web server is not reachable",
                        "finding_count": 0,
                        "findings":      []map[string]any{},
                        "checked_paths": []string{},
                }
        }

        for _, check := range exposureChecks {
                select {
                case <-ctx.Done():
                        slog.Debug("exposure_scanner: context cancelled", "domain", domain)
                        break
                default:
                }

                fullURL := baseURL + check.Path
                checkedPaths = append(checkedPaths, check.Path)

                checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
                resp, err := e.HTTP.Get(checkCtx, fullURL)
                cancel()

                if err != nil {
                        slog.Debug("exposure_scanner: request failed", "path", check.Path, "error", err)
                        continue
                }

                statusCode := resp.StatusCode

                isExpected := false
                for _, code := range check.SuccessOn {
                        if statusCode == code {
                                isExpected = true
                                break
                        }
                }

                if !isExpected {
                        resp.Body.Close()
                        continue
                }

                body, err := e.HTTP.ReadBody(resp, 512*1024)
                if err != nil {
                        continue
                }
                bodyStr := string(body)

                if check.ContentCheck != nil && !check.ContentCheck(bodyStr) {
                        continue
                }

                finding := ExposureFinding{
                        Path:        check.Path,
                        Status:      statusCode,
                        Severity:    check.Severity,
                        Category:    check.Category,
                        Risk:        check.Risk,
                        Remediation: check.Remediation,
                }

                detail := fmt.Sprintf("HTTP %d response with matching content at %s", statusCode, check.Path)
                if check.ContentCheck != nil {
                        detail += " — content validated as genuine exposure"
                }
                finding.Detail = detail

                findings = append(findings, finding)

                time.Sleep(200 * time.Millisecond)
        }

        status := "clear"
        message := fmt.Sprintf("No well-known exposure paths detected (%d paths checked)", len(checkedPaths))
        if len(findings) > 0 {
                hasCritical := false
                for _, f := range findings {
                        if f.Severity == "critical" {
                                hasCritical = true
                                break
                        }
                }
                if hasCritical {
                        status = "critical"
                        message = fmt.Sprintf("%d critical exposure(s) found in well-known paths", len(findings))
                } else {
                        status = "exposed"
                        message = fmt.Sprintf("%d exposure(s) found in well-known paths", len(findings))
                }
        }

        findingsMaps := make([]map[string]any, len(findings))
        for i, f := range findings {
                findingsMaps[i] = map[string]any{
                        "path":        f.Path,
                        "status":      f.Status,
                        "severity":    f.Severity,
                        "category":    f.Category,
                        "detail":      f.Detail,
                        "risk":        f.Risk,
                        "remediation": f.Remediation,
                }
        }

        return map[string]any{
                "status":        status,
                "message":       message,
                "finding_count": len(findings),
                "findings":      findingsMaps,
                "checked_paths": checkedPaths,
        }
}

func (a *Analyzer) ScanWebExposure(ctx context.Context, domain string) map[string]any {
        scanner := NewExposureScanner(a.HTTP)
        return scanner.Scan(ctx, domain)
}
