// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "context"
        "fmt"
        "log/slog"
        "os/exec"
        "strings"
        "time"
)

func (a *Analyzer) AnalyzeNmapDNS(ctx context.Context, domain string) map[string]any {
        result := map[string]any{
                "status":           "info",
                "zone_transfer":    map[string]any{"vulnerable": false, "message": "Not tested"},
                "recursion":        map[string]any{"open": false, "message": "Not tested"},
                "nsid":             map[string]any{"found": false, "message": "Not tested"},
                "cache_snoop":      map[string]any{"vulnerable": false, "message": "Not tested"},
                "nameservers":      []string{},
                "issues":           []string{},
                "scan_duration_ms": 0,
        }

        if _, err := exec.LookPath("nmap"); err != nil {
                result["message"] = "Nmap not available"
                return result
        }

        nsRecords := a.DNS.QueryDNS(ctx, "NS", domain)
        if len(nsRecords) == 0 {
                result["message"] = "No nameservers found"
                return result
        }

        nameservers := make([]string, 0, len(nsRecords))
        for _, ns := range nsRecords {
                ns = strings.TrimSuffix(strings.TrimSpace(ns), ".")
                if ns != "" {
                        nameservers = append(nameservers, ns)
                }
        }
        result["nameservers"] = nameservers

        if len(nameservers) == 0 {
                result["message"] = "No valid nameservers"
                return result
        }

        scanStart := time.Now()
        issues := []string{}

        primaryNS := nameservers[0]

        zoneResult := a.nmapZoneTransfer(ctx, domain, primaryNS)
        result["zone_transfer"] = zoneResult
        if zoneResult["vulnerable"] == true {
                issues = append(issues, fmt.Sprintf("Zone transfer (AXFR) allowed on %s", primaryNS))
        }

        recursionResult := a.nmapRecursion(ctx, primaryNS)
        result["recursion"] = recursionResult
        if recursionResult["open"] == true {
                issues = append(issues, fmt.Sprintf("Open recursion detected on %s — potential DNS amplification risk", primaryNS))
        }

        nsidResult := a.nmapNSID(ctx, primaryNS)
        result["nsid"] = nsidResult

        cacheResult := a.nmapCacheSnoop(ctx, primaryNS)
        result["cache_snoop"] = cacheResult
        if cacheResult["vulnerable"] == true {
                issues = append(issues, fmt.Sprintf("DNS cache snooping possible on %s", primaryNS))
        }

        result["issues"] = issues
        result["scan_duration_ms"] = time.Since(scanStart).Milliseconds()

        if len(issues) > 0 {
                result["status"] = "warning"
                result["message"] = fmt.Sprintf("%d issue(s) found across %d nameserver(s)", len(issues), len(nameservers))
        } else {
                result["status"] = "good"
                result["message"] = fmt.Sprintf("No DNS server misconfigurations found on %s", primaryNS)
        }

        slog.Info("Nmap DNS scan completed", "domain", domain, "ns", primaryNS, "issues", len(issues), "elapsed_ms", time.Since(scanStart).Milliseconds())

        return result
}

func (a *Analyzer) nmapZoneTransfer(ctx context.Context, domain, ns string) map[string]any {
        result := map[string]any{
                "vulnerable":  false,
                "message":     "Zone transfer denied (correct configuration)",
                "nameserver":  ns,
                "record_count": 0,
        }

        output, err := runNmapScript(ctx, ns, "dns-zone-transfer", fmt.Sprintf("dns-zone-transfer.domain=%s", domain), 15*time.Second)
        if err != nil {
                result["message"] = "Test inconclusive"
                return result
        }

        if strings.Contains(output, "Transfer") || strings.Contains(output, "SOA") {
                lines := strings.Split(output, "\n")
                recordCount := 0
                for _, line := range lines {
                        trimmed := strings.TrimSpace(line)
                        if trimmed != "" && !strings.HasPrefix(trimmed, "|") && !strings.HasPrefix(trimmed, "Nmap") && !strings.HasPrefix(trimmed, "Starting") {
                                recordCount++
                        }
                }
                if recordCount > 3 {
                        result["vulnerable"] = true
                        result["message"] = fmt.Sprintf("Zone transfer allowed — %d records exposed", recordCount)
                        result["record_count"] = recordCount
                }
        }

        return result
}

func (a *Analyzer) nmapRecursion(ctx context.Context, ns string) map[string]any {
        result := map[string]any{
                "open":       false,
                "message":    "Recursion disabled (correct configuration)",
                "nameserver": ns,
        }

        output, err := runNmapScript(ctx, ns, "dns-recursion", "", 10*time.Second)
        if err != nil {
                result["message"] = "Test inconclusive"
                return result
        }

        if strings.Contains(strings.ToLower(output), "recursion") && strings.Contains(strings.ToLower(output), "enabled") {
                result["open"] = true
                result["message"] = "Recursive queries enabled — authoritative servers should disable recursion to prevent DNS amplification attacks (RFC 5358)"
        }

        return result
}

func (a *Analyzer) nmapNSID(ctx context.Context, ns string) map[string]any {
        result := map[string]any{
                "found":      false,
                "message":    "No nameserver identity information disclosed",
                "nameserver": ns,
                "version":    "",
                "id":         "",
        }

        output, err := runNmapScript(ctx, ns, "dns-nsid", "", 10*time.Second)
        if err != nil {
                result["message"] = "Test inconclusive"
                return result
        }

        lower := strings.ToLower(output)
        if strings.Contains(lower, "bind.version") || strings.Contains(lower, "id.server") || strings.Contains(lower, "nsid") {
                result["found"] = true
                result["message"] = "Nameserver identity information disclosed — consider restricting version queries"

                for _, line := range strings.Split(output, "\n") {
                        trimmed := strings.TrimSpace(line)
                        if strings.Contains(strings.ToLower(trimmed), "bind.version") {
                                parts := strings.SplitN(trimmed, ":", 2)
                                if len(parts) == 2 {
                                        result["version"] = strings.TrimSpace(parts[1])
                                }
                        }
                        if strings.Contains(strings.ToLower(trimmed), "id.server") {
                                parts := strings.SplitN(trimmed, ":", 2)
                                if len(parts) == 2 {
                                        result["id"] = strings.TrimSpace(parts[1])
                                }
                        }
                }
        }

        return result
}

func (a *Analyzer) nmapCacheSnoop(ctx context.Context, ns string) map[string]any {
        result := map[string]any{
                "vulnerable": false,
                "message":    "Cache snooping not possible (correct configuration)",
                "nameserver": ns,
        }

        output, err := runNmapScript(ctx, ns, "dns-cache-snoop", "", 10*time.Second)
        if err != nil {
                result["message"] = "Test inconclusive"
                return result
        }

        if strings.Contains(strings.ToLower(output), "positive") || (strings.Contains(strings.ToLower(output), "cache") && strings.Contains(strings.ToLower(output), "found")) {
                result["vulnerable"] = true
                result["message"] = "DNS cache snooping detected — attacker can determine which domains this server has recently resolved"
        }

        return result
}

func runNmapScript(ctx context.Context, target, script, args string, timeout time.Duration) (string, error) {
        cmdCtx, cancel := context.WithTimeout(ctx, timeout)
        defer cancel()

        cmdArgs := []string{"-sn", "-Pn", "-p", "53", "--script", script, target}
        if args != "" {
                cmdArgs = append(cmdArgs[:len(cmdArgs)-1], "--script-args", args, target)
                cmdArgs = cmdArgs[:len(cmdArgs)]
        }

        finalArgs := []string{"-sn", "-Pn", "-p", "53", "--script", script}
        if args != "" {
                finalArgs = append(finalArgs, "--script-args", args)
        }
        finalArgs = append(finalArgs, target)

        cmd := exec.CommandContext(cmdCtx, "nmap", finalArgs...)
        out, err := cmd.CombinedOutput()
        if err != nil {
                if cmdCtx.Err() == context.DeadlineExceeded {
                        return "", fmt.Errorf("nmap script %s timed out after %v", script, timeout)
                }
                return string(out), nil
        }

        return string(out), nil
}
