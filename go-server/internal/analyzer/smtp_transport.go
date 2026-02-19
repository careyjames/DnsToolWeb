// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "bytes"
        "context"
        "crypto/tls"
        "encoding/json"
        "fmt"
        "io"
        "log/slog"
        "net"
        "net/http"
        "strings"
        "sync"
        "time"
)

type smtpServerResult struct {
        Host              string  `json:"host"`
        Reachable         bool    `json:"reachable"`
        StartTLS          bool    `json:"starttls"`
        TLSVersion        *string `json:"tls_version"`
        Cipher            *string `json:"cipher"`
        CipherBits        *int    `json:"cipher_bits"`
        CertValid         bool    `json:"cert_valid"`
        CertExpiry        *string `json:"cert_expiry"`
        CertDaysRemaining *int    `json:"cert_days_remaining"`
        CertIssuer        *string `json:"cert_issuer"`
        CertSubject       *string `json:"cert_subject"`
        Error             *string `json:"error"`
}

type smtpSummary struct {
        TotalServers     int `json:"total_servers"`
        Reachable        int `json:"reachable"`
        StartTLSSupport  int `json:"starttls_supported"`
        TLS13            int `json:"tls_1_3"`
        TLS12            int `json:"tls_1_2"`
        ValidCerts       int `json:"valid_certs"`
        ExpiringSoon     int `json:"expiring_soon"`
}

type AnalysisInputs struct {
        MTASTSResult map[string]any
        TLSRPTResult map[string]any
        DANEResult   map[string]any
}

func (a *Analyzer) AnalyzeSMTPTransport(ctx context.Context, domain string, mxRecords []string, inputs ...AnalysisInputs) map[string]any {
        var ai AnalysisInputs
        if len(inputs) > 0 {
                ai = inputs[0]
        }

        mxHosts := extractMXHosts(mxRecords)

        result := buildMailTransportResult(a, ctx, domain, mxHosts, ai)

        return result
}

func buildMailTransportResult(a *Analyzer, ctx context.Context, domain string, mxHosts []string, ai AnalysisInputs) map[string]any {
        result := map[string]any{
                "version": 2,
        }

        policy := buildPolicyAssessment(a, ctx, domain, mxHosts, ai)
        result["policy"] = policy

        telemetrySection := buildTelemetrySection(ai)
        result["telemetry"] = telemetrySection

        probe := buildProbeResult(a, ctx, domain, mxHosts)
        result["probe"] = probe

        result["status"] = derivePrimaryStatus(policy, probe)
        result["message"] = derivePrimaryMessage(policy, probe, mxHosts)

        result["dns_inferred"] = true
        result["inference_note"] = buildInferenceNote(probe)
        result["inference_signals"] = buildInferenceSignals(policy, telemetrySection)

        backfillLegacyFields(result, policy, probe)

        return result
}

func buildPolicyAssessment(a *Analyzer, ctx context.Context, domain string, mxHosts []string, ai AnalysisInputs) map[string]any {
        policy := map[string]any{
                "mta_sts":  map[string]any{"present": false, "mode": "none"},
                "dane":     map[string]any{"present": false},
                "tlsrpt":   map[string]any{"present": false},
                "provider": map[string]any{"identified": false},
                "verdict":  "none",
                "signals":  []string{},
        }

        var signals []string

        mtaSts := ai.MTASTSResult
        if mtaSts == nil {
                mtaSts = a.AnalyzeMTASTS(ctx, domain)
        }
        if mode, ok := mtaSts["mode"].(string); ok && mode != "" && mode != "none" {
                policy["mta_sts"] = map[string]any{
                        "present": true,
                        "mode":    mode,
                        "status":  mapGetStrSafe(mtaSts, "status"),
                }
                if mode == "enforce" {
                        signals = append(signals, "MTA-STS policy in enforce mode requires encrypted transport (RFC 8461)")
                } else if mode == "testing" {
                        signals = append(signals, "MTA-STS policy in testing mode — monitoring transport security (RFC 8461)")
                }
        }

        hasTLSA := false
        daneResult := ai.DANEResult
        if daneResult != nil {
                if hasDane, ok := daneResult["has_dane"].(bool); ok && hasDane {
                        hasTLSA = true
                }
        }
        if !hasTLSA {
                for _, host := range mxHosts {
                        tlsaName := fmt.Sprintf("_25._tcp.%s", host)
                        tlsaRecords := a.DNS.QueryDNS(ctx, "TLSA", tlsaName)
                        if len(tlsaRecords) > 0 {
                                hasTLSA = true
                                break
                        }
                }
        }
        if hasTLSA {
                policy["dane"] = map[string]any{"present": true}
                signals = append(signals, "DANE/TLSA records published — mail servers pin TLS certificates via DNSSEC (RFC 7672)")
        }

        tlsrpt := ai.TLSRPTResult
        if tlsrpt == nil {
                tlsrpt = a.AnalyzeTLSRPT(ctx, domain)
        }
        if st, ok := tlsrpt["status"].(string); ok && st == "success" {
                policy["tlsrpt"] = map[string]any{
                        "present": true,
                        "status":  st,
                }
                signals = append(signals, "TLS-RPT configured — domain monitors TLS delivery failures (RFC 8460)")
        }

        providerSignal := inferFromProvider(mxHosts)
        if providerSignal != "" {
                providerName := identifyProviderName(mxHosts)
                policy["provider"] = map[string]any{
                        "identified": true,
                        "name":       providerName,
                }
                signals = append(signals, providerSignal)
        }

        policy["signals"] = signals

        mtaStsMeta, _ := policy["mta_sts"].(map[string]any)
        mtaStsPresent, _ := mtaStsMeta["present"].(bool)
        mtaStsMode, _ := mtaStsMeta["mode"].(string)
        daneMeta, _ := policy["dane"].(map[string]any)
        danePresent, _ := daneMeta["present"].(bool)

        if mtaStsPresent && mtaStsMode == "enforce" && danePresent {
                policy["verdict"] = "enforced"
        } else if mtaStsPresent && mtaStsMode == "enforce" {
                policy["verdict"] = "enforced"
        } else if danePresent {
                policy["verdict"] = "enforced"
        } else if mtaStsPresent && mtaStsMode == "testing" {
                policy["verdict"] = "monitored"
        } else if len(signals) > 0 {
                policy["verdict"] = "opportunistic"
        } else {
                policy["verdict"] = "none"
        }

        return policy
}

func buildTelemetrySection(ai AnalysisInputs) map[string]any {
        section := map[string]any{
                "tlsrpt_configured": false,
                "reporting_uris":    []string{},
                "observability":     false,
        }

        tlsrpt := ai.TLSRPTResult
        if tlsrpt == nil {
                return section
        }

        if st, ok := tlsrpt["status"].(string); ok && st == "success" {
                section["tlsrpt_configured"] = true
                section["observability"] = true

                if record, ok := tlsrpt["record"].(string); ok && record != "" {
                        uris := extractTLSRPTURIs(record)
                        if len(uris) > 0 {
                                section["reporting_uris"] = uris
                        }
                }
        }

        return section
}

func extractTLSRPTURIs(record string) []string {
        var uris []string
        parts := strings.Split(record, ";")
        for _, part := range parts {
                part = strings.TrimSpace(part)
                if strings.HasPrefix(part, "rua=") {
                        rua := strings.TrimPrefix(part, "rua=")
                        for _, uri := range strings.Split(rua, ",") {
                                uri = strings.TrimSpace(uri)
                                if uri != "" {
                                        uris = append(uris, uri)
                                }
                        }
                }
        }
        return uris
}

func buildProbeResult(a *Analyzer, ctx context.Context, domain string, mxHosts []string) map[string]any {
        probe := map[string]any{
                "status":       "skipped",
                "reason":       "",
                "observations": []map[string]any{},
        }

        if len(mxHosts) == 0 {
                probe["reason"] = "No MX records found for this domain"
                return probe
        }

        if a.SMTPProbeMode == "skip" || a.SMTPProbeMode == "" {
                probe["reason"] = "SMTP probe skipped — outbound TCP port 25 is blocked by cloud hosting provider. This is standard for all major cloud platforms (AWS, GCP, Azure, Replit) as an anti-spam measure. Transport security is assessed via DNS policy records above, which is the standards-aligned primary method per NIST SP 800-177 Rev. 1."
                slog.Info("SMTP probe skipped (mode=skip)", "domain", domain)
                return probe
        }

        if a.SMTPProbeMode == "remote" && a.ProbeAPIURL != "" {
                return runRemoteProbe(ctx, a.ProbeAPIURL, mxHosts, probe)
        }

        if a.SMTPProbeMode == "force" || a.SMTPProbeMode == "remote" {
                return runLiveProbe(ctx, mxHosts, probe)
        }

        return probe
}

func runRemoteProbe(ctx context.Context, apiURL string, mxHosts []string, probe map[string]any) map[string]any {
        hostsToCheck := mxHosts
        if len(hostsToCheck) > 5 {
                hostsToCheck = hostsToCheck[:5]
        }

        reqBody, err := json.Marshal(map[string]any{"hosts": hostsToCheck})
        if err != nil {
                slog.Error("Remote probe: failed to marshal request", "error", err)
                return runLiveProbe(ctx, mxHosts, probe)
        }

        probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
        defer cancel()

        req, err := http.NewRequestWithContext(probeCtx, "POST", apiURL+"/probe/smtp", bytes.NewReader(reqBody))
        if err != nil {
                slog.Error("Remote probe: failed to create request", "error", err)
                return runLiveProbe(ctx, mxHosts, probe)
        }
        req.Header.Set("Content-Type", "application/json")

        resp, err := http.DefaultClient.Do(req)
        if err != nil {
                slog.Warn("Remote probe: request failed, falling back to local", "error", err)
                return runLiveProbe(ctx, mxHosts, probe)
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
                slog.Warn("Remote probe: non-200 response, falling back to local", "status", resp.StatusCode)
                return runLiveProbe(ctx, mxHosts, probe)
        }

        body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
        if err != nil {
                slog.Warn("Remote probe: failed to read response, falling back to local", "error", err)
                return runLiveProbe(ctx, mxHosts, probe)
        }

        var apiResp struct {
                ProbeHost      string           `json:"probe_host"`
                ElapsedSeconds float64          `json:"elapsed_seconds"`
                Servers        []map[string]any `json:"servers"`
        }
        if err := json.Unmarshal(body, &apiResp); err != nil {
                slog.Warn("Remote probe: failed to parse response, falling back to local", "error", err)
                return runLiveProbe(ctx, mxHosts, probe)
        }

        if len(apiResp.Servers) == 0 {
                slog.Warn("Remote probe: no servers in response, falling back to local")
                return runLiveProbe(ctx, mxHosts, probe)
        }

        summary := &smtpSummary{TotalServers: len(apiResp.Servers)}
        for _, srv := range apiResp.Servers {
                updateSummary(summary, srv)
        }

        reachable := summary.Reachable
        if reachable == 0 {
                probe["status"] = "skipped"
                probe["reason"] = "SMTP port 25 not reachable from probe host — transport security assessed via DNS policy records."
                return probe
        }

        probe["status"] = "observed"
        probe["reason"] = ""
        probe["observations"] = apiResp.Servers
        probe["summary"] = summaryToMap(summary)
        probe["probe_host"] = apiResp.ProbeHost
        probe["probe_elapsed"] = apiResp.ElapsedSeconds

        if summary.StartTLSSupport == reachable && summary.ValidCerts == summary.StartTLSSupport {
                probe["probe_verdict"] = "all_tls"
        } else if summary.StartTLSSupport > 0 {
                probe["probe_verdict"] = "partial_tls"
        } else {
                probe["probe_verdict"] = "no_tls"
        }

        slog.Info("Remote SMTP probe completed",
                "probe_host", apiResp.ProbeHost,
                "servers", len(apiResp.Servers),
                "reachable", reachable,
                "starttls", summary.StartTLSSupport,
                "elapsed", apiResp.ElapsedSeconds,
        )

        return probe
}

func runLiveProbe(ctx context.Context, mxHosts []string, probe map[string]any) map[string]any {
        hostsToCheck := mxHosts
        if len(hostsToCheck) > 3 {
                hostsToCheck = hostsToCheck[:3]
        }

        summary := &smtpSummary{TotalServers: len(hostsToCheck)}
        servers := probeSMTPServers(ctx, hostsToCheck, summary)

        if summary.Reachable == 0 {
                probe["status"] = "skipped"
                probe["reason"] = "SMTP port 25 not reachable from this host — outbound port 25 is likely blocked by the hosting provider. Transport security is assessed via DNS policy records, which is the standards-aligned primary method per NIST SP 800-177 Rev. 1."
                return probe
        }

        probe["status"] = "observed"
        probe["reason"] = ""
        probe["observations"] = servers
        probe["summary"] = summaryToMap(summary)

        if summary.StartTLSSupport == summary.Reachable && summary.ValidCerts == summary.StartTLSSupport {
                probe["probe_verdict"] = "all_tls"
        } else if summary.StartTLSSupport > 0 {
                probe["probe_verdict"] = "partial_tls"
        } else {
                probe["probe_verdict"] = "no_tls"
        }

        return probe
}

func derivePrimaryStatus(policy, probe map[string]any) string {
        verdict, _ := policy["verdict"].(string)
        probeStatus, _ := probe["status"].(string)

        if probeStatus == "observed" {
                probeVerdict, _ := probe["probe_verdict"].(string)
                if probeVerdict == "all_tls" && (verdict == "enforced" || verdict == "monitored") {
                        return "success"
                }
                if probeVerdict == "all_tls" {
                        return "success"
                }
                if probeVerdict == "partial_tls" {
                        return "warning"
                }
                return "error"
        }

        switch verdict {
        case "enforced":
                return "success"
        case "monitored":
                return "info"
        case "opportunistic":
                return "inferred"
        default:
                return "info"
        }
}

func derivePrimaryMessage(policy, probe map[string]any, mxHosts []string) string {
        verdict, _ := policy["verdict"].(string)
        probeStatus, _ := probe["status"].(string)
        signals, _ := policy["signals"].([]string)

        if len(mxHosts) == 0 {
                return "No MX records found"
        }

        if probeStatus == "observed" {
                probeSummary, _ := probe["summary"].(map[string]any)
                if probeSummary != nil {
                        reachable := int(toFloat64Val(probeSummary["reachable"]))
                        starttls := int(toFloat64Val(probeSummary["starttls_supported"]))
                        if starttls == reachable && reachable > 0 {
                                return fmt.Sprintf("All %d server(s) verified: encrypted transport confirmed via direct SMTP probe and DNS policy", reachable)
                        }
                        return fmt.Sprintf("%d/%d servers support STARTTLS (direct probe)", starttls, reachable)
                }
        }

        switch verdict {
        case "enforced":
                return fmt.Sprintf("Transport encryption enforced via DNS policy (%d signal(s))", len(signals))
        case "monitored":
                return fmt.Sprintf("Transport security in monitoring mode (%d signal(s))", len(signals))
        case "opportunistic":
                return fmt.Sprintf("Transport security inferred from %d signal(s) — no enforcement policy active", len(signals))
        default:
                return "No transport encryption policy detected — mail delivery relies on opportunistic TLS"
        }
}

func buildInferenceNote(probe map[string]any) string {
        probeStatus, _ := probe["status"].(string)
        if probeStatus == "observed" {
                return ""
        }
        return "Transport security assessed via DNS policy records (MTA-STS, DANE, TLS-RPT) — the standards-aligned primary method per NIST SP 800-177 Rev. 1 and RFC 8461. Direct SMTP probing is a supplementary verification step."
}

func buildInferenceSignals(policy, telemetrySection map[string]any) []string {
        signals, _ := policy["signals"].([]string)
        result := make([]string, len(signals))
        copy(result, signals)

        if configured, ok := telemetrySection["tlsrpt_configured"].(bool); ok && configured {
                hasTLSRPTSignal := false
                for _, s := range result {
                        if strings.Contains(s, "TLS-RPT") {
                                hasTLSRPTSignal = true
                                break
                        }
                }
                if !hasTLSRPTSignal {
                        result = append(result, "TLS-RPT configured — domain monitors TLS delivery failures (RFC 8460)")
                }
        }

        return result
}

func backfillLegacyFields(result map[string]any, policy, probe map[string]any) {
        probeStatus, _ := probe["status"].(string)

        if probeStatus == "observed" {
                observations, _ := probe["observations"].([]map[string]any)
                result["servers"] = observations
                if probeSummary, ok := probe["summary"].(map[string]any); ok {
                        result["summary"] = probeSummary
                } else {
                        result["summary"] = emptyLegacySummary()
                }
        } else {
                result["servers"] = []map[string]any{}
                result["summary"] = emptyLegacySummary()
        }

        result["issues"] = []string{}
}

func emptyLegacySummary() map[string]any {
        return map[string]any{
                "total_servers":      0,
                "reachable":          0,
                "starttls_supported": 0,
                "tls_1_3":           0,
                "tls_1_2":           0,
                "valid_certs":       0,
                "expiring_soon":     0,
        }
}

func identifyProviderName(mxHosts []string) string {
        providerNames := map[string]string{
                "google.com":         "Google Workspace",
                "googlemail.com":     "Google Workspace",
                "outlook.com":        "Microsoft 365",
                "protection.outlook": "Microsoft 365",
                "pphosted.com":       "Proofpoint",
                "mimecast.com":       "Mimecast",
                "messagelabs.com":    "Broadcom/Symantec",
                "fireeyecloud.com":   "Trellix",
                "iphmx.com":          "Cisco Email Security",
                "protonmail.ch":      "Proton Mail",
                "registrar-servers":  "Namecheap",
        }

        for _, host := range mxHosts {
                hostLower := strings.ToLower(host)
                for pattern, name := range providerNames {
                        if strings.Contains(hostLower, pattern) {
                                return name
                        }
                }
        }
        return ""
}

func mapGetStrSafe(m map[string]any, key string) string {
        if m == nil {
                return ""
        }
        v, ok := m[key].(string)
        if !ok {
                return ""
        }
        return v
}

func toFloat64Val(v any) float64 {
        switch n := v.(type) {
        case float64:
                return n
        case int:
                return float64(n)
        case int64:
                return float64(n)
        }
        return 0
}

func probeSMTPServers(ctx context.Context, hosts []string, summary *smtpSummary) []map[string]any {
        var (
                mu      sync.Mutex
                wg      sync.WaitGroup
                servers []map[string]any
        )

        for _, host := range hosts {
                wg.Add(1)
                go func(h string) {
                        defer wg.Done()
                        sr := probeSingleSMTPServer(ctx, h)
                        mu.Lock()
                        servers = append(servers, sr)
                        updateSummary(summary, sr)
                        mu.Unlock()
                }(host)
        }
        wg.Wait()
        return servers
}

func probeSingleSMTPServer(ctx context.Context, host string) map[string]any {
        result := map[string]any{
                "host":                host,
                "reachable":           false,
                "starttls":            false,
                "tls_version":         nil,
                "cipher":              nil,
                "cipher_bits":         nil,
                "cert_valid":          false,
                "cert_expiry":         nil,
                "cert_days_remaining": nil,
                "cert_issuer":         nil,
                "cert_subject":        nil,
                "error":               nil,
        }

        probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
        defer cancel()

        conn, err := dialSMTP(probeCtx, host)
        if err != nil {
                errStr := classifySMTPError(err)
                result["error"] = errStr
                return result
        }
        defer conn.Close()

        result["reachable"] = true

        banner, err := readSMTPResponse(conn, 2*time.Second)
        if err != nil || !strings.HasPrefix(banner, "220") {
                errStr := "Unexpected SMTP banner"
                result["error"] = errStr
                return result
        }

        _, err = fmt.Fprintf(conn, "EHLO dnstool.local\r\n")
        if err != nil {
                errStr := "EHLO failed"
                result["error"] = errStr
                return result
        }

        ehloResp, err := readSMTPResponse(conn, 2*time.Second)
        if err != nil {
                errStr := "EHLO response timeout"
                result["error"] = errStr
                return result
        }

        if !strings.Contains(strings.ToUpper(ehloResp), "STARTTLS") {
                errStr := "STARTTLS not supported"
                result["error"] = errStr
                return result
        }

        result["starttls"] = true

        _, err = fmt.Fprintf(conn, "STARTTLS\r\n")
        if err != nil {
                errStr := "STARTTLS command failed"
                result["error"] = errStr
                return result
        }

        starttlsResp, err := readSMTPResponse(conn, 2*time.Second)
        if err != nil || !strings.HasPrefix(starttlsResp, "220") {
                errStr := fmt.Sprintf("STARTTLS rejected: %s", truncate(starttlsResp, 50))
                result["error"] = errStr
                return result
        }

        negotiateTLS(conn, host, result)

        return result
}

func negotiateTLS(conn net.Conn, host string, result map[string]any) {
        tlsCfg := &tls.Config{ //nolint:gosec // Intentional: diagnostic tool must connect to servers with self-signed/expired/mismatched certs to inspect and report on their TLS configuration. Certificate validation is performed separately in verifyCert().
                ServerName:         host,
                InsecureSkipVerify: true, //NOSONAR — S4830/S5527: deliberate diagnostic probe; verifyCert() validates independently
        }
        tlsConn := tls.Client(conn, tlsCfg)
        defer tlsConn.Close()

        if err := tlsConn.Handshake(); err != nil {
                errStr := fmt.Sprintf("TLS handshake failed: %s", truncate(err.Error(), 80))
                result["error"] = errStr
                return
        }

        state := tlsConn.ConnectionState()
        tlsVer := tlsVersionString(state.Version)
        result["tls_version"] = tlsVer

        cipherName := tls.CipherSuiteName(state.CipherSuite)
        result["cipher"] = cipherName

        bits := cipherBits(state.CipherSuite)
        result["cipher_bits"] = bits

        verifyCert(host, result)
}

func verifyCert(host string, result map[string]any) {
        verifyCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
        defer cancel()

        dialer := &net.Dialer{Timeout: 2 * time.Second}
        verifyConn, err := dialSMTPWithDialer(verifyCtx, dialer, host)
        if err != nil {
                return
        }
        defer verifyConn.Close()

        banner, _ := readSMTPResponse(verifyConn, 1*time.Second)
        if !strings.HasPrefix(banner, "220") {
                return
        }
        fmt.Fprintf(verifyConn, "EHLO dnstool.local\r\n")
        readSMTPResponse(verifyConn, 1*time.Second)
        fmt.Fprintf(verifyConn, "STARTTLS\r\n")
        resp, _ := readSMTPResponse(verifyConn, 1*time.Second)
        if !strings.HasPrefix(resp, "220") {
                return
        }

        verifyCfg := &tls.Config{ServerName: host}
        verifyTLS := tls.Client(verifyConn, verifyCfg)
        defer verifyTLS.Close()

        if err := verifyTLS.Handshake(); err != nil {
                result["cert_valid"] = false
                errStr := fmt.Sprintf("Certificate invalid: %s", truncate(err.Error(), 100))
                result["error"] = errStr
                return
        }

        result["cert_valid"] = true
        certs := verifyTLS.ConnectionState().PeerCertificates
        if len(certs) > 0 {
                leaf := certs[0]
                expiry := leaf.NotAfter.Format("2006-01-02")
                result["cert_expiry"] = expiry
                daysRemaining := int(time.Until(leaf.NotAfter).Hours() / 24)
                result["cert_days_remaining"] = daysRemaining
                result["cert_subject"] = leaf.Subject.CommonName
                if leaf.Issuer.Organization != nil && len(leaf.Issuer.Organization) > 0 {
                        result["cert_issuer"] = leaf.Issuer.Organization[0]
                } else {
                        result["cert_issuer"] = leaf.Issuer.CommonName
                }
        }
}

func dialSMTP(ctx context.Context, host string) (net.Conn, error) {
        dialer := &net.Dialer{Timeout: 2 * time.Second}
        return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "25"))
}

func dialSMTPWithDialer(ctx context.Context, dialer *net.Dialer, host string) (net.Conn, error) {
        return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "25"))
}

func readSMTPResponse(conn net.Conn, timeout time.Duration) (string, error) {
        conn.SetReadDeadline(time.Now().Add(timeout))
        buf := make([]byte, 4096)
        var response strings.Builder
        for {
                n, err := conn.Read(buf)
                if n > 0 {
                        response.Write(buf[:n])
                        if smtpResponseComplete(response.String()) {
                                break
                        }
                }
                if err != nil {
                        return handlePartialResponse(response, err)
                }
        }
        return response.String(), nil
}

func smtpResponseComplete(data string) bool {
        lines := strings.Split(data, "\n")
        lastLine := strings.TrimSpace(lines[len(lines)-1])
        if lastLine == "" && len(lines) > 1 {
                lastLine = strings.TrimSpace(lines[len(lines)-2])
        }
        return len(lastLine) >= 4 && lastLine[3] == ' '
}

func handlePartialResponse(response strings.Builder, err error) (string, error) {
        if response.Len() > 0 {
                return response.String(), nil
        }
        return "", err
}

func classifySMTPError(err error) string {
        errStr := err.Error()
        if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
                return "Connection timeout"
        }
        if strings.Contains(errStr, "refused") {
                return "Connection refused"
        }
        if strings.Contains(errStr, "unreachable") {
                return "Network unreachable"
        }
        if strings.Contains(errStr, "no such host") {
                return "DNS resolution failed"
        }
        return truncate(errStr, 80)
}

func tlsVersionString(v uint16) string {
        switch v {
        case tls.VersionTLS13:
                return "TLSv1.3"
        case tls.VersionTLS12:
                return "TLSv1.2"
        case tls.VersionTLS11:
                return "TLSv1.1"
        case tls.VersionTLS10:
                return "TLSv1.0"
        default:
                return fmt.Sprintf("TLS 0x%04x", v)
        }
}

func cipherBits(suite uint16) int {
        name := tls.CipherSuiteName(suite)
        if strings.Contains(name, "256") || strings.Contains(name, "CHACHA20") {
                return 256
        }
        if strings.Contains(name, "128") {
                return 128
        }
        return 0
}

func truncate(s string, maxLen int) string {
        if len(s) <= maxLen {
                return s
        }
        return s[:maxLen]
}

func updateSummary(s *smtpSummary, sr map[string]any) {
        if sr["reachable"] == true {
                s.Reachable++
        }
        if sr["starttls"] == true {
                s.StartTLSSupport++
        }
        if v, ok := sr["tls_version"].(string); ok {
                if v == "TLSv1.3" {
                        s.TLS13++
                } else if v == "TLSv1.2" {
                        s.TLS12++
                }
        }
        if sr["cert_valid"] == true {
                s.ValidCerts++
        }
        if dr, ok := sr["cert_days_remaining"].(int); ok && dr < 30 {
                s.ExpiringSoon++
        }
}

func summaryToMap(s *smtpSummary) map[string]any {
        return map[string]any{
                "total_servers":      s.TotalServers,
                "reachable":          s.Reachable,
                "starttls_supported": s.StartTLSSupport,
                "tls_1_3":           s.TLS13,
                "tls_1_2":           s.TLS12,
                "valid_certs":       s.ValidCerts,
                "expiring_soon":     s.ExpiringSoon,
        }
}

func inferFromProvider(mxHosts []string) string {
        providerMap := map[string]string{
                "google.com":          "Google Workspace enforces TLS 1.2+ with valid certificates on all inbound/outbound mail",
                "googlemail.com":      "Google Workspace enforces TLS 1.2+ with valid certificates on all inbound/outbound mail",
                "outlook.com":         "Microsoft 365 enforces TLS 1.2+ with DANE (GA Oct 2024) and valid certificates",
                "protection.outlook":  "Microsoft 365 enforces TLS 1.2+ with DANE (GA Oct 2024) and valid certificates",
                "pphosted.com":        "Proofpoint enforces TLS on managed mail transport",
                "mimecast.com":        "Mimecast enforces TLS on managed mail transport",
                "messagelabs.com":     "Broadcom/Symantec Email Security enforces TLS",
                "fireeyecloud.com":    "Trellix Email Security enforces TLS",
                "iphmx.com":           "Cisco Email Security enforces TLS",
                "protonmail.ch":       "Proton Mail enforces TLS 1.2+ with DANE support",
                "registrar-servers":   "Namecheap mail service supports TLS",
        }

        for _, host := range mxHosts {
                hostLower := strings.ToLower(host)
                for pattern, description := range providerMap {
                        if strings.Contains(hostLower, pattern) {
                                return description
                        }
                }
        }
        return ""
}

func getIssuesList(result map[string]any) []string {
        if issues, ok := result["issues"].([]string); ok {
                return issues
        }
        return []string{}
}
