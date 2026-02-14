// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
package analyzer

import (
        "context"
        "crypto/tls"
        "fmt"
        "log/slog"
        "net"
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

func (a *Analyzer) AnalyzeSMTPTransport(ctx context.Context, domain string, mxRecords []string) map[string]any {
        result := buildEmptySMTPResult()

        mxHosts := extractMXHosts(mxRecords)
        if len(mxHosts) == 0 {
                result["status"] = "info"
                result["message"] = "No MX records found"
                return result
        }

        summary := &smtpSummary{TotalServers: len(mxHosts)}

        hostsToCheck := mxHosts
        if len(hostsToCheck) > 3 {
                hostsToCheck = hostsToCheck[:3]
        }

        servers := probeSMTPServers(ctx, hostsToCheck, summary)
        result["servers"] = servers
        result["summary"] = summaryToMap(summary)

        classifySMTPResult(result, summary)

        enrichWithDNSInference(result, summary, a, ctx, domain, mxHosts)

        return result
}

func buildEmptySMTPResult() map[string]any {
        return map[string]any{
                "status":  "warning",
                "message": "SMTP transport not verified",
                "servers": []map[string]any{},
                "summary": map[string]any{
                        "total_servers":      0,
                        "reachable":          0,
                        "starttls_supported": 0,
                        "tls_1_3":           0,
                        "tls_1_2":           0,
                        "valid_certs":       0,
                        "expiring_soon":     0,
                },
                "issues":        []string{},
                "dns_inferred":  false,
                "inference_note": nil,
        }
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

func classifySMTPResult(result map[string]any, summary *smtpSummary) {
        issues := getIssuesList(result)

        if summary.Reachable == 0 {
                result["status"] = "info"
                result["message"] = "Port 25 not reachable from this host"
                issues = append(issues, "SMTP port 25 may be blocked by hosting provider — this is common for cloud platforms")
                result["issues"] = issues
                return
        }

        if summary.StartTLSSupport == 0 {
                result["status"] = "error"
                result["message"] = "No mail servers support STARTTLS"
                issues = append(issues, "Mail is transmitted unencrypted — critical security issue")
                result["issues"] = issues
                return
        }

        if summary.StartTLSSupport < summary.Reachable {
                result["status"] = "warning"
                result["message"] = fmt.Sprintf("Only %d/%d servers support STARTTLS", summary.StartTLSSupport, summary.Reachable)
                issues = append(issues, "Some mail servers do not support encryption")
                result["issues"] = issues
                return
        }

        if summary.ValidCerts < summary.StartTLSSupport {
                result["status"] = "warning"
                result["message"] = fmt.Sprintf("STARTTLS supported but %d server(s) have certificate issues", summary.StartTLSSupport-summary.ValidCerts)
                issues = append(issues, "Some certificates failed validation")
                result["issues"] = issues
                return
        }

        var tlsVersions []string
        if summary.TLS13 > 0 {
                tlsVersions = append(tlsVersions, "TLS 1.3")
        }
        if summary.TLS12 > 0 {
                tlsVersions = append(tlsVersions, "TLS 1.2")
        }
        tlsStr := "TLS"
        if len(tlsVersions) > 0 {
                tlsStr = strings.Join(tlsVersions, "/")
        }
        result["status"] = "success"
        result["message"] = fmt.Sprintf("All %d server(s) support encrypted transport (%s)", summary.StartTLSSupport, tlsStr)

        if summary.ExpiringSoon > 0 {
                issues = append(issues, fmt.Sprintf("%d certificate(s) expiring within 30 days", summary.ExpiringSoon))
        }
        result["issues"] = issues
}

func enrichWithDNSInference(result map[string]any, summary *smtpSummary, a *Analyzer, ctx context.Context, domain string, mxHosts []string) {
        if summary.Reachable > 0 {
                return
        }

        slog.Info("Port 25 blocked, inferring transport security from DNS", "domain", domain)

        var signals []string

        mtaSts := a.AnalyzeMTASTS(ctx, domain)
        if mode, ok := mtaSts["mode"].(string); ok && mode == "enforce" {
                signals = append(signals, "MTA-STS policy in enforce mode requires encrypted transport")
        } else if mode == "testing" {
                signals = append(signals, "MTA-STS policy in testing mode (monitoring transport security)")
        }

        hasTLSA := false
        for _, host := range mxHosts {
                tlsaName := fmt.Sprintf("_25._tcp.%s", host)
                tlsaRecords := a.DNS.QueryDNS(ctx, "TLSA", tlsaName)
                if len(tlsaRecords) > 0 {
                        hasTLSA = true
                        break
                }
        }
        if hasTLSA {
                signals = append(signals, "DANE/TLSA records published — mail servers pin TLS certificates via DNSSEC")
        }

        tlsrpt := a.AnalyzeTLSRPT(ctx, domain)
        if st, ok := tlsrpt["status"].(string); ok && st == "success" {
                signals = append(signals, "TLS-RPT configured — domain monitors TLS delivery failures")
        }

        providerSignal := inferFromProvider(mxHosts)
        if providerSignal != "" {
                signals = append(signals, providerSignal)
        }

        if len(signals) > 0 {
                result["dns_inferred"] = true
                result["inference_note"] = "Direct SMTP probe unavailable (port 25 blocked). Transport security inferred from DNS policy records and provider capabilities."
                result["status"] = "inferred"
                result["message"] = fmt.Sprintf("Transport security inferred from %d DNS signal(s)", len(signals))
                result["inference_signals"] = signals
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
