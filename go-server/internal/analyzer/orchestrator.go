// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
package analyzer

import (
        "context"
        "fmt"
        "log/slog"
        "strings"
        "sync"
        "time"
)

const (
        msgDomainNotExist = "Domain does not exist or is not delegated"
)

type namedResult struct {
        key     string
        result  any
        elapsed time.Duration
}

func (a *Analyzer) AnalyzeDomain(ctx context.Context, domain string, customDKIMSelectors []string) map[string]any {
        select {
        case a.semaphore <- struct{}{}:
                defer func() { <-a.semaphore }()
        case <-time.After(10 * time.Second):
                slog.Warn("Backpressure: rejected analysis", "domain", domain)
                return map[string]any{
                        "domain":           domain,
                        "error":            "System is currently at capacity. Please try again in a moment.",
                        "analysis_success": false,
                }
        }

        ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
        defer cancel()

        exists, domainStatus, domainStatusMessage := a.checkDomainExists(ctx, domain)
        if !exists {
                return a.buildNonExistentResult(domain, domainStatus, domainStatusMessage)
        }

        analysisStart := time.Now()
        resultsMap := a.runParallelAnalyses(ctx, domain, customDKIMSelectors)

        parallelElapsed := time.Since(analysisStart).Seconds()
        slog.Info("Parallel lookups completed", "domain", domain, "elapsed_s", fmt.Sprintf("%.2f", parallelElapsed), "tasks", len(resultsMap))

        basic := getMapResult(resultsMap, "basic")
        auth := getMapResult(resultsMap, "auth")

        resolverTTL := extractAndRemove(basic, "_ttl")
        authTTL := extractAndRemove(auth, "_ttl")
        authQueryStatus := extractAndRemove(auth, "_query_status")

        mxForDANE, _ := basic["MX"].([]string)

        daneStart := time.Now()
        resultsMap["dane"] = a.AnalyzeDANE(ctx, domain, mxForDANE)
        slog.Info("Task completed", "task", "dane", "domain", domain, "elapsed_ms", fmt.Sprintf("%.0f", float64(time.Since(daneStart).Milliseconds())))

        smtpStart := time.Now()
        smtpResult := a.AnalyzeSMTPTransport(ctx, domain, mxForDANE)
        slog.Info("Task completed", "task", "smtp_transport", "domain", domain, "elapsed_ms", fmt.Sprintf("%.0f", float64(time.Since(smtpStart).Milliseconds())))

        enrichBasicRecords(basic, resultsMap)
        propagationStatus := buildPropagationStatus(basic, auth)
        sectionStatus := buildSectionStatus(resultsMap)
        spfAnalysis := getMapResult(resultsMap, "spf")

        results := map[string]any{
                "domain":                 domain,
                "domain_exists":          true,
                "domain_status":          domainStatus,
                "domain_status_message":  derefStr(domainStatusMessage),
                "section_status":         sectionStatus,
                "basic_records":          basic,
                "authoritative_records":  auth,
                "auth_query_status":      authQueryStatus,
                "resolver_ttl":           resolverTTL,
                "auth_ttl":               authTTL,
                "propagation_status":     propagationStatus,
                "spf_analysis":           getOrDefault(resultsMap, "spf", map[string]any{"status": "error"}),
                "dmarc_analysis":         getOrDefault(resultsMap, "dmarc", map[string]any{"status": "error"}),
                "dkim_analysis":          getOrDefault(resultsMap, "dkim", map[string]any{"status": "error"}),
                "mta_sts_analysis":       getOrDefault(resultsMap, "mta_sts", map[string]any{"status": "warning"}),
                "tlsrpt_analysis":        getOrDefault(resultsMap, "tlsrpt", map[string]any{"status": "warning"}),
                "bimi_analysis":          getOrDefault(resultsMap, "bimi", map[string]any{"status": "warning"}),
                "dane_analysis":          getOrDefault(resultsMap, "dane", map[string]any{"status": "info", "has_dane": false, "tlsa_records": []any{}, "issues": []string{}}),
                "caa_analysis":           getOrDefault(resultsMap, "caa", map[string]any{"status": "warning"}),
                "dnssec_analysis":        getOrDefault(resultsMap, "dnssec", map[string]any{"status": "warning"}),
                "ns_delegation_analysis": getOrDefault(resultsMap, "ns_delegation", map[string]any{"status": "warning"}),
                "registrar_info":         getOrDefault(resultsMap, "registrar", map[string]any{"status": "error", "registrar": nil}),
                "resolver_consensus":     getOrDefault(resultsMap, "resolver_consensus", map[string]any{}),
                "ct_subdomains":          getOrDefault(resultsMap, "ct_subdomains", map[string]any{"status": "error", "subdomains": []any{}, "unique_subdomains": 0}),
                "has_null_mx":            detectNullMX(basic),
                "is_no_mail_domain":      spfAnalysis["no_mail_intent"] == true,
        }

        results["smtp_transport"] = smtpResult

        results["hosting_summary"] = a.GetHostingInfo(ctx, domain, results)
        results["dns_infrastructure"] = a.AnalyzeDNSInfrastructure(domain, results)
        results["email_security_mgmt"] = a.DetectEmailSecurityManagement(
                spfAnalysis,
                getMapResult(resultsMap, "dmarc"),
                getMapResult(resultsMap, "tlsrpt"),
                getMapResult(resultsMap, "mta_sts"),
                domain,
                getMapResult(resultsMap, "dkim"),
        )

        results["dmarc_report_auth"] = a.ValidateDMARCExternalAuth(ctx, domain, getMapResult(resultsMap, "dmarc"))

        results["https_svcb"] = getOrDefault(resultsMap, "https_svcb", map[string]any{"status": "info", "has_https": false, "has_svcb": false})
        results["cds_cdnskey"] = getOrDefault(resultsMap, "cds_cdnskey", map[string]any{"status": "info", "has_cds": false, "has_cdnskey": false})
        results["smimea_openpgpkey"] = getOrDefault(resultsMap, "smimea_openpgpkey", map[string]any{"status": "info", "has_smimea": false, "has_openpgpkey": false})
        results["security_txt"] = getOrDefault(resultsMap, "security_txt", map[string]any{"status": "info", "found": false, "message": "Not checked", "contacts": []string{}, "issues": []string{}})
        results["ai_surface"] = getOrDefault(resultsMap, "ai_surface", map[string]any{"status": "info", "message": "Not checked"})

        results["saas_txt"] = ExtractSaaSTXTFootprint(results)

        results["asn_info"] = a.LookupASN(ctx, results)

        results["edge_cdn"] = DetectEdgeCDN(results)

        enrichHostingFromEdgeCDN(results)

        ctData := getMapResult(resultsMap, "ct_subdomains")
        ctSubdomains, _ := ctData["subdomains"].([]map[string]any)

        if stSubs, ok := resultsMap["st_subdomains"].([]string); ok && len(stSubs) > 0 {
                existing := make(map[string]bool, len(ctSubdomains))
                for _, sd := range ctSubdomains {
                        if name, ok := sd["subdomain"].(string); ok {
                                existing[name] = true
                        }
                }
                for _, fqdn := range stSubs {
                        if !existing[fqdn] {
                                existing[fqdn] = true
                                ctSubdomains = append(ctSubdomains, map[string]any{
                                        "subdomain":  fqdn,
                                        "source":     "securitytrails",
                                        "cert_count": 0,
                                })
                        }
                }
                ctData["subdomains"] = ctSubdomains
                ctData["unique_subdomains"] = len(ctSubdomains)
                results["ct_subdomains"] = ctData
        }

        results["dangling_dns"] = a.DetectDanglingDNS(ctx, domain, ctSubdomains)

        results["posture"] = a.CalculatePosture(results)
        results["remediation"] = a.GenerateRemediation(results)
        results["mail_posture"] = buildMailPosture(results)

        totalElapsed := time.Since(analysisStart).Seconds()
        slog.Info("Analysis complete", "domain", domain, "total_s", fmt.Sprintf("%.2f", totalElapsed), "parallel_s", fmt.Sprintf("%.2f", parallelElapsed))

        return results
}


func (a *Analyzer) checkDomainExists(ctx context.Context, domain string) (bool, string, *string) {
        for _, rtype := range []string{"A", "TXT", "MX"} {
                if len(a.DNS.QueryDNS(ctx, rtype, domain)) > 0 {
                        return true, "active", nil
                }
        }

        if len(a.DNS.QueryDNS(ctx, "NS", domain)) > 0 {
                return true, "active", nil
        }

        msg := "Domain is not delegated or has no DNS records. This may be an unused subdomain or unregistered domain."
        return false, "undelegated", &msg
}

func timedTask(ch chan<- namedResult, key string, fn func() any) func() {
        return func() {
                start := time.Now()
                result := fn()
                ch <- namedResult{key, result, time.Since(start)}
        }
}

func (a *Analyzer) runParallelAnalyses(ctx context.Context, domain string, customDKIMSelectors []string) map[string]any {
        resultsCh := make(chan namedResult, 26)
        var wg sync.WaitGroup

        tasks := []func(){
                timedTask(resultsCh, "basic", func() any { return a.GetBasicRecords(ctx, domain) }),
                timedTask(resultsCh, "auth", func() any { return a.GetAuthoritativeRecords(ctx, domain) }),
                timedTask(resultsCh, "spf", func() any { return a.AnalyzeSPF(ctx, domain) }),
                timedTask(resultsCh, "dmarc", func() any { return a.AnalyzeDMARC(ctx, domain) }),
                timedTask(resultsCh, "dkim", func() any { return a.AnalyzeDKIM(ctx, domain, nil, customDKIMSelectors) }),
                timedTask(resultsCh, "mta_sts", func() any { return a.AnalyzeMTASTS(ctx, domain) }),
                timedTask(resultsCh, "tlsrpt", func() any { return a.AnalyzeTLSRPT(ctx, domain) }),
                timedTask(resultsCh, "bimi", func() any { return a.AnalyzeBIMI(ctx, domain) }),
                timedTask(resultsCh, "caa", func() any { return a.AnalyzeCAA(ctx, domain) }),
                timedTask(resultsCh, "dnssec", func() any { return a.AnalyzeDNSSEC(ctx, domain) }),
                timedTask(resultsCh, "ns_delegation", func() any { return a.AnalyzeNSDelegation(ctx, domain) }),
                timedTask(resultsCh, "registrar", func() any { return a.GetRegistrarInfo(ctx, domain) }),
                timedTask(resultsCh, "resolver_consensus", func() any { return a.DNS.ValidateResolverConsensus(ctx, domain) }),
                timedTask(resultsCh, "ct_subdomains", func() any { return a.DiscoverSubdomains(ctx, domain) }),
                timedTask(resultsCh, "https_svcb", func() any { return a.AnalyzeHTTPSSVCB(ctx, domain) }),
                timedTask(resultsCh, "cds_cdnskey", func() any { return a.AnalyzeCDSCDNSKEY(ctx, domain) }),
                timedTask(resultsCh, "smimea_openpgpkey", func() any { return a.AnalyzeSMIMEA(ctx, domain) }),
                timedTask(resultsCh, "security_txt", func() any { return a.AnalyzeSecurityTxt(ctx, domain) }),
                timedTask(resultsCh, "ai_surface", func() any { return a.AnalyzeAISurface(ctx, domain) }),
                timedTask(resultsCh, "st_subdomains", func() any {
                        initSecurityTrails()
                        if !securityTrailsEnabled {
                                return []string(nil)
                        }
                        subs, _, err := FetchSubdomains(ctx, domain)
                        if err != nil {
                                return []string(nil)
                        }
                        return subs
                }),
        }

        for _, fn := range tasks {
                wg.Add(1)
                go func(f func()) {
                        defer wg.Done()
                        f()
                }(fn)
        }

        go func() {
                wg.Wait()
                close(resultsCh)
        }()

        resultsMap := make(map[string]any)
        for nr := range resultsCh {
                resultsMap[nr.key] = nr.result
                slog.Info("Task completed", "task", nr.key, "domain", domain, "elapsed_ms", fmt.Sprintf("%.0f", float64(nr.elapsed.Milliseconds())))
        }
        return resultsMap
}

func enrichBasicRecords(basic, resultsMap map[string]any) {
        dmarcData := getMapResult(resultsMap, "dmarc")
        mtaStsData := getMapResult(resultsMap, "mta_sts")
        tlsrptData := getMapResult(resultsMap, "tlsrpt")

        if dmarcData["status"] == "success" || dmarcData["status"] == "warning" {
                if vr, ok := dmarcData["valid_records"].([]string); ok && len(vr) > 0 {
                        basic["DMARC"] = vr
                }
        }
        if rec, ok := mtaStsData["record"].(string); ok && rec != "" {
                basic["MTA-STS"] = []string{rec}
        }
        if rec, ok := tlsrptData["record"].(string); ok && rec != "" {
                basic["TLS-RPT"] = []string{rec}
        }
}

func buildSectionStatus(resultsMap map[string]any) map[string]any {
        sectionStatus := make(map[string]any)
        for key, result := range resultsMap {
                rm, ok := result.(map[string]any)
                if !ok {
                        sectionStatus[key] = map[string]any{"status": "ok"}
                        continue
                }
                status, _ := rm["status"].(string)
                switch status {
                case "timeout":
                        sectionStatus[key] = map[string]any{"status": "timeout", "message": "Query timed out"}
                case "error":
                        msg, _ := rm["message"].(string)
                        if msg == "" {
                                msg = "Lookup failed"
                        }
                        sectionStatus[key] = map[string]any{"status": "error", "message": msg}
                default:
                        sectionStatus[key] = map[string]any{"status": "ok"}
                }
        }
        return sectionStatus
}

func detectNullMX(basic map[string]any) bool {
        mxRecords, _ := basic["MX"].([]string)
        for _, r := range mxRecords {
                stripped := strings.TrimSpace(strings.TrimRight(r, "."))
                normalized := strings.ReplaceAll(stripped, " ", "")
                if normalized == "0." || normalized == "0" || stripped == "0 ." {
                        return true
                }
        }
        return false
}

func (a *Analyzer) buildNonExistentResult(domain, status string, statusMessage *string) map[string]any {
        return map[string]any{
                "domain":                 domain,
                "domain_exists":          false,
                "domain_status":          status,
                "domain_status_message":  derefStr(statusMessage),
                "section_status":         map[string]any{},
                "basic_records":          map[string]any{"A": []string{}, "AAAA": []string{}, "MX": []string{}, "NS": []string{}, "TXT": []string{}, "CNAME": []string{}, "SOA": []string{}},
                "authoritative_records":  map[string]any{},
                "auth_query_status":      nil,
                "resolver_ttl":           nil,
                "auth_ttl":               nil,
                "propagation_status":     map[string]any{},
                "resolver_consensus":     map[string]any{},
                "spf_analysis":           map[string]any{"status": "n/a", "message": msgDomainNotExist},
                "dmarc_analysis":         map[string]any{"status": "n/a", "message": msgDomainNotExist},
                "dkim_analysis":          map[string]any{"status": "n/a"},
                "mta_sts_analysis":       map[string]any{"status": "n/a"},
                "tlsrpt_analysis":        map[string]any{"status": "n/a"},
                "bimi_analysis":          map[string]any{"status": "n/a"},
                "dane_analysis":          map[string]any{"status": "n/a", "has_dane": false, "tlsa_records": []any{}, "issues": []string{}},
                "caa_analysis":           map[string]any{"status": "n/a"},
                "dnssec_analysis":        map[string]any{"status": "n/a"},
                "ns_delegation_analysis": map[string]any{"status": "error", "delegation_ok": false, "message": msgDomainNotExist},
                "registrar_info":         map[string]any{"status": "n/a", "registrar": nil},
                "smtp_transport":         map[string]any{"status": "n/a", "message": "Domain does not exist"},
                "ct_subdomains":          map[string]any{"status": "success", "subdomains": []any{}, "unique_subdomains": 0, "total_certs": 0},
                "has_null_mx":            false,
                "is_no_mail_domain":      false,
                "hosting_summary":        map[string]any{"hosting": "N/A", "dns_hosting": "N/A", "email_hosting": "N/A"},
                "dns_infrastructure":     map[string]any{"provider": "N/A", "tier": "N/A"},
                "email_security_mgmt":    map[string]any{},
                "dmarc_report_auth":      map[string]any{"status": "success", "checked": false, "external_domains": []map[string]any{}, "issues": []string{}},
                "https_svcb":             map[string]any{"status": "info", "has_https": false, "has_svcb": false, "https_records": []map[string]any{}, "svcb_records": []map[string]any{}, "supports_http3": false, "supports_ech": false, "issues": []string{}},
                "cds_cdnskey":            map[string]any{"status": "info", "has_cds": false, "has_cdnskey": false, "cds_records": []map[string]any{}, "cdnskey_records": []map[string]any{}, "automation": "none", "issues": []string{}},
                "smimea_openpgpkey":      map[string]any{"status": "info", "has_smimea": false, "has_openpgpkey": false, "smimea_records": []map[string]any{}, "openpgpkey_records": []map[string]any{}, "issues": []string{}},
                "security_txt":          map[string]any{"status": "info", "found": false, "message": "Domain does not exist", "contacts": []string{}, "issues": []string{}},
                "ai_surface":            map[string]any{"status": "info", "message": "Domain does not exist", "llms_txt": map[string]any{"found": false}, "robots_txt": map[string]any{"found": false}, "poisoning": map[string]any{"ioc_count": 0}, "hidden_prompts": map[string]any{"artifact_count": 0}, "evidence": []map[string]any{}, "summary": map[string]any{}},
                "saas_txt":               map[string]any{"status": "success", "services": []map[string]any{}, "service_count": 0, "issues": []string{}},
                "asn_info":               map[string]any{"status": "info", "ipv4_asn": []map[string]any{}, "ipv6_asn": []map[string]any{}, "unique_asns": []map[string]any{}, "issues": []string{}},
                "edge_cdn":               map[string]any{"status": "success", "is_behind_cdn": false, "cdn_provider": "", "cdn_indicators": []string{}, "origin_visible": true, "issues": []string{}},
                "dangling_dns":           map[string]any{"status": "success", "checked": true, "dangling_count": 0, "dangling_records": []map[string]any{}, "issues": []string{}},
                "posture":                map[string]any{"score": 0, "grade": "N/A", "state": "N/A", "label": "Non-existent Domain", "message": msgDomainNotExist, "icon": "times-circle", "issues": []string{msgDomainNotExist}, "monitoring": []string{}, "configured": []string{}, "absent": []string{}, "color": "secondary", "deliberate_monitoring": false, "deliberate_monitoring_note": ""},
                "remediation":            map[string]any{"top_fixes": []map[string]any{}, "posture_achievable": "N/A"},
                "mail_posture":           map[string]any{"classification": "unknown"},
        }
}

func getMapResult(m map[string]any, key string) map[string]any {
        if v, ok := m[key]; ok {
                if vm, ok := v.(map[string]any); ok {
                        return vm
                }
        }
        return map[string]any{}
}

func getOrDefault(m map[string]any, key string, defaultVal map[string]any) any {
        if v, ok := m[key]; ok {
                return v
        }
        return defaultVal
}

func extractAndRemove(m map[string]any, key string) any {
        v := m[key]
        delete(m, key)
        return v
}

func buildPropagationStatus(basic, auth map[string]any) map[string]any {
        propagation := make(map[string]any)
        for rtype := range basic {
                if rtype == "_ttl" || rtype == "_query_status" {
                        continue
                }
                bRecords, _ := basic[rtype].([]string)
                aRecords, _ := auth[rtype].([]string)

                bSet := makeStringSet(bRecords)
                aSet := makeStringSet(aRecords)

                var status string
                if len(aSet) == 0 {
                        status = "unknown"
                } else if stringSetEqual(keysOf(bSet), keysOf(aSet)) {
                        status = "synchronized"
                } else {
                        status = "propagating"
                }

                propagation[rtype] = map[string]any{
                        "status":   status,
                        "synced":   status == "synchronized",
                        "mismatch": status == "propagating",
                }
        }
        return propagation
}

func makeStringSet(s []string) map[string]bool {
        m := make(map[string]bool, len(s))
        for _, v := range s {
                m[v] = true
        }
        return m
}

func keysOf(m map[string]bool) []string {
        keys := make([]string, 0, len(m))
        for k := range m {
                keys = append(keys, k)
        }
        return keys
}
