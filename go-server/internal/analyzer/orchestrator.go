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

        domainExists := true
        domainStatus := "active"
        var domainStatusMessage *string

        quickCheckFound := false
        for _, rtype := range []string{"A", "TXT", "MX"} {
                result := a.DNS.QueryDNS(ctx, rtype, domain)
                if len(result) > 0 {
                        quickCheckFound = true
                        break
                }
        }

        if !quickCheckFound {
                nsRecords := a.DNS.QueryDNS(ctx, "NS", domain)
                if len(nsRecords) == 0 {
                        domainExists = false
                        domainStatus = "undelegated"
                        msg := "Domain is not delegated or has no DNS records. This may be an unused subdomain or unregistered domain."
                        domainStatusMessage = &msg
                }
        }

        if !domainExists {
                return a.buildNonExistentResult(domain, domainStatus, domainStatusMessage)
        }

        analysisStart := time.Now()

        type namedResult struct {
                key    string
                result any
        }

        resultsCh := make(chan namedResult, 20)
        var wg sync.WaitGroup

        tasks := map[string]func(){
                "basic":      func() { resultsCh <- namedResult{"basic", a.GetBasicRecords(ctx, domain)} },
                "auth":       func() { resultsCh <- namedResult{"auth", a.GetAuthoritativeRecords(ctx, domain)} },
                "spf":        func() { resultsCh <- namedResult{"spf", a.AnalyzeSPF(ctx, domain)} },
                "dmarc":      func() { resultsCh <- namedResult{"dmarc", a.AnalyzeDMARC(ctx, domain)} },
                "dkim":       func() { resultsCh <- namedResult{"dkim", a.AnalyzeDKIM(ctx, domain, nil, customDKIMSelectors)} },
                "mta_sts":    func() { resultsCh <- namedResult{"mta_sts", a.AnalyzeMTASTS(ctx, domain)} },
                "tlsrpt":     func() { resultsCh <- namedResult{"tlsrpt", a.AnalyzeTLSRPT(ctx, domain)} },
                "bimi":       func() { resultsCh <- namedResult{"bimi", a.AnalyzeBIMI(ctx, domain)} },
                "caa":        func() { resultsCh <- namedResult{"caa", a.AnalyzeCAA(ctx, domain)} },
                "dnssec":     func() { resultsCh <- namedResult{"dnssec", a.AnalyzeDNSSEC(ctx, domain)} },
                "ns":         func() { resultsCh <- namedResult{"ns_delegation", a.AnalyzeNSDelegation(ctx, domain)} },
                "registrar":  func() { resultsCh <- namedResult{"registrar", a.GetRegistrarInfo(ctx, domain)} },
                "consensus":  func() { resultsCh <- namedResult{"resolver_consensus", a.DNS.ValidateResolverConsensus(ctx, domain)} },
                "subdomains": func() { resultsCh <- namedResult{"ct_subdomains", a.DiscoverSubdomains(ctx, domain)} },
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
        }

        parallelElapsed := time.Since(analysisStart).Seconds()
        slog.Info("Parallel lookups completed", "domain", domain, "elapsed_s", fmt.Sprintf("%.2f", parallelElapsed), "tasks", len(resultsMap))

        basic := getMapResult(resultsMap, "basic")
        auth := getMapResult(resultsMap, "auth")

        resolverTTL := extractAndRemove(basic, "_ttl")
        authTTL := extractAndRemove(auth, "_ttl")
        authQueryStatus := extractAndRemove(auth, "_query_status")

        mxForDANE, _ := basic["MX"].([]string)
        daneResult := a.AnalyzeDANE(ctx, domain, mxForDANE)
        resultsMap["dane"] = daneResult

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

        propagationStatus := buildPropagationStatus(basic, auth)

        sectionStatus := make(map[string]any)
        for key, result := range resultsMap {
                if rm, ok := result.(map[string]any); ok {
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
                } else {
                        sectionStatus[key] = map[string]any{"status": "ok"}
                }
        }

        mxRecords, _ := basic["MX"].([]string)
        hasNullMX := false
        for _, r := range mxRecords {
                stripped := strings.TrimSpace(strings.TrimRight(r, "."))
                normalized := strings.ReplaceAll(stripped, " ", "")
                if normalized == "0." || normalized == "0" || stripped == "0 ." {
                        hasNullMX = true
                        break
                }
        }

        spfAnalysis := getMapResult(resultsMap, "spf")
        isNoMailDomain := false
        if spfAnalysis["no_mail_intent"] == true {
                isNoMailDomain = true
        }

        results := map[string]any{
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
                "smtp_transport":         nil,
                "has_null_mx":            hasNullMX,
                "is_no_mail_domain":      isNoMailDomain,
        }

        results["hosting_summary"] = a.GetHostingInfo(domain, results)
        results["dns_infrastructure"] = a.AnalyzeDNSInfrastructure(domain, results)
        results["email_security_mgmt"] = a.DetectEmailSecurityManagement(
                spfAnalysis,
                getMapResult(resultsMap, "dmarc"),
                getMapResult(resultsMap, "tlsrpt"),
                getMapResult(resultsMap, "mta_sts"),
                domain,
                getMapResult(resultsMap, "dkim"),
        )
        results["posture"] = a.CalculatePosture(results)
        results["remediation"] = a.GenerateRemediation(results)
        results["mail_posture"] = buildMailPosture(results)

        return results
}

func (a *Analyzer) buildNonExistentResult(domain, status string, statusMessage *string) map[string]any {
        return map[string]any{
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
                "smtp_transport":         nil,
                "ct_subdomains":          map[string]any{"status": "success", "subdomains": []any{}, "unique_subdomains": 0, "total_certs": 0},
                "has_null_mx":            false,
                "is_no_mail_domain":      false,
                "hosting_summary":        map[string]any{"hosting": "N/A", "dns_hosting": "N/A", "email_hosting": "N/A"},
                "dns_infrastructure":     map[string]any{"provider": "N/A", "tier": "N/A"},
                "email_security_mgmt":    map[string]any{},
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
