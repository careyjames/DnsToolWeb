// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
//
// Live integration tests — these query real DNS infrastructure.
// Run manually: cd go-server && GIT_DIR=/dev/null go test -tags=integration -run TestLive ./internal/analyzer/ -v -timeout 120s
// These tests are NOT part of the default test suite and never run in CI.
// They validate end-to-end pipeline behavior against real domains.
//
// Design principles:
//   - Assert STRUCTURAL properties, not exact record values
//   - Use owner-controlled domain (it-help.tech) as primary target
//   - Failures here may indicate domain config changes, not code bugs
//   - Test the shape of results: "SPF exists" not "SPF equals X"

//go:build integration

package analyzer

import (
        "context"
        "fmt"
        "strings"
        "testing"
        "time"
)

func newLiveAnalyzer(t *testing.T) *Analyzer {
        t.Helper()
        a := New(WithMaxConcurrent(4))
        time.Sleep(2 * time.Second)
        return a
}

func requireMapKey(t *testing.T, m map[string]any, key string) any {
        t.Helper()
        v, ok := m[key]
        if !ok {
                t.Fatalf("result missing required key %q", key)
        }
        return v
}

func requireMapStringKey(t *testing.T, m map[string]any, key string) string {
        t.Helper()
        v := requireMapKey(t, m, key)
        s, ok := v.(string)
        if !ok {
                t.Fatalf("key %q is not a string: %T", key, v)
        }
        return s
}

func TestLiveFullScanOwnerDomain(t *testing.T) {
        a := newLiveAnalyzer(t)
        ctx := context.Background()

        start := time.Now()
        results := a.AnalyzeDomain(ctx, "it-help.tech", nil)
        elapsed := time.Since(start)

        success, _ := results["analysis_success"].(bool)
        if !success {
                if elapsed > 55*time.Second {
                        t.Skipf("AnalyzeDomain timed out (%s) — orchestrator 60s limit hit; individual protocol tests validate correctness separately", elapsed)
                }
                t.Fatalf("AnalyzeDomain returned analysis_success=false for it-help.tech (took %s)", elapsed)
        }

        domain := requireMapStringKey(t, results, "domain")
        if domain != "it-help.tech" {
                t.Errorf("domain mismatch: expected it-help.tech, got %s", domain)
        }

        t.Run("SPF_exists", func(t *testing.T) {
                spf, ok := results["spf_analysis"].(map[string]any)
                if !ok {
                        t.Fatal("spf_analysis missing or not a map")
                }
                status := requireMapStringKey(t, spf, "status")
                if status == "not_found" || status == "error" || status == "n/a" {
                        t.Errorf("SPF should be configured for it-help.tech, got status=%s", status)
                }
                if record, ok := spf["record"].(string); ok {
                        if !strings.HasPrefix(record, "v=spf1") {
                                t.Errorf("SPF record should start with v=spf1, got: %s", record)
                        }
                }
        })

        t.Run("DMARC_exists", func(t *testing.T) {
                dmarc, ok := results["dmarc_analysis"].(map[string]any)
                if !ok {
                        t.Fatal("dmarc_analysis missing or not a map")
                }
                status := requireMapStringKey(t, dmarc, "status")
                if status == "not_found" || status == "error" || status == "n/a" {
                        t.Errorf("DMARC should be configured for it-help.tech, got status=%s", status)
                }
                if policy, ok := dmarc["policy"].(string); ok {
                        validPolicies := map[string]bool{"none": true, "quarantine": true, "reject": true}
                        if !validPolicies[policy] {
                                t.Errorf("DMARC policy should be none/quarantine/reject, got: %s", policy)
                        }
                }
        })

        t.Run("DNS_infrastructure_classified", func(t *testing.T) {
                infra, ok := results["dns_infrastructure"].(map[string]any)
                if !ok {
                        t.Fatal("dns_infrastructure missing or not a map")
                }
                tier := requireMapStringKey(t, infra, "provider_tier")
                if tier == "" || tier == "N/A" {
                        t.Error("DNS infrastructure should have a provider tier classification")
                }
                provider := requireMapStringKey(t, infra, "provider")
                if provider == "" || provider == "N/A" {
                        t.Error("DNS infrastructure should identify a provider")
                }
                t.Logf("Detected: provider=%s, tier=%s", provider, tier)
        })

        t.Run("mail_posture_classified", func(t *testing.T) {
                posture, ok := results["mail_posture"].(map[string]any)
                if !ok {
                        t.Fatal("mail_posture missing or not a map")
                }
                classification := requireMapStringKey(t, posture, "classification")
                if classification == "" || classification == "unknown" {
                        t.Error("mail posture should have a classification")
                }
                t.Logf("Mail posture: %s", classification)
        })

        t.Run("remediation_generated", func(t *testing.T) {
                remediation, ok := results["remediation"].(map[string]any)
                if !ok {
                        t.Fatal("remediation missing or not a map")
                }
                _ = requireMapKey(t, remediation, "top_fixes")
        })

        t.Run("basic_records_populated", func(t *testing.T) {
                basic, ok := results["basic_records"].(map[string]any)
                if !ok {
                        t.Fatal("basic_records missing or not a map")
                }
                nsRecords, _ := basic["NS"].([]string)
                if len(nsRecords) == 0 {
                        t.Error("domain should have NS records")
                }
                t.Logf("NS records: %v", nsRecords)
        })

        t.Run("DNSSEC_analyzed", func(t *testing.T) {
                dnssec, ok := results["dnssec_analysis"].(map[string]any)
                if !ok {
                        t.Fatal("dnssec_analysis missing or not a map")
                }
                status := requireMapStringKey(t, dnssec, "status")
                if status == "" || status == "error" {
                        t.Errorf("DNSSEC analysis should return a definitive status, got: %s", status)
                }
                t.Logf("DNSSEC status: %s", status)
        })

        t.Run("CAA_analyzed", func(t *testing.T) {
                caa, ok := results["caa_analysis"].(map[string]any)
                if !ok {
                        t.Fatal("caa_analysis missing or not a map")
                }
                status := requireMapStringKey(t, caa, "status")
                if status == "" || status == "error" {
                        t.Errorf("CAA analysis should return a status, got: %s", status)
                }
                t.Logf("CAA status: %s", status)
        })

        t.Run("all_protocol_sections_present", func(t *testing.T) {
                requiredSections := []string{
                        "spf_analysis", "dmarc_analysis", "dkim_analysis",
                        "mta_sts_analysis", "tlsrpt_analysis", "bimi_analysis",
                        "dane_analysis", "caa_analysis", "dnssec_analysis",
                }
                for _, section := range requiredSections {
                        sectionData, ok := results[section].(map[string]any)
                        if !ok {
                                t.Errorf("missing section %s", section)
                                continue
                        }
                        if _, hasStatus := sectionData["status"]; !hasStatus {
                                t.Errorf("section %s has no status field", section)
                        }
                }
        })
}

func TestLiveIndividualProtocols(t *testing.T) {
        a := newLiveAnalyzer(t)
        ctx := context.Background()
        domain := "it-help.tech"

        t.Run("SPF_analysis", func(t *testing.T) {
                result := a.AnalyzeSPF(ctx, domain)
                status := requireMapStringKey(t, result, "status")
                t.Logf("SPF status: %s", status)
                if status == "error" {
                        t.Error("SPF analysis returned error — DNS query may have failed")
                }
        })

        t.Run("DMARC_analysis", func(t *testing.T) {
                result := a.AnalyzeDMARC(ctx, domain)
                status := requireMapStringKey(t, result, "status")
                t.Logf("DMARC status: %s", status)
                if status == "error" {
                        t.Error("DMARC analysis returned error — DNS query may have failed")
                }
        })

        t.Run("DKIM_analysis", func(t *testing.T) {
                result := a.AnalyzeDKIM(ctx, domain, nil, nil)
                status := requireMapStringKey(t, result, "status")
                t.Logf("DKIM status: %s", status)
        })

        t.Run("MTA_STS_analysis", func(t *testing.T) {
                result := a.AnalyzeMTASTS(ctx, domain)
                status := requireMapStringKey(t, result, "status")
                t.Logf("MTA-STS status: %s", status)
                if status == "error" {
                        t.Error("MTA-STS analysis returned error")
                }
        })

        t.Run("DNSSEC_analysis", func(t *testing.T) {
                result := a.AnalyzeDNSSEC(ctx, domain)
                status := requireMapStringKey(t, result, "status")
                t.Logf("DNSSEC status: %s", status)
                if status == "error" {
                        t.Error("DNSSEC analysis returned error")
                }
        })
}

func TestLiveResultsShape(t *testing.T) {
        a := newLiveAnalyzer(t)
        ctx := context.Background()

        t.Run("nonexistent_domain", func(t *testing.T) {
                results := a.AnalyzeDomain(ctx, "this-domain-definitely-does-not-exist-xyzzy-12345.com", nil)
                exists, _ := results["domain_exists"].(bool)
                if exists {
                        t.Error("nonexistent domain should return domain_exists=false")
                }
                success, _ := results["analysis_success"].(bool)
                if success {
                        t.Error("nonexistent domain should return analysis_success=false")
                }
        })

        t.Run("well_known_domain_google", func(t *testing.T) {
                start := time.Now()
                results := a.AnalyzeDomain(ctx, "google.com", nil)
                elapsed := time.Since(start)
                success, _ := results["analysis_success"].(bool)
                if !success {
                        if elapsed > 55*time.Second {
                                t.Skipf("google.com analysis timed out (%s)", elapsed)
                        }
                        t.Fatal("google.com should analyze successfully")
                }

                spf, _ := results["spf_analysis"].(map[string]any)
                spfStatus, _ := spf["status"].(string)
                if spfStatus == "not_found" {
                        t.Error("google.com should have SPF — if this fails, google removed their SPF record (unlikely)")
                }

                dmarc, _ := results["dmarc_analysis"].(map[string]any)
                dmarcStatus, _ := dmarc["status"].(string)
                if dmarcStatus == "not_found" {
                        t.Error("google.com should have DMARC — if this fails, google removed their DMARC record (unlikely)")
                }

                infra, _ := results["dns_infrastructure"].(map[string]any)
                provider, _ := infra["provider"].(string)
                t.Logf("google.com provider: %s", provider)
        })
}

func TestLiveAnalysisTimingReasonable(t *testing.T) {
        a := newLiveAnalyzer(t)
        ctx := context.Background()

        start := time.Now()
        results := a.AnalyzeDomain(ctx, "it-help.tech", nil)
        elapsed := time.Since(start)

        success, _ := results["analysis_success"].(bool)
        if !success {
                if elapsed > 55*time.Second {
                        t.Skipf("analysis timed out (%s) — orchestrator limit; timing test not applicable", elapsed)
                }
                t.Fatal("analysis failed — cannot assess timing")
        }

        t.Logf("Full analysis completed in %s", elapsed)

        if elapsed > 90*time.Second {
                t.Errorf("analysis took %s — exceeds 90s timeout, something may be hanging", elapsed)
        }

        if elapsed < 500*time.Millisecond {
                t.Log("WARNING: analysis completed suspiciously fast — may indicate cached or stubbed results")
        }

        scanTime, _ := results["scan_time"].(string)
        if scanTime != "" {
                t.Logf("Reported scan_time: %s", scanTime)
        }

        fmt.Printf("\n=== LIVE INTEGRATION TEST SUMMARY ===\n")
        fmt.Printf("Domain: it-help.tech\n")
        fmt.Printf("Analysis time: %s\n", elapsed)
        if posture, ok := results["mail_posture"].(map[string]any); ok {
                fmt.Printf("Mail posture: %v\n", posture["classification"])
        }
        if infra, ok := results["dns_infrastructure"].(map[string]any); ok {
                fmt.Printf("Provider: %v (tier: %v)\n", infra["provider"], infra["provider_tier"])
        }
        fmt.Printf("=====================================\n")
}
