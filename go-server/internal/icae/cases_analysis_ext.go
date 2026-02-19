// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package icae

import (
        "dnstool/go-server/internal/analyzer"
        "fmt"
        "strings"
)

func dkimAnalysisCases() []TestCase {
        rsa2048Record := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 266)
        rsa1024Record := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 134)

        return []TestCase{
                {
                        CaseID:     "dkim-analysis-001",
                        CaseName:   "2048-bit RSA key classified as adequate",
                        Protocol:   "dkim",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 8301",
                        Expected:   "adequate",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportAnalyzeDKIMKey(rsa2048Record)
                                strength, _ := result["key_strength"].(string)
                                return strength, strength == "adequate"
                        },
                },
                {
                        CaseID:     "dkim-analysis-002",
                        CaseName:   "1024-bit RSA key classified as weak",
                        Protocol:   "dkim",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 8301",
                        Expected:   "weak",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportAnalyzeDKIMKey(rsa1024Record)
                                strength, _ := result["key_strength"].(string)
                                return strength, strength == "weak"
                        },
                },
                {
                        CaseID:     "dkim-analysis-003",
                        CaseName:   "Revoked key detected (p= empty)",
                        Protocol:   "dkim",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 6376 §3.6.1",
                        Expected:   "true",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportAnalyzeDKIMKey("v=DKIM1; k=rsa; p=")
                                revoked, _ := result["revoked"].(bool)
                                return fmt.Sprintf("%v", revoked), revoked == true
                        },
                },
                {
                        CaseID:     "dkim-analysis-004",
                        CaseName:   "Test mode detected (t=y flag)",
                        Protocol:   "dkim",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 6376 §3.6.1",
                        Expected:   "true",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportAnalyzeDKIMKey("v=DKIM1; k=rsa; t=y; p=" + strings.Repeat("A", 266))
                                testMode, _ := result["test_mode"].(bool)
                                return fmt.Sprintf("%v", testMode), testMode == true
                        },
                },
                {
                        CaseID:     "dkim-analysis-005",
                        CaseName:   "Ed25519 key type parsed correctly",
                        Protocol:   "dkim",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 8463",
                        Expected:   "ed25519",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportAnalyzeDKIMKey("v=DKIM1; k=ed25519; p=AAAA")
                                keyType, _ := result["key_type"].(string)
                                return keyType, keyType == "ed25519"
                        },
                },
                {
                        CaseID:     "dkim-analysis-006",
                        CaseName:   "Selector provider classified for Google",
                        Protocol:   "dkim",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 6376",
                        Expected:   "Google Workspace",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifySelectorProvider("google._domainkey", "Unknown")
                                return result, result == "Google Workspace"
                        },
                },
                {
                        CaseID:     "dkim-analysis-007",
                        CaseName:   "Selector provider classified for Microsoft 365",
                        Protocol:   "dkim",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 6376",
                        Expected:   "Microsoft 365",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifySelectorProvider("selector1._domainkey", "Microsoft 365")
                                return result, result == "Microsoft 365"
                        },
                },
        }
}

func caaAnalysisCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "caa-analysis-001",
                        CaseName:   "CAA issuer identified as Let's Encrypt",
                        Protocol:   "caa",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 8659 §4",
                        Expected:   "Let's Encrypt",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportIdentifyCAIssuer("0 issue \"letsencrypt.org\"")
                                return result, result == "Let's Encrypt"
                        },
                },
                {
                        CaseID:     "caa-analysis-002",
                        CaseName:   "CAA issuer identified as DigiCert",
                        Protocol:   "caa",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 8659 §4",
                        Expected:   "DigiCert",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportIdentifyCAIssuer("0 issue \"digicert.com\"")
                                return result, result == "DigiCert"
                        },
                },
                {
                        CaseID:     "caa-analysis-003",
                        CaseName:   "CAA records parsed with issuewild detected",
                        Protocol:   "caa",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 8659 §4.3",
                        Expected:   "true",
                        RunFn: func() (string, bool) {
                                _, _, hasWildcard, _ := analyzer.ExportParseCAARecords([]string{
                                        "0 issue \"letsencrypt.org\"",
                                        "0 issuewild \"digicert.com\"",
                                })
                                return fmt.Sprintf("%v", hasWildcard), hasWildcard == true
                        },
                },
                {
                        CaseID:     "caa-analysis-004",
                        CaseName:   "CAA iodef record detected",
                        Protocol:   "caa",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 8659 §4.4",
                        Expected:   "true",
                        RunFn: func() (string, bool) {
                                _, _, _, hasIodef := analyzer.ExportParseCAARecords([]string{
                                        "0 issue \"letsencrypt.org\"",
                                        "0 iodef \"mailto:security@example.com\"",
                                })
                                return fmt.Sprintf("%v", hasIodef), hasIodef == true
                        },
                },
                {
                        CaseID:     "caa-analysis-005",
                        CaseName:   "CAA message built correctly with issuers",
                        Protocol:   "caa",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 8659",
                        Expected:   "contains 'CAA configured'",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildCAAMessage([]string{"Let's Encrypt"}, nil, false)
                                return result, strings.Contains(result, "CAA configured")
                        },
                },
        }
}

func mtaStsAnalysisCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "mta_sts-analysis-001",
                        CaseName:   "MTA-STS enforce mode returns success",
                        Protocol:   "mta_sts",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 8461 §5",
                        Expected:   "success",
                        RunFn: func() (string, bool) {
                                policyData := map[string]any{"mx": []string{"mail.example.com"}}
                                status, _ := analyzer.ExportDetermineMTASTSModeStatus("enforce", policyData)
                                return status, status == "success"
                        },
                },
                {
                        CaseID:     "mta_sts-analysis-002",
                        CaseName:   "MTA-STS testing mode returns warning",
                        Protocol:   "mta_sts",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 8461 §5",
                        Expected:   "warning",
                        RunFn: func() (string, bool) {
                                policyData := map[string]any{"mx": []string{"mail.example.com"}}
                                status, _ := analyzer.ExportDetermineMTASTSModeStatus("testing", policyData)
                                return status, status == "warning"
                        },
                },
                {
                        CaseID:     "mta_sts-analysis-003",
                        CaseName:   "MTA-STS policy parsing extracts mode and mx",
                        Protocol:   "mta_sts",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 8461 §3.2",
                        Expected:   "enforce",
                        RunFn: func() (string, bool) {
                                mode, _, mx, hasVersion := analyzer.ExportParseMTASTSPolicyLines("version: STSv1\nmode: enforce\nmax_age: 86400\nmx: mail.example.com\nmx: *.example.com")
                                ok := mode == "enforce" && len(mx) == 2 && hasVersion
                                actual := fmt.Sprintf("mode=%s mx=%d version=%v", mode, len(mx), hasVersion)
                                if !ok {
                                        return actual, false
                                }
                                return mode, true
                        },
                },
                {
                        CaseID:     "mta_sts-analysis-004",
                        CaseName:   "MTA-STS valid record filtered correctly",
                        Protocol:   "mta_sts",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 8461 §3.1",
                        Expected:   "1",
                        RunFn: func() (string, bool) {
                                records := analyzer.ExportFilterSTSRecords([]string{"v=STSv1; id=20230101", "not-an-sts-record"})
                                actual := fmt.Sprintf("%d", len(records))
                                return actual, len(records) == 1
                        },
                },
                {
                        CaseID:     "mta_sts-analysis-005",
                        CaseName:   "MTA-STS ID extracted from record",
                        Protocol:   "mta_sts",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 8461 §3.1",
                        Expected:   "20230101",
                        RunFn: func() (string, bool) {
                                id := analyzer.ExportExtractSTSID("v=STSv1; id=20230101")
                                if id == nil {
                                        return "nil", false
                                }
                                return *id, *id == "20230101"
                        },
                },
        }
}

func tlsrptAnalysisCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "tlsrpt-analysis-001",
                        CaseName:   "DKIM key classification: 2048-bit RSA adequate per crypto policy",
                        Protocol:   "tlsrpt",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 8301",
                        Expected:   "Adequate",
                        RunFn: func() (string, bool) {
                                c := analyzer.ClassifyDKIMKey("rsa", 2048)
                                return c.Label, c.Label == "Adequate"
                        },
                },
                {
                        CaseID:     "tlsrpt-analysis-002",
                        CaseName:   "DKIM key classification: Ed25519 strong per crypto policy",
                        Protocol:   "tlsrpt",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 8301",
                        Expected:   "Strong",
                        RunFn: func() (string, bool) {
                                c := analyzer.ClassifyDKIMKey("ed25519", 256)
                                return c.Label, c.Label == "Strong"
                        },
                },
                {
                        CaseID:     "tlsrpt-analysis-003",
                        CaseName:   "DS digest type 2 (SHA-256) classified as adequate",
                        Protocol:   "tlsrpt",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 8624 §3.3",
                        Expected:   "Adequate",
                        RunFn: func() (string, bool) {
                                c := analyzer.ClassifyDSDigest(2)
                                return c.Label, c.Label == "Adequate"
                        },
                },
        }
}

func bimiAnalysisCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "bimi-analysis-001",
                        CaseName:   "BIMI record filtered correctly (v=BIMI1)",
                        Protocol:   "bimi",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 9495 §3",
                        Expected:   "1",
                        RunFn: func() (string, bool) {
                                records := analyzer.ExportFilterBIMIRecords([]string{"v=BIMI1; l=https://example.com/logo.svg", "not-bimi"})
                                actual := fmt.Sprintf("%d", len(records))
                                return actual, len(records) == 1
                        },
                },
                {
                        CaseID:     "bimi-analysis-002",
                        CaseName:   "BIMI logo URL extracted from record",
                        Protocol:   "bimi",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 9495 §3",
                        Expected:   "https://example.com/logo.svg",
                        RunFn: func() (string, bool) {
                                logo, _ := analyzer.ExportExtractBIMIURLs("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem")
                                if logo == nil {
                                        return "nil", false
                                }
                                return *logo, *logo == "https://example.com/logo.svg"
                        },
                },
                {
                        CaseID:     "bimi-analysis-003",
                        CaseName:   "BIMI VMC URL extracted from record",
                        Protocol:   "bimi",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 9495 §3",
                        Expected:   "https://example.com/vmc.pem",
                        RunFn: func() (string, bool) {
                                _, vmc := analyzer.ExportExtractBIMIURLs("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem")
                                if vmc == nil {
                                        return "nil", false
                                }
                                return *vmc, *vmc == "https://example.com/vmc.pem"
                        },
                },
                {
                        CaseID:     "bimi-analysis-004",
                        CaseName:   "BIMI record without VMC returns nil authority URL",
                        Protocol:   "bimi",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 9495 §3",
                        Expected:   "nil",
                        RunFn: func() (string, bool) {
                                _, vmc := analyzer.ExportExtractBIMIURLs("v=BIMI1; l=https://example.com/logo.svg")
                                return fmt.Sprintf("%v", vmc), vmc == nil
                        },
                },
        }
}

func daneAnalysisCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "dane-analysis-001",
                        CaseName:   "TLSA entry parsed with usage 3 (DANE-EE)",
                        Protocol:   "dane",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7672 §3.1",
                        Expected:   "DANE-EE (Domain-issued certificate)",
                        RunFn: func() (string, bool) {
                                rec, ok := analyzer.ExportParseTLSAEntry("3 1 1 AABBCCDD", "mail.example.com", "_25._tcp.mail.example.com")
                                if !ok {
                                        return "parse failed", false
                                }
                                usageName, _ := rec["usage_name"].(string)
                                return usageName, usageName == "DANE-EE (Domain-issued certificate)"
                        },
                },
                {
                        CaseID:     "dane-analysis-002",
                        CaseName:   "TLSA usage 0 triggers RFC 7672 recommendation",
                        Protocol:   "dane",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7672 §3.1",
                        Expected:   "contains recommendation",
                        RunFn: func() (string, bool) {
                                rec, ok := analyzer.ExportParseTLSAEntry("0 1 1 AABBCCDD", "mail.example.com", "_25._tcp.mail.example.com")
                                if !ok {
                                        return "parse failed", false
                                }
                                recommendation, _ := rec["recommendation"].(string)
                                return recommendation, strings.Contains(recommendation, "RFC 7672")
                        },
                },
                {
                        CaseID:     "dane-analysis-003",
                        CaseName:   "MX hosts extracted correctly from records",
                        Protocol:   "dane",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 5321 §5",
                        Expected:   "2",
                        RunFn: func() (string, bool) {
                                hosts := analyzer.ExportExtractMXHosts([]string{"10 mail1.example.com.", "20 mail2.example.com."})
                                actual := fmt.Sprintf("%d", len(hosts))
                                return actual, len(hosts) == 2
                        },
                },
                {
                        CaseID:     "dane-analysis-004",
                        CaseName:   "DANE verdict with all MX covered = success",
                        Protocol:   "dane",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7672",
                        Expected:   "success",
                        RunFn: func() (string, bool) {
                                tlsa := []map[string]any{
                                        {"mx_host": "mail.example.com", "usage": 3, "matching_type": 1},
                                }
                                status, _, _ := analyzer.ExportBuildDANEVerdict(tlsa, []string{"mail.example.com"}, []string{"mail.example.com"}, nil)
                                return status, status == "success"
                        },
                },
                {
                        CaseID:     "dane-analysis-005",
                        CaseName:   "DANE verdict with no TLSA records = info",
                        Protocol:   "dane",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7672",
                        Expected:   "info",
                        RunFn: func() (string, bool) {
                                status, _, _ := analyzer.ExportBuildDANEVerdict(nil, nil, []string{"mail.example.com"}, nil)
                                return status, status == "info"
                        },
                },
        }
}
