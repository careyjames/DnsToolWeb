// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package ice

import (
        "dnstool/go-server/internal/analyzer"
        "fmt"
        "strings"
)

func AnalysisTestCases() []TestCase {
        var cases []TestCase
        cases = append(cases, spfAnalysisCases()...)
        cases = append(cases, dmarcAnalysisCases()...)
        cases = append(cases, spfVerdictCases()...)
        cases = append(cases, emailAnswerCases()...)
        return cases
}

func spfAnalysisCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "spf-analysis-001",
                        CaseName:   "SPF ~all classified as SOFT (industry standard)",
                        Protocol:   "spf",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7208 §5",
                        Expected:   "SOFT",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifyAllQualifier("v=spf1 include:_spf.google.com ~all")
                                if result == nil {
                                        return "nil", false
                                }
                                return *result, *result == "SOFT"
                        },
                },
                {
                        CaseID:     "spf-analysis-002",
                        CaseName:   "SPF -all classified as STRICT",
                        Protocol:   "spf",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7208 §5",
                        Expected:   "STRICT",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifyAllQualifier("v=spf1 include:_spf.google.com -all")
                                if result == nil {
                                        return "nil", false
                                }
                                return *result, *result == "STRICT"
                        },
                },
                {
                        CaseID:     "spf-analysis-003",
                        CaseName:   "SPF +all classified as DANGEROUS",
                        Protocol:   "spf",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7208 §5",
                        Expected:   "DANGEROUS",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifyAllQualifier("v=spf1 +all")
                                if result == nil {
                                        return "nil", false
                                }
                                return *result, *result == "DANGEROUS"
                        },
                },
                {
                        CaseID:     "spf-analysis-004",
                        CaseName:   "SPF ?all classified as NEUTRAL",
                        Protocol:   "spf",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7208 §5",
                        Expected:   "NEUTRAL",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifyAllQualifier("v=spf1 ?all")
                                if result == nil {
                                        return "nil", false
                                }
                                return *result, *result == "NEUTRAL"
                        },
                },
                {
                        CaseID:     "spf-analysis-005",
                        CaseName:   "SPF bare all (no qualifier) defaults to DANGEROUS (+all)",
                        Protocol:   "spf",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7208 §5",
                        Expected:   "DANGEROUS",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportClassifyAllQualifier("v=spf1 all")
                                if result == nil {
                                        return "nil", false
                                }
                                return *result, *result == "DANGEROUS"
                        },
                },
                {
                        CaseID:     "spf-analysis-006",
                        CaseName:   "SPF lookup count with includes",
                        Protocol:   "spf",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7208 §4.6.4",
                        Expected:   "3 lookups",
                        RunFn: func() (string, bool) {
                                count := analyzer.ExportCountSPFLookups("v=spf1 include:_spf.google.com include:spf.protection.outlook.com include:sendgrid.net ~all")
                                actual := fmt.Sprintf("%d lookups", count)
                                return actual, count == 3
                        },
                },
                {
                        CaseID:     "spf-analysis-007",
                        CaseName:   "SPF over 10 lookup limit detected as error",
                        Protocol:   "spf",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7208 §4.6.4",
                        Expected:   "error",
                        RunFn: func() (string, bool) {
                                status, _ := analyzer.ExportBuildSPFVerdict(11, strPtr("SOFT"), false, []string{"v=spf1 ~all"}, nil)
                                return status, status == "error"
                        },
                },
                {
                        CaseID:     "spf-analysis-008",
                        CaseName:   "SPF valid ~all with 3 lookups classified as success",
                        Protocol:   "spf",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7208",
                        Expected:   "success",
                        RunFn: func() (string, bool) {
                                status, _ := analyzer.ExportBuildSPFVerdict(3, strPtr("SOFT"), false, []string{"v=spf1 include:x ~all"}, nil)
                                return status, status == "success"
                        },
                },
                {
                        CaseID:     "spf-analysis-009",
                        CaseName:   "Multiple SPF records classified as error",
                        Protocol:   "spf",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7208 §3.2",
                        Expected:   "error",
                        RunFn: func() (string, bool) {
                                status, _ := analyzer.ExportBuildSPFVerdict(3, strPtr("SOFT"), false, []string{"v=spf1 ~all", "v=spf1 -all"}, nil)
                                return status, status == "error"
                        },
                },
                {
                        CaseID:     "spf-analysis-010",
                        CaseName:   "No SPF record classified as warning",
                        Protocol:   "spf",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7208",
                        Expected:   "warning",
                        RunFn: func() (string, bool) {
                                status, _ := analyzer.ExportBuildSPFVerdict(0, nil, false, nil, nil)
                                return status, status == "warning"
                        },
                },
                {
                        CaseID:     "spf-analysis-011",
                        CaseName:   "SPF no-mail intent (v=spf1 -all) classified as success",
                        Protocol:   "spf",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7208",
                        Expected:   "success",
                        RunFn: func() (string, bool) {
                                status, _ := analyzer.ExportBuildSPFVerdict(0, strPtr("STRICT"), true, []string{"v=spf1 -all"}, nil)
                                return status, status == "success"
                        },
                },
                {
                        CaseID:     "spf-analysis-012",
                        CaseName:   "SPF -all with senders triggers RFC 7489 §10.1 warning",
                        Protocol:   "spf",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7489 §10.1",
                        Expected:   "contains RFC 7489 warning",
                        RunFn: func() (string, bool) {
                                _, _, _, _, _, issues, _ := analyzer.ExportParseSPFMechanisms("v=spf1 include:_spf.google.com -all")
                                for _, issue := range issues {
                                        if strings.Contains(issue, "RFC 7489") {
                                                return "RFC 7489 warning present", true
                                        }
                                }
                                return fmt.Sprintf("no RFC 7489 warning in %v", issues), false
                        },
                },
                {
                        CaseID:     "spf-analysis-013",
                        CaseName:   "SPF ~all does NOT trigger RFC 7489 premature rejection warning",
                        Protocol:   "spf",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7489 §10.1",
                        Expected:   "no RFC 7489 warning",
                        RunFn: func() (string, bool) {
                                _, _, _, _, _, issues, _ := analyzer.ExportParseSPFMechanisms("v=spf1 include:_spf.google.com ~all")
                                for _, issue := range issues {
                                        if strings.Contains(issue, "RFC 7489") {
                                                return "false positive: RFC 7489 warning on ~all", false
                                        }
                                }
                                return "no RFC 7489 warning", true
                        },
                },
                {
                        CaseID:     "spf-analysis-014",
                        CaseName:   "SPF record classification separates valid from spf-like",
                        Protocol:   "spf",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7208 §3",
                        Expected:   "1 valid, 1 spf-like",
                        RunFn: func() (string, bool) {
                                valid, spfLike := analyzer.ExportClassifySPFRecords([]string{"v=spf1 include:x ~all", "spf2.0/mfrom include:y ~all"})
                                actual := fmt.Sprintf("%d valid, %d spf-like", len(valid), len(spfLike))
                                return actual, len(valid) == 1 && len(spfLike) == 1
                        },
                },
        }
}

func dmarcAnalysisCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "dmarc-analysis-001",
                        CaseName:   "DMARC reject + SPF + DKIM = not spoofable",
                        Protocol:   "dmarc",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7489 §6.3",
                        Expected:   "No — SPF and DMARC reject policy enforced",
                        RunFn: func() (string, bool) {
                                answer := analyzer.ExportBuildEmailAnswer(false, "reject", 100, false, true, true)
                                return answer, answer == "No — SPF and DMARC reject policy enforced"
                        },
                },
                {
                        CaseID:     "dmarc-analysis-002",
                        CaseName:   "DMARC p=none is monitor-only (spoofable)",
                        Protocol:   "dmarc",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7489 §6.3",
                        Expected:   "Yes — DMARC is monitor-only (p=none)",
                        RunFn: func() (string, bool) {
                                answer := analyzer.ExportBuildEmailAnswer(false, "none", 0, false, true, true)
                                return answer, answer == "Yes — DMARC is monitor-only (p=none)"
                        },
                },
                {
                        CaseID:     "dmarc-analysis-003",
                        CaseName:   "No SPF + no DMARC = fully spoofable",
                        Protocol:   "dmarc",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7489",
                        Expected:   "Yes — no SPF or DMARC protection",
                        RunFn: func() (string, bool) {
                                answer := analyzer.ExportBuildEmailAnswer(false, "", 0, false, false, false)
                                return answer, answer == "Yes — no SPF or DMARC protection"
                        },
                },
                {
                        CaseID:     "dmarc-analysis-004",
                        CaseName:   "DMARC quarantine at 100% = unlikely spoofable",
                        Protocol:   "dmarc",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7489 §6.3",
                        Expected:   "Unlikely — SPF and DMARC quarantine policy enforced",
                        RunFn: func() (string, bool) {
                                answer := analyzer.ExportBuildEmailAnswer(false, "quarantine", 100, false, true, true)
                                return answer, answer == "Unlikely — SPF and DMARC quarantine policy enforced"
                        },
                },
                {
                        CaseID:     "dmarc-analysis-005",
                        CaseName:   "DMARC quarantine at partial pct = partially protected",
                        Protocol:   "dmarc",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7489 §6.3",
                        Expected:   "Partially — DMARC quarantine at limited percentage",
                        RunFn: func() (string, bool) {
                                answer := analyzer.ExportBuildEmailAnswer(false, "quarantine", 50, false, true, true)
                                return answer, answer == "Partially — DMARC quarantine at limited percentage"
                        },
                },
                {
                        CaseID:     "dmarc-analysis-006",
                        CaseName:   "SPF only (no DMARC) = likely spoofable",
                        Protocol:   "dmarc",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7489",
                        Expected:   "Likely — SPF alone cannot prevent spoofing",
                        RunFn: func() (string, bool) {
                                answer := analyzer.ExportBuildEmailAnswer(false, "", 0, false, true, false)
                                return answer, answer == "Likely — SPF alone cannot prevent spoofing"
                        },
                },
                {
                        CaseID:     "dmarc-analysis-007",
                        CaseName:   "Null MX (no-mail domain) = not spoofable",
                        Protocol:   "dmarc",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7505",
                        Expected:   "No — null MX indicates no-mail domain",
                        RunFn: func() (string, bool) {
                                answer := analyzer.ExportBuildEmailAnswer(false, "", 0, true, false, false)
                                return answer, answer == "No — null MX indicates no-mail domain"
                        },
                },
                {
                        CaseID:     "dmarc-analysis-008",
                        CaseName:   "DMARC present but no SPF = partial protection",
                        Protocol:   "dmarc",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7489",
                        Expected:   "Partially — DMARC present but no SPF",
                        RunFn: func() (string, bool) {
                                answer := analyzer.ExportBuildEmailAnswer(false, "reject", 100, false, false, true)
                                return answer, answer == "Partially — DMARC present but no SPF"
                        },
                },
        }
}

func spfVerdictCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "spf-verdict-001",
                        CaseName:   "~all verdict message contains 'industry-standard'",
                        Protocol:   "spf",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7208",
                        Expected:   "contains 'industry-standard'",
                        RunFn: func() (string, bool) {
                                _, msg := analyzer.ExportBuildSPFVerdict(3, strPtr("SOFT"), false, []string{"v=spf1 include:x ~all"}, nil)
                                return msg, strings.Contains(msg, "industry-standard")
                        },
                },
                {
                        CaseID:     "spf-verdict-002",
                        CaseName:   "+all verdict message warns 'anyone can send'",
                        Protocol:   "spf",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7208 §5",
                        Expected:   "contains 'anyone can send'",
                        RunFn: func() (string, bool) {
                                _, msg := analyzer.ExportBuildSPFVerdict(1, strPtr("DANGEROUS"), false, []string{"v=spf1 +all"}, nil)
                                return msg, strings.Contains(msg, "anyone can send")
                        },
                },
                {
                        CaseID:     "spf-verdict-003",
                        CaseName:   "SPF over 10 lookups verdict cites RFC 7208 §4.6.4",
                        Protocol:   "spf",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7208 §4.6.4",
                        Expected:   "contains 'RFC 7208'",
                        RunFn: func() (string, bool) {
                                _, msg := analyzer.ExportBuildSPFVerdict(11, strPtr("SOFT"), false, []string{"v=spf1 ~all"}, nil)
                                return msg, strings.Contains(msg, "RFC 7208")
                        },
                },
        }
}

func emailAnswerCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "email-answer-001",
                        CaseName:   "Structured email answer for reject = green/success",
                        Protocol:   "dmarc",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7489 §6.3",
                        Expected:   "success",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildEmailAnswerStructured(false, "reject", 100, false, true, true)
                                color := result["color"]
                                return color, color == "success"
                        },
                },
                {
                        CaseID:     "email-answer-002",
                        CaseName:   "Structured email answer for p=none = red/danger",
                        Protocol:   "dmarc",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7489 §6.3",
                        Expected:   "danger",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildEmailAnswerStructured(false, "none", 0, false, true, true)
                                color := result["color"]
                                return color, color == "danger"
                        },
                },
                {
                        CaseID:     "email-answer-003",
                        CaseName:   "Structured email answer for no protection = red/danger",
                        Protocol:   "dmarc",
                        Layer:      LayerAnalysis,
                        RFCSection: "RFC 7489",
                        Expected:   "danger",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportBuildEmailAnswerStructured(false, "", 0, false, false, false)
                                color := result["color"]
                                return color, color == "danger"
                        },
                },
        }
}

func strPtr(s string) *string { return &s }
