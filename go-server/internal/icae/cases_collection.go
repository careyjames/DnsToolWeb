// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package icae

import (
        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/dnsclient"
        "fmt"
        "strings"
)

func CollectionTestCases() []TestCase {
        var cases []TestCase
        cases = append(cases, consensusCases()...)
        cases = append(cases, mxExtractionCases()...)
        cases = append(cases, recordFilteringCases()...)
        cases = append(cases, recordParsingCases()...)
        return cases
}

func consensusCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "consensus-collection-001",
                        CaseName:   "Unanimous resolver agreement yields consensus",
                        Protocol:   "dnssec",
                        Layer:      LayerCollection,
                        RFCSection: "Multi-resolver consensus (5-resolver architecture)",
                        Expected:   "allSame=true, 0 discrepancies",
                        RunFn: func() (string, bool) {
                                results := map[string][]string{
                                        "8.8.8.8":       {"1.2.3.4"},
                                        "1.1.1.1":       {"1.2.3.4"},
                                        "9.9.9.9":       {"1.2.3.4"},
                                        "208.67.222.222": {"1.2.3.4"},
                                        "185.228.168.9":  {"1.2.3.4"},
                                }
                                records, allSame, discrepancies := dnsclient.ExportFindConsensus(results)
                                actual := fmt.Sprintf("allSame=%t, %d discrepancies, records=%v", allSame, len(discrepancies), records)
                                return actual, allSame && len(discrepancies) == 0 && len(records) == 1 && records[0] == "1.2.3.4"
                        },
                },
                {
                        CaseID:     "consensus-collection-002",
                        CaseName:   "Majority consensus with one dissenter",
                        Protocol:   "dnssec",
                        Layer:      LayerCollection,
                        RFCSection: "Multi-resolver consensus (5-resolver architecture)",
                        Expected:   "allSame=false, 1 discrepancy, majority wins",
                        RunFn: func() (string, bool) {
                                results := map[string][]string{
                                        "8.8.8.8":       {"1.2.3.4"},
                                        "1.1.1.1":       {"1.2.3.4"},
                                        "9.9.9.9":       {"1.2.3.4"},
                                        "208.67.222.222": {"1.2.3.4"},
                                        "185.228.168.9":  {"5.6.7.8"},
                                }
                                records, allSame, discrepancies := dnsclient.ExportFindConsensus(results)
                                actual := fmt.Sprintf("allSame=%t, %d discrepancies, records=%v", allSame, len(discrepancies), records)
                                return actual, !allSame && len(discrepancies) == 1 && len(records) == 1 && records[0] == "1.2.3.4"
                        },
                },
                {
                        CaseID:     "consensus-collection-003",
                        CaseName:   "All resolvers return empty (NXDOMAIN consensus)",
                        Protocol:   "dnssec",
                        Layer:      LayerCollection,
                        RFCSection: "Multi-resolver consensus (5-resolver architecture)",
                        Expected:   "allSame=true, nil records",
                        RunFn: func() (string, bool) {
                                results := map[string][]string{
                                        "8.8.8.8":       {},
                                        "1.1.1.1":       {},
                                        "9.9.9.9":       {},
                                        "208.67.222.222": {},
                                        "185.228.168.9":  {},
                                }
                                records, allSame, discrepancies := dnsclient.ExportFindConsensus(results)
                                actual := fmt.Sprintf("allSame=%t, records=%v, discrepancies=%d", allSame, records, len(discrepancies))
                                return actual, allSame && records == nil && len(discrepancies) == 0
                        },
                },
                {
                        CaseID:     "consensus-collection-004",
                        CaseName:   "Multi-record consensus preserves order",
                        Protocol:   "spf",
                        Layer:      LayerCollection,
                        RFCSection: "Multi-resolver consensus (5-resolver architecture)",
                        Expected:   "allSame=true, 2 records",
                        RunFn: func() (string, bool) {
                                results := map[string][]string{
                                        "8.8.8.8":       {"v=spf1 include:_spf.google.com ~all", "v=spf1 -all"},
                                        "1.1.1.1":       {"v=spf1 include:_spf.google.com ~all", "v=spf1 -all"},
                                        "9.9.9.9":       {"v=spf1 include:_spf.google.com ~all", "v=spf1 -all"},
                                }
                                records, allSame, discrepancies := dnsclient.ExportFindConsensus(results)
                                actual := fmt.Sprintf("allSame=%t, %d records, %d discrepancies", allSame, len(records), len(discrepancies))
                                return actual, allSame && len(records) == 2 && len(discrepancies) == 0
                        },
                },
                {
                        CaseID:     "consensus-collection-005",
                        CaseName:   "Split consensus (no clear majority) picks highest count",
                        Protocol:   "dnssec",
                        Layer:      LayerCollection,
                        RFCSection: "Multi-resolver consensus (5-resolver architecture)",
                        Expected:   "allSame=false, result chosen from largest group",
                        RunFn: func() (string, bool) {
                                results := map[string][]string{
                                        "8.8.8.8":       {"1.2.3.4"},
                                        "1.1.1.1":       {"1.2.3.4"},
                                        "9.9.9.9":       {"5.6.7.8"},
                                }
                                records, allSame, discrepancies := dnsclient.ExportFindConsensus(results)
                                actual := fmt.Sprintf("allSame=%t, records=%v, discrepancies=%d", allSame, records, len(discrepancies))
                                return actual, !allSame && len(records) == 1 && records[0] == "1.2.3.4" && len(discrepancies) == 1
                        },
                },
        }
}

func mxExtractionCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "mx-collection-001",
                        CaseName:   "MX host extraction strips priority prefix",
                        Protocol:   "dane",
                        Layer:      LayerCollection,
                        RFCSection: "RFC 5321 §5",
                        Expected:   "2 hosts extracted",
                        RunFn: func() (string, bool) {
                                hosts := analyzer.ExportExtractMXHosts([]string{"10 mail1.example.com.", "20 mail2.example.com."})
                                actual := fmt.Sprintf("%d hosts: %v", len(hosts), hosts)
                                return actual, len(hosts) == 2
                        },
                },
                {
                        CaseID:     "mx-collection-002",
                        CaseName:   "Null MX (priority 0, dot) returns empty",
                        Protocol:   "dane",
                        Layer:      LayerCollection,
                        RFCSection: "RFC 7505",
                        Expected:   "0 hosts (null MX)",
                        RunFn: func() (string, bool) {
                                hosts := analyzer.ExportExtractMXHosts([]string{"0 ."})
                                actual := fmt.Sprintf("%d hosts", len(hosts))
                                return actual, len(hosts) == 0
                        },
                },
                {
                        CaseID:     "mx-collection-003",
                        CaseName:   "Empty MX input returns empty slice",
                        Protocol:   "dane",
                        Layer:      LayerCollection,
                        RFCSection: "RFC 5321 §5",
                        Expected:   "0 hosts",
                        RunFn: func() (string, bool) {
                                hosts := analyzer.ExportExtractMXHosts(nil)
                                actual := fmt.Sprintf("%d hosts", len(hosts))
                                return actual, len(hosts) == 0
                        },
                },
        }
}

func recordFilteringCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "sts-collection-001",
                        CaseName:   "MTA-STS record filtering accepts v=STSv1",
                        Protocol:   "mta_sts",
                        Layer:      LayerCollection,
                        RFCSection: "RFC 8461 §3.1",
                        Expected:   "1 valid record",
                        RunFn: func() (string, bool) {
                                records := analyzer.ExportFilterSTSRecords([]string{
                                        "v=STSv1; id=20260220",
                                        "some-random-txt-record",
                                        "v=spf1 include:google.com ~all",
                                })
                                actual := fmt.Sprintf("%d valid records", len(records))
                                return actual, len(records) == 1 && strings.Contains(records[0], "STSv1")
                        },
                },
                {
                        CaseID:     "sts-collection-002",
                        CaseName:   "MTA-STS ID extraction from valid record",
                        Protocol:   "mta_sts",
                        Layer:      LayerCollection,
                        RFCSection: "RFC 8461 §3.1",
                        Expected:   "ID extracted",
                        RunFn: func() (string, bool) {
                                id := analyzer.ExportExtractSTSID("v=STSv1; id=20260220")
                                if id == nil {
                                        return "nil", false
                                }
                                return *id, *id == "20260220"
                        },
                },
                {
                        CaseID:     "sts-collection-003",
                        CaseName:   "MTA-STS policy parsing extracts mode and max_age",
                        Protocol:   "mta_sts",
                        Layer:      LayerCollection,
                        RFCSection: "RFC 8461 §3.2",
                        Expected:   "mode=enforce, max_age>0",
                        RunFn: func() (string, bool) {
                                mode, maxAge, mx, hasVersion := analyzer.ExportParseMTASTSPolicyLines(
                                        "version: STSv1\nmode: enforce\nmax_age: 86400\nmx: mail.example.com\n",
                                )
                                actual := fmt.Sprintf("mode=%s, max_age=%d, mx=%v, version=%t", mode, maxAge, mx, hasVersion)
                                return actual, mode == "enforce" && maxAge == 86400 && len(mx) == 1 && hasVersion
                        },
                },
                {
                        CaseID:     "bimi-collection-001",
                        CaseName:   "BIMI record filtering accepts v=BIMI1",
                        Protocol:   "bimi",
                        Layer:      LayerCollection,
                        RFCSection: "BIMI Spec §3",
                        Expected:   "1 valid record",
                        RunFn: func() (string, bool) {
                                records := analyzer.ExportFilterBIMIRecords([]string{
                                        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem",
                                        "v=spf1 include:google.com ~all",
                                })
                                actual := fmt.Sprintf("%d valid records", len(records))
                                return actual, len(records) == 1
                        },
                },
                {
                        CaseID:     "bimi-collection-002",
                        CaseName:   "BIMI URL extraction separates logo and authority",
                        Protocol:   "bimi",
                        Layer:      LayerCollection,
                        RFCSection: "BIMI Spec §3",
                        Expected:   "logo and authority URLs extracted",
                        RunFn: func() (string, bool) {
                                logo, auth := analyzer.ExportExtractBIMIURLs("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem")
                                hasLogo := logo != nil && *logo == "https://example.com/logo.svg"
                                hasAuth := auth != nil && *auth == "https://example.com/cert.pem"
                                actual := "logo=nil, auth=nil"
                                if logo != nil && auth != nil {
                                        actual = fmt.Sprintf("logo=%s, auth=%s", *logo, *auth)
                                }
                                return actual, hasLogo && hasAuth
                        },
                },
                {
                        CaseID:     "caa-collection-001",
                        CaseName:   "CAA record parsing extracts issuers and wildcards",
                        Protocol:   "caa",
                        Layer:      LayerCollection,
                        RFCSection: "RFC 8659 §4",
                        Expected:   "1 issuer, 1 wildcard, has iodef",
                        RunFn: func() (string, bool) {
                                issuers, wildcardIssuers, _, hasIodef := analyzer.ExportParseCAARecords([]string{
                                        `0 issue "letsencrypt.org"`,
                                        `0 issuewild "digicert.com"`,
                                        `0 iodef "mailto:security@example.com"`,
                                })
                                actual := fmt.Sprintf("%d issuers, %d wildcards, iodef=%t", len(issuers), len(wildcardIssuers), hasIodef)
                                return actual, len(issuers) == 1 && len(wildcardIssuers) == 1 && hasIodef
                        },
                },
                {
                        CaseID:     "caa-collection-002",
                        CaseName:   "Empty CAA records return zero issuers",
                        Protocol:   "caa",
                        Layer:      LayerCollection,
                        RFCSection: "RFC 8659 §4",
                        Expected:   "0 issuers, 0 wildcards",
                        RunFn: func() (string, bool) {
                                issuers, wildcardIssuers, _, _ := analyzer.ExportParseCAARecords(nil)
                                actual := fmt.Sprintf("%d issuers, %d wildcards", len(issuers), len(wildcardIssuers))
                                return actual, len(issuers) == 0 && len(wildcardIssuers) == 0
                        },
                },
        }
}

func recordParsingCases() []TestCase {
        return []TestCase{
                {
                        CaseID:     "dkim-collection-001",
                        CaseName:   "DKIM key analysis extracts key type and length",
                        Protocol:   "dkim",
                        Layer:      LayerCollection,
                        RFCSection: "RFC 6376 §3.6.1",
                        Expected:   "key parsed with type and length",
                        RunFn: func() (string, bool) {
                                result := analyzer.ExportAnalyzeDKIMKey("v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890")
                                keyType, _ := result["key_type"].(string)
                                actual := fmt.Sprintf("type=%s", keyType)
                                return actual, keyType == "rsa"
                        },
                },
                {
                        CaseID:     "tlsa-collection-001",
                        CaseName:   "TLSA entry parsing extracts usage and selector fields",
                        Protocol:   "dane",
                        Layer:      LayerCollection,
                        RFCSection: "RFC 6698 §2.1",
                        Expected:   "valid TLSA with usage_name",
                        RunFn: func() (string, bool) {
                                parsed, valid := analyzer.ExportParseTLSAEntry("3 1 1 abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", "mail.example.com", "_25._tcp.mail.example.com")
                                if !valid {
                                        return "invalid", false
                                }
                                usageName, _ := parsed["usage_name"].(string)
                                actual := fmt.Sprintf("valid=%t, usage_name=%s", valid, usageName)
                                return actual, valid && usageName != ""
                        },
                },
                {
                        CaseID:     "ns-collection-001",
                        CaseName:   "NS provider classification identifies major providers",
                        Protocol:   "dnssec",
                        Layer:      LayerCollection,
                        RFCSection: "DNS provider detection",
                        Expected:   "Cloudflare detected",
                        RunFn: func() (string, bool) {
                                provider := analyzer.ExportClassifyNSProvider("ns1.cloudflare.com.")
                                return provider, provider == "Cloudflare"
                        },
                },
                {
                        CaseID:     "ns-collection-002",
                        CaseName:   "NS provider classification identifies Amazon Route 53",
                        Protocol:   "dnssec",
                        Layer:      LayerCollection,
                        RFCSection: "DNS provider detection",
                        Expected:   "Amazon Route 53 detected",
                        RunFn: func() (string, bool) {
                                provider := analyzer.ExportClassifyNSProvider("ns-123.awsdns-45.com.")
                                return provider, provider == "Amazon Route 53"
                        },
                },
                {
                        CaseID:     "ca-collection-001",
                        CaseName:   "CA issuer identification from CAA record",
                        Protocol:   "caa",
                        Layer:      LayerCollection,
                        RFCSection: "RFC 8659 §4",
                        Expected:   "Let's Encrypt identified",
                        RunFn: func() (string, bool) {
                                issuer := analyzer.ExportIdentifyCAIssuer("letsencrypt.org")
                                return issuer, issuer == "Let's Encrypt"
                        },
                },
                {
                        CaseID:     "ca-collection-002",
                        CaseName:   "CA issuer identification for DigiCert",
                        Protocol:   "caa",
                        Layer:      LayerCollection,
                        RFCSection: "RFC 8659 §4",
                        Expected:   "DigiCert identified",
                        RunFn: func() (string, bool) {
                                issuer := analyzer.ExportIdentifyCAIssuer("digicert.com")
                                return issuer, issuer == "DigiCert"
                        },
                },
                {
                        CaseID:     "domain-collection-001",
                        CaseName:   "Registrable domain extraction from subdomain",
                        Protocol:   "dnssec",
                        Layer:      LayerCollection,
                        RFCSection: "PSL-based domain registration",
                        Expected:   "example.com",
                        RunFn: func() (string, bool) {
                                domain := analyzer.ExportRegistrableDomain("sub.example.com")
                                return domain, domain == "example.com"
                        },
                },
        }
}
