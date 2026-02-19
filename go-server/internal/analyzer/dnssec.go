// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "context"
        "fmt"
        "strconv"
        "strings"

        "dnstool/go-server/internal/dnsclient"
)

var algorithmNames = map[int]string{
        1: "RSAMD5", 3: "DSA", 5: "RSA/SHA-1", 6: "DSA-NSEC3-SHA1",
        7: "RSASHA1-NSEC3-SHA1", 8: "RSA/SHA-256", 10: "RSA/SHA-512",
        12: "ECC-GOST", 13: "ECDSA P-256/SHA-256", 14: "ECDSA P-384/SHA-384",
        15: "Ed25519", 16: "Ed448",
}

func parseAlgorithm(dsRecords []string) (*int, *string) {
        if len(dsRecords) == 0 {
                return nil, nil
        }
        parts := strings.Fields(dsRecords[0])
        if len(parts) < 2 {
                return nil, nil
        }
        algNum, err := strconv.Atoi(parts[1])
        if err != nil {
                return nil, nil
        }
        algorithm := &algNum
        if name, ok := algorithmNames[algNum]; ok {
                return algorithm, &name
        }
        n := fmt.Sprintf("Algorithm %d", algNum)
        return algorithm, &n
}

type dnssecParams struct {
        hasDNSKEY     bool
        hasDS         bool
        adFlag        bool
        dnskeyRecords []string
        dsRecords     []string
        algorithm     *int
        algorithmName *string
        adResolver    *string
}

func algorithmObservation(algo *int) map[string]any {
        if algo == nil {
                return nil
        }
        c := ClassifyDNSSECAlgorithm(*algo)
        return map[string]any{
                "strength":    c.Strength,
                "label":       c.Label,
                "rfc":         c.RFC,
                "observation": c.Observation,
                "quantum_note": c.QuantumNote,
        }
}

func buildDNSSECResult(p dnssecParams) map[string]any {
        if p.hasDNSKEY && p.hasDS {
                var message string
                if p.adFlag {
                        message = fmt.Sprintf("DNSSEC fully configured and validated — AD (Authenticated Data) flag set by resolver %s confirming cryptographic chain of trust from root to zone (RFC 4035 §3.2.3)", derefStr(p.adResolver))
                } else {
                        message = "DNSSEC configured (DNSKEY + DS records present) but AD flag not set — resolver did not confirm chain of trust validation (RFC 4035 §3.2.3). This may indicate a broken chain or a non-validating resolver path."
                }
                return map[string]any{
                        "status":                "success",
                        "message":               message,
                        "has_dnskey":            true,
                        "has_ds":                true,
                        "dnskey_records":        p.dnskeyRecords,
                        "ds_records":            p.dsRecords,
                        "algorithm":             derefInt(p.algorithm),
                        "algorithm_name":        derefStr(p.algorithmName),
                        "algorithm_observation": algorithmObservation(p.algorithm),
                        "chain_of_trust":        "complete",
                        "ad_flag":               p.adFlag,
                        "ad_resolver":           derefStr(p.adResolver),
                }
        }

        if p.hasDNSKEY && !p.hasDS {
                return map[string]any{
                        "status":                "warning",
                        "message":               "DNSSEC partially configured - DNSKEY exists but DS record missing at registrar",
                        "has_dnskey":            true,
                        "has_ds":                false,
                        "dnskey_records":        p.dnskeyRecords,
                        "ds_records":            []string{},
                        "algorithm":             nil,
                        "algorithm_name":        nil,
                        "algorithm_observation": nil,
                        "chain_of_trust":        "broken",
                        "ad_flag":               false,
                        "ad_resolver":           derefStr(p.adResolver),
                }
        }

        return map[string]any{
                "status":                "warning",
                "message":               "DNSSEC not configured - DNS responses are unsigned",
                "has_dnskey":            false,
                "has_ds":                false,
                "dnskey_records":        []string{},
                "ds_records":            []string{},
                "algorithm":             nil,
                "algorithm_name":        nil,
                "algorithm_observation": nil,
                "chain_of_trust":        "none",
                "ad_flag":               false,
                "ad_resolver":           nil,
        }
}

func collectDNSKEYRecords(results []string) (bool, []string) {
        if len(results) == 0 {
                return false, nil
        }
        var records []string
        for i, rec := range results {
                if i >= 3 {
                        break
                }
                if len(rec) > 100 {
                        records = append(records, rec[:100]+"...")
                } else {
                        records = append(records, rec)
                }
        }
        return true, records
}

func collectDSRecords(results []string) (bool, []string) {
        if len(results) == 0 {
                return false, nil
        }
        var records []string
        for i, rec := range results {
                if i >= 3 {
                        break
                }
                records = append(records, rec)
        }
        return true, records
}

func parentDSRecords(a *Analyzer, ctx context.Context, parentZone string) []string {
        if parentZone == "" {
                return nil
        }
        return a.DNS.QueryDNS(ctx, "DS", parentZone)
}

func buildInheritedDNSSECResult(parentZone string, adResolver *string, parentAlgo *int, parentAlgoName *string) map[string]any {
        var message string
        if parentZone != "" {
                message = fmt.Sprintf("DNSSEC inherited from parent zone (%s) - DNS responses are authenticated", parentZone)
        } else {
                message = "DNSSEC validated by resolver - DNS responses are authenticated"
        }
        return map[string]any{
                "status":                "success",
                "message":               message,
                "has_dnskey":            false,
                "has_ds":                false,
                "dnskey_records":        []string{},
                "ds_records":            []string{},
                "algorithm":             derefInt(parentAlgo),
                "algorithm_name":        derefStr(parentAlgoName),
                "algorithm_observation": algorithmObservation(parentAlgo),
                "chain_of_trust":        "inherited",
                "ad_flag":               true,
                "ad_resolver":           derefStr(adResolver),
                "is_subdomain":          true,
                "parent_zone":           parentZone,
        }
}

func (a *Analyzer) AnalyzeDNSSEC(ctx context.Context, domain string) map[string]any {
        hasDNSKEY, dnskeyRecords := collectDNSKEYRecords(a.DNS.QueryDNS(ctx, "DNSKEY", domain))
        hasDS, dsRecords := collectDSRecords(a.DNS.QueryDNS(ctx, "DS", domain))

        adResult := a.DNS.CheckDNSSECADFlag(ctx, domain)
        adFlag := adResult.ADFlag
        adResolver := adResult.ResolverUsed

        algorithm, algorithmName := parseAlgorithm(dsRecords)

        if !adFlag || hasDNSKEY || hasDS {
                return buildDNSSECResult(dnssecParams{
                        hasDNSKEY:     hasDNSKEY,
                        hasDS:         hasDS,
                        adFlag:        adFlag,
                        dnskeyRecords: dnskeyRecords,
                        dsRecords:     dsRecords,
                        algorithm:     algorithm,
                        algorithmName: algorithmName,
                        adResolver:    adResolver,
                })
        }

        parentZone := dnsclient.FindParentZone(a.DNS, ctx, domain)
        parentAlgo, parentAlgoName := parseAlgorithm(parentDSRecords(a, ctx, parentZone))

        return buildInheritedDNSSECResult(parentZone, adResolver, parentAlgo, parentAlgoName)
}
