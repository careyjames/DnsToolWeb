package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"dnstool/internal/dnsclient"
)

var algorithmNames = map[int]string{
	5: "RSA/SHA-1", 7: "RSASHA1-NSEC3-SHA1", 8: "RSA/SHA-256",
	10: "RSA/SHA-512", 13: "ECDSA P-256/SHA-256", 14: "ECDSA P-384/SHA-384",
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

func buildDNSSECResult(hasDNSKEY, hasDS, adFlag bool, dnskeyRecords, dsRecords []string, algorithm *int, algorithmName *string, adResolver *string) map[string]any {
	if hasDNSKEY && hasDS {
		var message string
		if adFlag {
			message = "DNSSEC fully configured and validated - AD flag confirmed by resolver"
		} else {
			message = "DNSSEC configured (DNSKEY + DS present) but AD flag not set by resolver"
		}
		return map[string]any{
			"status":         "success",
			"message":        message,
			"has_dnskey":     true,
			"has_ds":         true,
			"dnskey_records": dnskeyRecords,
			"ds_records":     dsRecords,
			"algorithm":      algorithm,
			"algorithm_name": algorithmName,
			"chain_of_trust": "complete",
			"ad_flag":        adFlag,
			"ad_resolver":    adResolver,
		}
	}

	if hasDNSKEY && !hasDS {
		return map[string]any{
			"status":         "warning",
			"message":        "DNSSEC partially configured - DNSKEY exists but DS record missing at registrar",
			"has_dnskey":     true,
			"has_ds":         false,
			"dnskey_records": dnskeyRecords,
			"ds_records":     []string{},
			"algorithm":      nil,
			"algorithm_name": nil,
			"chain_of_trust": "broken",
			"ad_flag":        false,
			"ad_resolver":    adResolver,
		}
	}

	return map[string]any{
		"status":         "warning",
		"message":        "DNSSEC not configured - DNS responses are unsigned",
		"has_dnskey":     false,
		"has_ds":         false,
		"dnskey_records": []string{},
		"ds_records":     []string{},
		"algorithm":      nil,
		"algorithm_name": nil,
		"chain_of_trust": "none",
		"ad_flag":        false,
		"ad_resolver":    nil,
	}
}

func (a *Analyzer) AnalyzeDNSSEC(ctx context.Context, domain string) map[string]any {
	hasDNSKEY := false
	hasDS := false
	var dnskeyRecords []string
	var dsRecords []string

	dnskeyResult := a.DNS.QueryDNS(ctx, "DNSKEY", domain)
	if len(dnskeyResult) > 0 {
		hasDNSKEY = true
		for i, rec := range dnskeyResult {
			if i >= 3 {
				break
			}
			if len(rec) > 100 {
				dnskeyRecords = append(dnskeyRecords, rec[:100]+"...")
			} else {
				dnskeyRecords = append(dnskeyRecords, rec)
			}
		}
	}

	dsResult := a.DNS.QueryDNS(ctx, "DS", domain)
	if len(dsResult) > 0 {
		hasDS = true
		for i, rec := range dsResult {
			if i >= 3 {
				break
			}
			dsRecords = append(dsRecords, rec)
		}
	}

	adResult := a.DNS.CheckDNSSECADFlag(ctx, domain)
	adFlag := adResult.ADFlag
	adResolver := adResult.ResolverUsed

	algorithm, algorithmName := parseAlgorithm(dsRecords)

	if !adFlag || hasDNSKEY || hasDS {
		return buildDNSSECResult(hasDNSKEY, hasDS, adFlag, dnskeyRecords, dsRecords, algorithm, algorithmName, adResolver)
	}

	parentZone := dnsclient.FindParentZone(a.DNS, ctx, domain)
	parentAlgo, parentAlgoName := parseAlgorithm(func() []string {
		if parentZone == "" {
			return nil
		}
		return a.DNS.QueryDNS(ctx, "DS", parentZone)
	}())

	var message string
	if parentZone != "" {
		message = fmt.Sprintf("DNSSEC inherited from parent zone (%s) - DNS responses are authenticated", parentZone)
	} else {
		message = "DNSSEC validated by resolver - DNS responses are authenticated"
	}

	return map[string]any{
		"status":         "success",
		"message":        message,
		"has_dnskey":     false,
		"has_ds":         false,
		"dnskey_records": []string{},
		"ds_records":     []string{},
		"algorithm":      parentAlgo,
		"algorithm_name": parentAlgoName,
		"chain_of_trust": "inherited",
		"ad_flag":        true,
		"ad_resolver":    adResolver,
		"is_subdomain":   true,
		"parent_zone":    parentZone,
	}
}
