// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"dnstool/go-server/internal/dnsclient"
)

func normalizeNSList(records []string) []string {
	var result []string
	for _, ns := range records {
		if ns != "" {
			result = append(result, strings.ToLower(strings.TrimRight(ns, ".")))
		}
	}
	sort.Strings(result)
	return result
}

func (a *Analyzer) queryChildNS(ctx context.Context, domain string) []string {
	childResult := a.DNS.QueryDNS(ctx, "NS", domain)
	if len(childResult) == 0 {
		return nil
	}
	return normalizeNSList(childResult)
}

func parentZoneFromDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}
	if len(parts) > 2 {
		return strings.Join(parts[1:], ".")
	}
	return parts[len(parts)-1]
}

func (a *Analyzer) queryParentNS(ctx context.Context, domain string) []string {
	parentZone := parentZoneFromDomain(domain)
	if parentZone == "" {
		return nil
	}

	parentNSServers := a.DNS.QueryDNS(ctx, "NS", parentZone)
	if len(parentNSServers) == 0 {
		return nil
	}

	parentServer := strings.TrimRight(parentNSServers[0], ".")
	parentIPs := a.DNS.QueryDNS(ctx, "A", parentServer)
	if len(parentIPs) == 0 {
		return nil
	}

	delegation, err := a.DNS.QuerySpecificResolver(ctx, "NS", domain, parentIPs[0])
	if err != nil || len(delegation) == 0 {
		return nil
	}

	return normalizeNSList(delegation)
}

func nsDelegationResult(status, message string, childNS, parentNS []string, match any, delegationOK bool, extras map[string]any) map[string]any {
	if childNS == nil {
		childNS = []string{}
	}
	if parentNS == nil {
		parentNS = []string{}
	}
	result := map[string]any{
		"status":        status,
		"message":       message,
		"child_ns":      childNS,
		"parent_ns":     parentNS,
		"match":         match,
		"delegation_ok": delegationOK,
	}
	for k, v := range extras {
		result[k] = v
	}
	return result
}

func (a *Analyzer) handleNoChildNS(ctx context.Context, domain string) map[string]any {
	parentZone := dnsclient.FindParentZone(a.DNS, ctx, domain)
	if parentZone == "" {
		return nsDelegationResult("error", "Could not retrieve NS records", nil, nil, false, false, nil)
	}

	var parentZoneNS []string
	pzResult := a.DNS.QueryDNS(ctx, "NS", parentZone)
	if len(pzResult) > 0 {
		parentZoneNS = normalizeNSList(pzResult)
	}
	return nsDelegationResult("success",
		fmt.Sprintf("Subdomain within %s zone - no separate delegation needed", parentZone),
		nil, parentZoneNS, nil, true,
		map[string]any{"is_subdomain": true, "parent_zone": parentZone},
	)
}

func (a *Analyzer) AnalyzeNSDelegation(ctx context.Context, domain string) map[string]any {
	childNS := a.queryChildNS(ctx, domain)
	parentNS := a.queryParentNS(ctx, domain)

	if len(childNS) == 0 {
		return a.handleNoChildNS(ctx, domain)
	}

	if len(parentNS) == 0 {
		return nsDelegationResult("success",
			fmt.Sprintf("%d nameserver(s) configured", len(childNS)),
			childNS, nil, nil, true,
			map[string]any{"note": "Parent zone delegation could not be verified"},
		)
	}

	if stringSetEqual(childNS, parentNS) {
		return nsDelegationResult("success",
			fmt.Sprintf("NS delegation verified - %d nameserver(s) match parent zone", len(childNS)),
			childNS, parentNS, true, true, nil,
		)
	}

	return nsDelegationResult("warning",
		"NS delegation mismatch - child and parent zone have different NS records",
		childNS, parentNS, false, false,
		map[string]any{"note": "This may indicate a recent change still propagating"},
	)
}

func stringSetEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]bool, len(a))
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		if !set[s] {
			return false
		}
	}
	return true
}
