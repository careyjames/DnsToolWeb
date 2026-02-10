package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"dnstool/go-server/internal/dnsclient"
)

func (a *Analyzer) AnalyzeNSDelegation(ctx context.Context, domain string) map[string]any {
	var childNS []string
	childResult := a.DNS.QueryDNS(ctx, "NS", domain)
	if len(childResult) > 0 {
		for _, ns := range childResult {
			if ns != "" {
				childNS = append(childNS, strings.ToLower(strings.TrimRight(ns, ".")))
			}
		}
		sort.Strings(childNS)
	}

	var parentNS []string
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		var parentZone string
		if len(parts) > 2 {
			parentZone = strings.Join(parts[1:], ".")
		} else {
			parentZone = parts[len(parts)-1]
		}

		parentNSServers := a.DNS.QueryDNS(ctx, "NS", parentZone)
		if len(parentNSServers) > 0 {
			parentServer := strings.TrimRight(parentNSServers[0], ".")
			parentIPs := a.DNS.QueryDNS(ctx, "A", parentServer)
			if len(parentIPs) > 0 {
				delegation, err := a.DNS.QuerySpecificResolver(ctx, "NS", domain, parentIPs[0])
				if err == nil && len(delegation) > 0 {
					for _, ns := range delegation {
						if ns != "" {
							parentNS = append(parentNS, strings.ToLower(strings.TrimRight(ns, ".")))
						}
					}
					sort.Strings(parentNS)
				}
			}
		}
	}

	if len(childNS) == 0 {
		parentZone := dnsclient.FindParentZone(a.DNS, ctx, domain)
		if parentZone != "" {
			var parentZoneNS []string
			pzResult := a.DNS.QueryDNS(ctx, "NS", parentZone)
			if len(pzResult) > 0 {
				for _, ns := range pzResult {
					if ns != "" {
						parentZoneNS = append(parentZoneNS, strings.ToLower(strings.TrimRight(ns, ".")))
					}
				}
				sort.Strings(parentZoneNS)
			}
			return map[string]any{
				"status":        "success",
				"message":       fmt.Sprintf("Subdomain within %s zone - no separate delegation needed", parentZone),
				"child_ns":      []string{},
				"parent_ns":     parentZoneNS,
				"match":         nil,
				"delegation_ok": true,
				"is_subdomain":  true,
				"parent_zone":   parentZone,
			}
		}
		return map[string]any{
			"status":        "error",
			"message":       "Could not retrieve NS records",
			"child_ns":      []string{},
			"parent_ns":     []string{},
			"match":         false,
			"delegation_ok": false,
		}
	}

	if len(parentNS) == 0 {
		return map[string]any{
			"status":        "success",
			"message":       fmt.Sprintf("%d nameserver(s) configured", len(childNS)),
			"child_ns":      childNS,
			"parent_ns":     []string{},
			"match":         nil,
			"delegation_ok": true,
			"note":          "Parent zone delegation could not be verified",
		}
	}

	match := stringSetEqual(childNS, parentNS)
	if match {
		return map[string]any{
			"status":        "success",
			"message":       fmt.Sprintf("NS delegation verified - %d nameserver(s) match parent zone", len(childNS)),
			"child_ns":      childNS,
			"parent_ns":     parentNS,
			"match":         true,
			"delegation_ok": true,
		}
	}

	return map[string]any{
		"status":        "warning",
		"message":       "NS delegation mismatch - child and parent zone have different NS records",
		"child_ns":      childNS,
		"parent_ns":     parentNS,
		"match":         false,
		"delegation_ok": false,
		"note":          "This may indicate a recent change still propagating",
	}
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
