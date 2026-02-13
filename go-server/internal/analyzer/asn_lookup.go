// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
package analyzer

import (
	"context"
	"fmt"
	"strings"
)

type ASNInfo struct {
	IP      string `json:"ip"`
	ASN     string `json:"asn"`
	ASName  string `json:"as_name"`
	Country string `json:"country"`
	Prefix  string `json:"prefix"`
}

func (a *Analyzer) LookupASN(ctx context.Context, results map[string]any) map[string]any {
	basicRecords, _ := results["basic_records"].(map[string]any)
	aRecords, _ := basicRecords["A"].([]string)
	aaaaRecords, _ := basicRecords["AAAA"].([]string)

	result := map[string]any{
		"status":    "success",
		"ipv4_asn":  []map[string]any{},
		"ipv6_asn":  []map[string]any{},
		"unique_asns": []map[string]any{},
		"issues":    []string{},
	}

	asnSet := make(map[string]map[string]any)

	ipv4Results := a.lookupIPv4ASNs(ctx, aRecords, asnSet)
	ipv6Results := a.lookupIPv6ASNs(ctx, aaaaRecords, asnSet)

	result["ipv4_asn"] = ipv4Results
	result["ipv6_asn"] = ipv6Results

	var uniqueASNs []map[string]any
	for _, info := range asnSet {
		uniqueASNs = append(uniqueASNs, info)
	}
	result["unique_asns"] = uniqueASNs

	if len(ipv4Results) == 0 && len(ipv6Results) == 0 {
		result["status"] = "info"
		result["message"] = "No IP addresses to look up"
	} else {
		result["message"] = fmt.Sprintf("Resolved %d unique ASN(s) across %d IP address(es)", len(uniqueASNs), len(ipv4Results)+len(ipv6Results))
	}

	return result
}

func (a *Analyzer) lookupIPv4ASNs(ctx context.Context, ips []string, asnSet map[string]map[string]any) []map[string]any {
	var results []map[string]any
	for _, ip := range ips {
		info := a.lookupIPv4ASN(ctx, ip)
		results = append(results, info)
		mergeASNSet(asnSet, info)
	}
	return results
}

func (a *Analyzer) lookupIPv6ASNs(ctx context.Context, ips []string, asnSet map[string]map[string]any) []map[string]any {
	var results []map[string]any
	for _, ip := range ips {
		info := a.lookupIPv6ASN(ctx, ip)
		results = append(results, info)
		mergeASNSet(asnSet, info)
	}
	return results
}

func (a *Analyzer) lookupIPv4ASN(ctx context.Context, ip string) map[string]any {
	reversed := reverseIPv4(ip)
	if reversed == "" {
		return map[string]any{"ip": ip, "error": "invalid IPv4"}
	}

	query := fmt.Sprintf("%s.origin.asn.cymru.com", reversed)
	records := a.DNS.QueryDNS(ctx, "TXT", query)

	info := map[string]any{
		"ip":         ip,
		"confidence": ConfidenceThirdPartyMap(MethodTeamCymru),
	}

	if len(records) == 0 {
		info["error"] = "no ASN data"
		return info
	}

	parseTeamCymruResponse(info, records[0])
	enrichASName(ctx, a, info)
	return info
}

func (a *Analyzer) lookupIPv6ASN(ctx context.Context, ip string) map[string]any {
	reversed := reverseIPv6(ip)
	if reversed == "" {
		return map[string]any{"ip": ip, "error": "invalid IPv6"}
	}

	query := fmt.Sprintf("%s.origin6.asn.cymru.com", reversed)
	records := a.DNS.QueryDNS(ctx, "TXT", query)

	info := map[string]any{
		"ip":         ip,
		"confidence": ConfidenceThirdPartyMap(MethodTeamCymru),
	}

	if len(records) == 0 {
		info["error"] = "no ASN data"
		return info
	}

	parseTeamCymruResponse(info, records[0])
	enrichASName(ctx, a, info)
	return info
}

func parseTeamCymruResponse(info map[string]any, record string) {
	record = strings.Trim(record, "\"")
	parts := strings.Split(record, "|")
	if len(parts) < 3 {
		return
	}
	info["asn"] = strings.TrimSpace(parts[0])
	info["prefix"] = strings.TrimSpace(parts[1])
	info["country"] = strings.TrimSpace(parts[2])
}

func enrichASName(ctx context.Context, a *Analyzer, info map[string]any) {
	asn, _ := info["asn"].(string)
	if asn == "" {
		return
	}
	query := fmt.Sprintf("AS%s.peer.asn.cymru.com", asn)
	records := a.DNS.QueryDNS(ctx, "TXT", query)
	if len(records) == 0 {
		return
	}

	record := strings.Trim(records[0], "\"")
	parts := strings.Split(record, "|")
	if len(parts) >= 5 {
		info["as_name"] = strings.TrimSpace(parts[4])
	}
}

func mergeASNSet(set map[string]map[string]any, info map[string]any) {
	asn, _ := info["asn"].(string)
	if asn == "" {
		return
	}
	if _, exists := set[asn]; !exists {
		set[asn] = map[string]any{
			"asn":     asn,
			"as_name": info["as_name"],
			"country": info["country"],
		}
	}
}

func reverseIPv4(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
}

func reverseIPv6(ip string) string {
	ip = strings.ToLower(ip)

	parts := strings.Split(ip, ":")
	if len(parts) < 3 {
		return ""
	}

	full := expandIPv6(ip)
	if full == "" {
		return ""
	}

	nibbles := strings.ReplaceAll(full, ":", "")
	if len(nibbles) != 32 {
		return ""
	}

	reversed := make([]byte, 63)
	for i := 0; i < 32; i++ {
		reversed[62-i*2] = nibbles[i]
		if i < 31 {
			reversed[62-i*2-1] = '.'
		}
	}
	return string(reversed)
}

func expandIPv6(ip string) string {
	if strings.Contains(ip, "::") {
		halves := strings.SplitN(ip, "::", 2)
		left := filterEmpty(strings.Split(halves[0], ":"))
		right := filterEmpty(strings.Split(halves[1], ":"))
		missing := 8 - len(left) - len(right)
		if missing < 0 {
			return ""
		}
		var full []string
		full = append(full, left...)
		for i := 0; i < missing; i++ {
			full = append(full, "0000")
		}
		full = append(full, right...)
		for i := range full {
			full[i] = padHex(full[i])
		}
		return strings.Join(full, ":")
	}

	parts := strings.Split(ip, ":")
	if len(parts) != 8 {
		return ""
	}
	for i := range parts {
		parts[i] = padHex(parts[i])
	}
	return strings.Join(parts, ":")
}

func padHex(s string) string {
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}

func filterEmpty(ss []string) []string {
	var result []string
	for _, s := range ss {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}
