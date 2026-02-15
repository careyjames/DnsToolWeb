// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

func CanonicalPostureHash(results map[string]any) string {
	var parts []string

	parts = append(parts, "spf:"+extractPostureField(results, "spf_analysis", "status"))
	parts = append(parts, "spf_records:"+extractSortedRecords(results, "spf_analysis", "records"))

	parts = append(parts, "dmarc:"+extractPostureField(results, "dmarc_analysis", "status"))
	parts = append(parts, "dmarc_policy:"+extractPostureField(results, "dmarc_analysis", "policy"))
	parts = append(parts, "dmarc_records:"+extractSortedRecords(results, "dmarc_analysis", "records"))

	parts = append(parts, "dkim:"+extractPostureField(results, "dkim_analysis", "status"))
	parts = append(parts, "dkim_selectors:"+extractSortedSelectors(results))

	parts = append(parts, "mta_sts:"+extractPostureField(results, "mta_sts_analysis", "status"))
	parts = append(parts, "mta_sts_mode:"+extractPostureField(results, "mta_sts_analysis", "mode"))

	parts = append(parts, "tlsrpt:"+extractPostureField(results, "tlsrpt_analysis", "status"))

	parts = append(parts, "bimi:"+extractPostureField(results, "bimi_analysis", "status"))

	parts = append(parts, "dane:"+extractPostureField(results, "dane_analysis", "status"))
	parts = append(parts, "dane_has:"+extractPostureBool(results, "dane_analysis", "has_dane"))

	parts = append(parts, "caa:"+extractPostureField(results, "caa_analysis", "status"))
	parts = append(parts, "caa_tags:"+extractSortedCAATags(results))

	parts = append(parts, "dnssec:"+extractPostureField(results, "dnssec_analysis", "status"))

	parts = append(parts, "mail_posture:"+extractPostureField(results, "mail_posture", "label"))

	parts = append(parts, "mx:"+extractSortedMX(results))
	parts = append(parts, "ns:"+extractSortedNS(results))

	canonical := strings.Join(parts, "|")
	hash := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(hash[:])
}

func extractPostureField(results map[string]any, section, key string) string {
	sectionData, ok := results[section].(map[string]any)
	if !ok {
		return ""
	}
	v, ok := sectionData[key]
	if !ok {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", v)))
}

func extractPostureBool(results map[string]any, section, key string) string {
	sectionData, ok := results[section].(map[string]any)
	if !ok {
		return "false"
	}
	v, ok := sectionData[key].(bool)
	if !ok {
		return "false"
	}
	if v {
		return "true"
	}
	return "false"
}

func extractSortedRecords(results map[string]any, section, key string) string {
	sectionData, ok := results[section].(map[string]any)
	if !ok {
		return ""
	}
	records, ok := sectionData[key]
	if !ok {
		return ""
	}
	switch v := records.(type) {
	case []any:
		var strs []string
		for _, r := range v {
			strs = append(strs, strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", r))))
		}
		sort.Strings(strs)
		return strings.Join(strs, ",")
	case []string:
		sorted := make([]string, len(v))
		copy(sorted, v)
		for i := range sorted {
			sorted[i] = strings.ToLower(strings.TrimSpace(sorted[i]))
		}
		sort.Strings(sorted)
		return strings.Join(sorted, ",")
	default:
		return strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", records)))
	}
}

func extractSortedSelectors(results map[string]any) string {
	dkim, ok := results["dkim_analysis"].(map[string]any)
	if !ok {
		return ""
	}
	selectors, ok := dkim["selectors"]
	if !ok {
		return ""
	}
	switch v := selectors.(type) {
	case []any:
		var names []string
		for _, s := range v {
			if m, ok := s.(map[string]any); ok {
				if name, ok := m["selector"].(string); ok {
					names = append(names, strings.ToLower(strings.TrimSpace(name)))
				}
			}
		}
		sort.Strings(names)
		return strings.Join(names, ",")
	default:
		return ""
	}
}

func extractSortedCAATags(results map[string]any) string {
	caa, ok := results["caa_analysis"].(map[string]any)
	if !ok {
		return ""
	}
	records, ok := caa["records"]
	if !ok {
		return ""
	}
	switch v := records.(type) {
	case []any:
		var tags []string
		for _, r := range v {
			if m, ok := r.(map[string]any); ok {
				tag := fmt.Sprintf("%v:%v", m["tag"], m["value"])
				tags = append(tags, strings.ToLower(strings.TrimSpace(tag)))
			}
		}
		sort.Strings(tags)
		return strings.Join(tags, ",")
	default:
		return ""
	}
}

func extractSortedMX(results map[string]any) string {
	basic, ok := results["basic_records"].(map[string]any)
	if !ok {
		return ""
	}
	mx, ok := basic["mx"]
	if !ok {
		return ""
	}
	switch v := mx.(type) {
	case []any:
		var hosts []string
		for _, r := range v {
			if m, ok := r.(map[string]any); ok {
				if host, ok := m["host"].(string); ok {
					hosts = append(hosts, strings.ToLower(strings.TrimSpace(host)))
				}
			} else {
				hosts = append(hosts, strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", r))))
			}
		}
		sort.Strings(hosts)
		return strings.Join(hosts, ",")
	default:
		return ""
	}
}

func extractSortedNS(results map[string]any) string {
	basic, ok := results["basic_records"].(map[string]any)
	if !ok {
		return ""
	}
	ns, ok := basic["ns"]
	if !ok {
		auth, ok := results["authoritative_records"].(map[string]any)
		if !ok {
			return ""
		}
		ns, ok = auth["ns"]
		if !ok {
			return ""
		}
	}
	switch v := ns.(type) {
	case []any:
		var servers []string
		for _, r := range v {
			servers = append(servers, strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", r))))
		}
		sort.Strings(servers)
		return strings.Join(servers, ",")
	case []string:
		sorted := make([]string, len(v))
		copy(sorted, v)
		for i := range sorted {
			sorted[i] = strings.ToLower(strings.TrimSpace(sorted[i]))
		}
		sort.Strings(sorted)
		return strings.Join(sorted, ",")
	default:
		return ""
	}
}
