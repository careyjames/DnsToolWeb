//go:build !intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Stub implementations. See github.com/careyjames/dnstool-intel for the full version.
package analyzer

var saasPatterns = []saasPattern{}

func ExtractSaaSTXTFootprint(results map[string]any) map[string]any {
	basicRecords, ok := results["basic_records"].(map[string]any)
	if !ok {
		return map[string]any{
			"status":        "success",
			"services":      []map[string]any{},
			"service_count": 0,
			"issues":        []string{},
			"message":       "No SaaS services detected",
		}
	}

	txtRaw, ok := basicRecords["TXT"]
	if !ok {
		return map[string]any{
			"status":        "success",
			"services":      []map[string]any{},
			"service_count": 0,
			"issues":        []string{},
			"message":       "No SaaS services detected",
		}
	}

	var txtAsAny []any
	switch v := txtRaw.(type) {
	case []string:
		for _, s := range v {
			txtAsAny = append(txtAsAny, s)
		}
	case []any:
		txtAsAny = v
	default:
		return map[string]any{
			"status":        "success",
			"services":      []map[string]any{},
			"service_count": 0,
			"issues":        []string{},
			"message":       "No SaaS services detected",
		}
	}

	if len(txtAsAny) == 0 {
		return map[string]any{
			"status":        "success",
			"services":      []map[string]any{},
			"service_count": 0,
			"issues":        []string{},
			"message":       "No SaaS services detected",
		}
	}

	return extractSaaSTXTFromRecords(txtAsAny, commoditySaaSPatterns)
}

func matchSaaSPatterns(txt string, seen map[string]bool, services *[]map[string]any) {
}
