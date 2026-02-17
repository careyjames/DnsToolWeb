// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// saas_txt.go — Framework only (types, constants). Always compiled.
// Intelligence maps and detection functions live in saas_txt_oss.go / saas_txt_intel.go.
package analyzer

import "regexp"

type saasPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

func truncateRecord(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
