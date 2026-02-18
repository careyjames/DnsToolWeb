// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import "strings"

type PostureDiffField struct {
	Label    string
	Previous string
	Current  string
	Severity string
}

func ComputePostureDiff(prev, curr map[string]any) []PostureDiffField {
	type fieldSpec struct {
		label   string
		section string
		key     string
	}

	fields := []fieldSpec{
		{"SPF Status", "spf_analysis", "status"},
		{"DMARC Status", "dmarc_analysis", "status"},
		{"DMARC Policy", "dmarc_analysis", "policy"},
		{"DKIM Status", "dkim_analysis", "status"},
		{"MTA-STS Status", "mta_sts_analysis", "status"},
		{"MTA-STS Mode", "mta_sts_analysis", "mode"},
		{"TLS-RPT Status", "tlsrpt_analysis", "status"},
		{"BIMI Status", "bimi_analysis", "status"},
		{"DANE Status", "dane_analysis", "status"},
		{"CAA Status", "caa_analysis", "status"},
		{"DNSSEC Status", "dnssec_analysis", "status"},
		{"Mail Posture", "mail_posture", "label"},
	}

	var diffs []PostureDiffField

	for _, f := range fields {
		prevVal := extractPostureField(prev, f.section, f.key)
		currVal := extractPostureField(curr, f.section, f.key)
		if prevVal != currVal {
			diffs = append(diffs, PostureDiffField{
				Label:    f.label,
				Previous: displayVal(prevVal),
				Current:  displayVal(currVal),
				Severity: classifyDriftSeverity(f.label, prevVal, currVal),
			})
		}
	}

	prevMX := extractSortedMX(prev)
	currMX := extractSortedMX(curr)
	if prevMX != currMX {
		diffs = append(diffs, PostureDiffField{
			Label:    "MX Records",
			Previous: displayVal(prevMX),
			Current:  displayVal(currMX),
			Severity: classifyDriftSeverity("MX Records", prevMX, currMX),
		})
	}

	prevNS := extractSortedNS(prev)
	currNS := extractSortedNS(curr)
	if prevNS != currNS {
		diffs = append(diffs, PostureDiffField{
			Label:    "NS Records",
			Previous: displayVal(prevNS),
			Current:  displayVal(currNS),
			Severity: classifyDriftSeverity("NS Records", prevNS, currNS),
		})
	}

	return diffs
}

func displayVal(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "(none)"
	}
	return v
}
