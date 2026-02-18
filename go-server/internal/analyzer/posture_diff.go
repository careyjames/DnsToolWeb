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

        type sortedSpec struct {
                label string
                fn    func(map[string]any) string
        }
        sortedFields := []sortedSpec{
                {"DKIM Selectors", extractSortedSelectors},
                {"CAA Tags", extractSortedCAATags},
                {"SPF Records", func(r map[string]any) string { return extractSortedRecords(r, "spf_analysis", "records") }},
                {"DMARC Records", func(r map[string]any) string { return extractSortedRecords(r, "dmarc_analysis", "records") }},
                {"MX Records", extractSortedMX},
                {"NS Records", extractSortedNS},
        }
        for _, sf := range sortedFields {
                prevVal := sf.fn(prev)
                currVal := sf.fn(curr)
                if prevVal != currVal {
                        diffs = append(diffs, PostureDiffField{
                                Label:    sf.label,
                                Previous: displayVal(prevVal),
                                Current:  displayVal(currVal),
                                Severity: classifyDriftSeverity(sf.label, prevVal, currVal),
                        })
                }
        }

        prevDANE := extractPostureBool(prev, "dane_analysis", "has_dane")
        currDANE := extractPostureBool(curr, "dane_analysis", "has_dane")
        if prevDANE != currDANE {
                diffs = append(diffs, PostureDiffField{
                        Label:    "DANE Present",
                        Previous: displayVal(prevDANE),
                        Current:  displayVal(currDANE),
                        Severity: classifyDriftSeverity("DANE Present", prevDANE, currDANE),
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
