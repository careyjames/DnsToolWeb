package handlers

import (
        "encoding/json"
        "math"
        "sort"
        "strings"
)

type PaginationInfo struct {
        Page       int  `json:"page"`
        PerPage    int  `json:"per_page"`
        Total      int64 `json:"total"`
        TotalPages int  `json:"total_pages"`
        HasPrev    bool `json:"has_prev"`
        HasNext    bool `json:"has_next"`
}

func NewPagination(page, perPage int, total int64) PaginationInfo {
        if page < 1 {
                page = 1
        }
        totalPages := int(math.Ceil(float64(total) / float64(perPage)))
        if totalPages < 1 {
                totalPages = 1
        }
        return PaginationInfo{
                Page:       page,
                PerPage:    perPage,
                Total:      total,
                TotalPages: totalPages,
                HasPrev:    page > 1,
                HasNext:    page < totalPages,
        }
}

func (p PaginationInfo) Offset() int32 {
        return int32((p.Page - 1) * p.PerPage)
}

func (p PaginationInfo) Limit() int32 {
        return int32(p.PerPage)
}

func (p PaginationInfo) Pages() []int {
        pages := make([]int, 0, p.TotalPages)
        for i := 1; i <= p.TotalPages; i++ {
                pages = append(pages, i)
        }
        return pages
}

var normalizeDefaults = map[string]interface{}{
        "basic_records":          map[string]interface{}{},
        "authoritative_records":  map[string]interface{}{},
        "spf_analysis":           map[string]interface{}{"status": "unknown", "records": []interface{}{}},
        "dmarc_analysis":         map[string]interface{}{"status": "unknown", "policy": nil, "records": []interface{}{}},
        "dkim_analysis":          map[string]interface{}{"status": "unknown", "selectors": map[string]interface{}{}},
        "registrar_info":         map[string]interface{}{"registrar": nil, "source": nil},
        "posture":                map[string]interface{}{"state": "unknown", "label": "Unknown", "icon": "question-circle", "color": "secondary", "message": "Posture data unavailable", "deliberate_monitoring": false, "deliberate_monitoring_note": "", "issues": []interface{}{}, "monitoring": []interface{}{}, "configured": []interface{}{}, "absent": []interface{}{}},
        "dane_analysis":          map[string]interface{}{"status": "info", "has_dane": false, "tlsa_records": []interface{}{}, "issues": []interface{}{}},
        "mta_sts_analysis":       map[string]interface{}{"status": "warning"},
        "tlsrpt_analysis":        map[string]interface{}{"status": "warning"},
        "bimi_analysis":          map[string]interface{}{"status": "warning"},
        "caa_analysis":           map[string]interface{}{"status": "warning"},
        "dnssec_analysis":        map[string]interface{}{"status": "warning"},
        "ct_subdomains":          map[string]interface{}{},
        "mail_posture":           map[string]interface{}{"classification": "unknown"},
        "_data_freshness":        map[string]interface{}{},
}

var legacyPostureStates = map[string]string{
        "Low":      "Low Risk",
        "Medium":   "Medium Risk",
        "High":     "High Risk",
        "Critical": "Critical Risk",
        "STRONG":       "Secure",
        "Informational": "Secure",
        "MODERATE": "Medium Risk",
        "WEAK":     "High Risk",
        "NONE":     "Critical Risk",
}

func NormalizeResults(fullResults json.RawMessage) map[string]interface{} {
        if len(fullResults) == 0 {
                return nil
        }

        var results map[string]interface{}
        if json.Unmarshal(fullResults, &results) != nil {
                return nil
        }

        for key, defaultVal := range normalizeDefaults {
                if _, exists := results[key]; !exists {
                        results[key] = defaultVal
                }
        }

        if posture, ok := results["posture"].(map[string]interface{}); ok {
                if state, ok := posture["state"].(string); ok {
                        if normalized, found := legacyPostureStates[state]; found {
                                posture["state"] = normalized
                        }
                        if posture["state"] == "Secure" {
                                posture["color"] = "success"
                                posture["icon"] = "shield-alt"
                        }
                }
        }

        return results
}

type CompareSectionDef struct {
        Key   string
        Label string
        Icon  string
}

var CompareSections = []CompareSectionDef{
        {"spf_analysis", "SPF", "fa-envelope-open-text"},
        {"dmarc_analysis", "DMARC", "fa-shield-alt"},
        {"dkim_analysis", "DKIM", "fa-key"},
        {"dnssec_analysis", "DNSSEC", "fa-lock"},
        {"dane_analysis", "DANE / TLSA", "fa-certificate"},
        {"mta_sts_analysis", "MTA-STS", "fa-paper-plane"},
        {"tlsrpt_analysis", "TLS-RPT", "fa-file-alt"},
        {"bimi_analysis", "BIMI", "fa-image"},
        {"caa_analysis", "CAA", "fa-certificate"},
        {"posture", "Mail Posture", "fa-mail-bulk"},
}

var compareSkipKeys = map[string]bool{
        "status": true, "state": true, "_schema_version": true,
        "_tool_version": true, "_captured_at": true,
}

type DetailChange struct {
        Field string      `json:"field"`
        Old   interface{} `json:"old"`
        New   interface{} `json:"new"`
}

type SectionDiff struct {
        Key           string         `json:"key"`
        Label         string         `json:"label"`
        Icon          string         `json:"icon"`
        StatusA       string         `json:"status_a"`
        StatusB       string         `json:"status_b"`
        Changed       bool           `json:"changed"`
        DetailChanges []DetailChange `json:"detail_changes"`
}

func getStatus(section map[string]interface{}) string {
        if s, ok := section["status"].(string); ok {
                return s
        }
        if s, ok := section["state"].(string); ok {
                return s
        }
        return "unknown"
}

func ComputeSectionDiff(secA, secB map[string]interface{}, key, label, icon string) SectionDiff {
        statusA := getStatus(secA)
        statusB := getStatus(secB)

        allKeys := make(map[string]bool)
        for k := range secA {
                allKeys[k] = true
        }
        for k := range secB {
                allKeys[k] = true
        }

        sortedKeys := make([]string, 0, len(allKeys))
        for k := range allKeys {
                if !compareSkipKeys[k] {
                        sortedKeys = append(sortedKeys, k)
                }
        }
        sort.Strings(sortedKeys)

        var detailChanges []DetailChange
        for _, k := range sortedKeys {
                valA := secA[k]
                valB := secB[k]
                jsonA, _ := json.Marshal(valA)
                jsonB, _ := json.Marshal(valB)
                if string(jsonA) != string(jsonB) {
                        fieldName := strings.ReplaceAll(k, "_", " ")
                        fieldName = strings.Title(fieldName)
                        detailChanges = append(detailChanges, DetailChange{
                                Field: fieldName,
                                Old:   valA,
                                New:   valB,
                        })
                }
        }

        return SectionDiff{
                Key:           key,
                Label:         label,
                Icon:          icon,
                StatusA:       statusA,
                StatusB:       statusB,
                Changed:       statusA != statusB || len(detailChanges) > 0,
                DetailChanges: detailChanges,
        }
}

func ComputeAllDiffs(resultsA, resultsB map[string]interface{}) []SectionDiff {
        diffs := make([]SectionDiff, 0, len(CompareSections))
        for _, sec := range CompareSections {
                secA := getSection(resultsA, sec.Key)
                secB := getSection(resultsB, sec.Key)
                diffs = append(diffs, ComputeSectionDiff(secA, secB, sec.Key, sec.Label, sec.Icon))
        }
        return diffs
}

func getSection(results map[string]interface{}, key string) map[string]interface{} {
        if s, ok := results[key].(map[string]interface{}); ok {
                return s
        }
        return map[string]interface{}{}
}
