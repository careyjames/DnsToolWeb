// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "encoding/json"
        "fmt"
        "math"
        "sort"
        "strings"

        "golang.org/x/net/publicsuffix"
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
                normalizeVerdicts(results, posture)
        }

        return results
}

func normalizeVerdicts(results, posture map[string]interface{}) {
        verdicts, ok := posture["verdicts"].(map[string]interface{})
        if !ok {
                return
        }

        normalizeVerdictAnswers(verdicts)
        normalizeAIVerdicts(results, verdicts)
        normalizeEmailAnswer(verdicts)
}

func normalizeEmailAnswer(verdicts map[string]interface{}) {
        if _, has := verdicts["email_answer_short"]; has {
                return
        }
        emailAnswer, ok := verdicts["email_answer"].(string)
        if !ok || emailAnswer == "" {
                return
        }
        parts := strings.SplitN(emailAnswer, " — ", 2)
        if len(parts) == 2 {
                answer := parts[0]
                reason := parts[1]
                color := "warning"
                switch {
                case answer == "No" || answer == "Unlikely":
                        color = "success"
                case answer == "Yes" || answer == "Likely":
                        color = "danger"
                case answer == "Partially" || answer == "Uncertain":
                        color = "warning"
                }
                verdicts["email_answer_short"] = answer
                verdicts["email_answer_reason"] = reason
                verdicts["email_answer_color"] = color
        }
}

func normalizeVerdictAnswers(verdicts map[string]interface{}) {
        answerMap := map[string]map[string]string{
                "dns_tampering": {
                        "Protected":      "No",
                        "Exposed":        "Yes",
                        "Not Configured": "Possible",
                },
                "brand_impersonation": {
                        "Protected":          "No",
                        "Exposed":            "Yes",
                        "Mostly Protected":   "Possible",
                        "Partially Protected": "Possible",
                        "Basic":              "Likely",
                },
                "certificate_control": {
                        "Configured":     "Yes",
                        "Not Configured": "No",
                },
                "transport": {
                        "Fully Protected": "Yes",
                        "Protected":       "Yes",
                        "Monitoring":      "Partially",
                        "Not Enforced":    "No",
                },
        }

        reasonPrefixes := []string{"No — ", "Yes — ", "Possible — "}

        for key, labelToAnswer := range answerMap {
                v, ok := verdicts[key].(map[string]interface{})
                if !ok {
                        continue
                }
                if _, hasAnswer := v["answer"]; hasAnswer {
                        continue
                }
                label, _ := v["label"].(string)
                if ans, found := labelToAnswer[label]; found {
                        v["answer"] = ans
                }
                if reason, ok := v["reason"].(string); ok {
                        for _, prefix := range reasonPrefixes {
                                if strings.HasPrefix(reason, prefix) {
                                        v["reason"] = strings.TrimPrefix(reason, prefix)
                                        break
                                }
                        }
                }
        }
}

func normalizeAIVerdicts(results, verdicts map[string]interface{}) {
        if _, has := verdicts["ai_llms_txt"]; has {
                return
        }

        aiSurface, ok := results["ai_surface"].(map[string]interface{})
        if !ok {
                return
        }

        if llmsTxt, ok := aiSurface["llms_txt"].(map[string]interface{}); ok {
                found, _ := llmsTxt["found"].(bool)
                fullFound, _ := llmsTxt["full_found"].(bool)
                if found && fullFound {
                        verdicts["ai_llms_txt"] = map[string]interface{}{"answer": "Yes", "color": "success", "reason": "llms.txt and llms-full.txt published — AI models receive structured context about this domain"}
                } else if found {
                        verdicts["ai_llms_txt"] = map[string]interface{}{"answer": "Yes", "color": "success", "reason": "llms.txt published — AI models receive structured context about this domain"}
                } else {
                        verdicts["ai_llms_txt"] = map[string]interface{}{"answer": "No", "color": "secondary", "reason": "No llms.txt file detected — AI models have no structured instructions for this domain"}
                }
        }

        if robotsTxt, ok := aiSurface["robots_txt"].(map[string]interface{}); ok {
                found, _ := robotsTxt["found"].(bool)
                blocksAI, _ := robotsTxt["blocks_ai_crawlers"].(bool)
                if found && blocksAI {
                        verdicts["ai_crawler_governance"] = map[string]interface{}{"answer": "Yes", "color": "success", "reason": "robots.txt actively blocks AI crawlers from scraping site content"}
                } else if found {
                        verdicts["ai_crawler_governance"] = map[string]interface{}{"answer": "No", "color": "warning", "reason": "robots.txt present but does not block AI crawlers — content may be freely scraped"}
                } else {
                        verdicts["ai_crawler_governance"] = map[string]interface{}{"answer": "No", "color": "secondary", "reason": "No robots.txt found — AI crawlers have unrestricted access"}
                }
        }

        if poisoning, ok := aiSurface["poisoning"].(map[string]interface{}); ok {
                iocCount := getNumValue(poisoning, "ioc_count")
                if iocCount > 0 {
                        verdicts["ai_poisoning"] = map[string]interface{}{"answer": "Yes", "color": "danger", "reason": fmt.Sprintf("%.0f indicator(s) of AI recommendation manipulation detected on homepage", iocCount)}
                } else {
                        verdicts["ai_poisoning"] = map[string]interface{}{"answer": "No", "color": "success", "reason": "No indicators of AI recommendation manipulation found"}
                }
        }

        if hidden, ok := aiSurface["hidden_prompts"].(map[string]interface{}); ok {
                count := getNumValue(hidden, "artifact_count")
                if count > 0 {
                        verdicts["ai_hidden_prompts"] = map[string]interface{}{"answer": "Yes", "color": "danger", "reason": fmt.Sprintf("%.0f hidden prompt-like artifact(s) detected in page source", count)}
                } else {
                        verdicts["ai_hidden_prompts"] = map[string]interface{}{"answer": "No", "color": "success", "reason": "No hidden prompt artifacts found in page source"}
                }
        }
}

func getNumValue(m map[string]interface{}, key string) float64 {
        v, ok := m[key]
        if !ok {
                return 0
        }
        switch n := v.(type) {
        case float64:
                return n
        case int:
                return float64(n)
        case int64:
                return float64(n)
        }
        return 0
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

func extractRootDomain(domain string) (isSubdomain bool, root string) {
        domain = strings.TrimRight(domain, ".")
        registrable, err := publicsuffix.EffectiveTLDPlusOne(domain)
        if err != nil {
                return false, ""
        }
        if strings.EqualFold(domain, registrable) {
                return false, ""
        }
        return true, registrable
}
