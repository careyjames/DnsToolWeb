// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package zoneparse

import (
	"fmt"
	"strings"
)

type DriftCategory string

const (
	DriftAdded   DriftCategory = "added"
	DriftMissing DriftCategory = "missing"
	DriftChanged DriftCategory = "changed"
	DriftTTLOnly DriftCategory = "ttl_only"
)

type DriftEntry struct {
	Category    DriftCategory `json:"category"`
	Name        string        `json:"name"`
	Type        string        `json:"type"`
	ZoneValue   string        `json:"zone_value,omitempty"`
	LiveValue   string        `json:"live_value,omitempty"`
	ZoneTTL     uint32        `json:"zone_ttl,omitempty"`
	LiveTTL     uint32        `json:"live_ttl,omitempty"`
	Description string        `json:"description"`
}

type DriftReport struct {
	Domain      string       `json:"domain"`
	ZoneRecords int          `json:"zone_records"`
	LiveRecords int          `json:"live_records"`
	TotalDrifts int          `json:"total_drifts"`
	Added       []DriftEntry `json:"added"`
	Missing     []DriftEntry `json:"missing"`
	Changed     []DriftEntry `json:"changed"`
	TTLOnly     []DriftEntry `json:"ttl_only"`
}

func CompareDrift(zoneRecords []ParsedRecord, liveResults map[string]any) *DriftReport {
	report := &DriftReport{
		Added:   []DriftEntry{},
		Missing: []DriftEntry{},
		Changed: []DriftEntry{},
		TTLOnly: []DriftEntry{},
	}

	liveRecords := extractLiveRecords(liveResults)
	report.ZoneRecords = len(zoneRecords)
	report.LiveRecords = len(liveRecords)

	zoneMap := buildRecordMap(zoneRecords)
	liveMap := buildRecordMap(liveRecords)

	for key, zRecs := range zoneMap {
		if _, exists := liveMap[key]; !exists {
			for _, zr := range zRecs {
				report.Added = append(report.Added, DriftEntry{
					Category:    DriftAdded,
					Name:        zr.Name,
					Type:        zr.Type,
					ZoneValue:   zr.RData,
					ZoneTTL:     zr.TTL,
					Description: fmt.Sprintf("Record %s %s exists in zone file but was not observed in live DNS", zr.Name, zr.Type),
				})
			}
		}
	}

	for key, lRecs := range liveMap {
		if _, exists := zoneMap[key]; !exists {
			for _, lr := range lRecs {
				report.Missing = append(report.Missing, DriftEntry{
					Category:    DriftMissing,
					Name:        lr.Name,
					Type:        lr.Type,
					LiveValue:   lr.RData,
					LiveTTL:     lr.TTL,
					Description: fmt.Sprintf("Record %s %s observed in live DNS but not in zone file", lr.Name, lr.Type),
				})
			}
		}
	}

	for key, zRecs := range zoneMap {
		lRecs, exists := liveMap[key]
		if !exists {
			continue
		}

		zDataSet := make(map[string]uint32)
		for _, zr := range zRecs {
			zDataSet[normalizeRData(zr.RData)] = zr.TTL
		}
		lDataSet := make(map[string]uint32)
		for _, lr := range lRecs {
			lDataSet[normalizeRData(lr.RData)] = lr.TTL
		}

		for zData, zTTL := range zDataSet {
			if lTTL, found := lDataSet[zData]; found {
				if zTTL != lTTL {
					parts := strings.SplitN(key, "|", 2)
					name, rtype := parts[0], parts[1]
					report.TTLOnly = append(report.TTLOnly, DriftEntry{
						Category:    DriftTTLOnly,
						Name:        name,
						Type:        rtype,
						ZoneValue:   zData,
						LiveValue:   zData,
						ZoneTTL:     zTTL,
						LiveTTL:     lTTL,
						Description: fmt.Sprintf("TTL differs for %s %s: zone=%d, live=%d", name, rtype, zTTL, lTTL),
					})
				}
			} else {
				parts := strings.SplitN(key, "|", 2)
				name, rtype := parts[0], parts[1]
				liveValues := make([]string, 0, len(lDataSet))
				for ld := range lDataSet {
					liveValues = append(liveValues, ld)
				}
				report.Changed = append(report.Changed, DriftEntry{
					Category:    DriftChanged,
					Name:        name,
					Type:        rtype,
					ZoneValue:   zData,
					LiveValue:   strings.Join(liveValues, "; "),
					ZoneTTL:     zTTL,
					Description: fmt.Sprintf("Value differs for %s %s", name, rtype),
				})
			}
		}
	}

	report.TotalDrifts = len(report.Added) + len(report.Missing) + len(report.Changed) + len(report.TTLOnly)
	return report
}

func buildRecordMap(records []ParsedRecord) map[string][]ParsedRecord {
	m := make(map[string][]ParsedRecord)
	for _, r := range records {
		key := strings.ToLower(r.Name) + "|" + r.Type
		m[key] = append(m[key], r)
	}
	return m
}

func normalizeRData(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.Trim(s, `"`)
	return s
}

func extractLiveRecords(results map[string]any) []ParsedRecord {
	var records []ParsedRecord

	basic, _ := results["basic_records"].(map[string]any)
	if basic == nil {
		return records
	}

	ttls := extractTTLs(results)
	domain := ""
	if d, ok := results["domain"].(string); ok {
		domain = d
	}
	fqdn := strings.ToLower(domain) + "."

	simpleTypes := []string{"A", "AAAA", "NS", "CNAME"}
	for _, rtype := range simpleTypes {
		if vals, ok := basic[rtype]; ok {
			if arr, ok := vals.([]any); ok {
				for _, v := range arr {
					if s, ok := v.(string); ok && s != "" {
						records = append(records, ParsedRecord{
							Name:  fqdn,
							TTL:   ttls[rtype],
							Class: "IN",
							Type:  rtype,
							RData: s,
						})
					}
				}
			}
		}
	}

	if mxVals, ok := basic["MX"]; ok {
		if arr, ok := mxVals.([]any); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok && s != "" {
					records = append(records, ParsedRecord{
						Name:  fqdn,
						TTL:   ttls["MX"],
						Class: "IN",
						Type:  "MX",
						RData: s,
					})
				}
			}
		}
	}

	if txtVals, ok := basic["TXT"]; ok {
		if arr, ok := txtVals.([]any); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok && s != "" {
					records = append(records, ParsedRecord{
						Name:  fqdn,
						TTL:   ttls["TXT"],
						Class: "IN",
						Type:  "TXT",
						RData: s,
					})
				}
			}
		}
	}

	if soaVals, ok := basic["SOA"]; ok {
		if arr, ok := soaVals.([]any); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok && s != "" {
					records = append(records, ParsedRecord{
						Name:  fqdn,
						TTL:   ttls["SOA"],
						Class: "IN",
						Type:  "SOA",
						RData: s,
					})
				}
			}
		}
	}

	if caaVals, ok := basic["CAA"]; ok {
		if arr, ok := caaVals.([]any); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok && s != "" {
					records = append(records, ParsedRecord{
						Name:  fqdn,
						TTL:   ttls["CAA"],
						Class: "IN",
						Type:  "CAA",
						RData: s,
					})
				}
			}
		}
	}

	return records
}

func extractTTLs(results map[string]any) map[string]uint32 {
	ttls := make(map[string]uint32)
	if rttl, ok := results["resolver_ttl"]; ok {
		if m, ok := rttl.(map[string]any); ok {
			for k, v := range m {
				if f, ok := v.(float64); ok {
					ttls[k] = uint32(f)
				}
			}
		}
	}
	return ttls
}
