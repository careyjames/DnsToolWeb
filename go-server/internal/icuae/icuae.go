// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// ICuAE — Intelligence Currency Audit Engine
//
// Companion to ICAE (Intelligence Confidence Audit Engine).
// ICAE answers: "Did we interpret the DNS data correctly?"
// ICuAE answers: "Is the DNS data still valid/current?"
//
// Grounded in five authoritative standards:
//   - ICD 203 (CIA): Timeliness as core analytic standard
//   - NIST SP 800-53 SI-18: Accuracy, Relevance, Timeliness, Completeness
//   - ISO/IEC 25012: Currentness — data of the right age for its context
//   - RFC 8767: TTL-based cache expiration and serve-stale behavior
//   - SPJ Code of Ethics: Multiple independent sources for verification
package icuae

import "fmt"

const (
        DimensionCurrentness      = "currentness"
        DimensionTTLCompliance    = "ttl_compliance"
        DimensionCompleteness     = "completeness"
        DimensionSourceCredibility = "source_credibility"
        DimensionTTLRelevance     = "ttl_relevance"

        GradeExcellent = "excellent"
        GradeGood      = "good"
        GradeAdequate  = "adequate"
        GradeDegraded  = "degraded"
        GradeStale     = "stale"
)

var DimensionDisplayNames = map[string]string{
        DimensionCurrentness:       "Currentness",
        DimensionTTLCompliance:     "TTL Compliance",
        DimensionCompleteness:      "Completeness",
        DimensionSourceCredibility: "Source Credibility",
        DimensionTTLRelevance:      "TTL Relevance",
}

var DimensionStandards = map[string]string{
        DimensionCurrentness:       "ISO/IEC 25012",
        DimensionTTLCompliance:     "RFC 8767",
        DimensionCompleteness:      "NIST SP 800-53 SI-18",
        DimensionSourceCredibility: "ISO/IEC 25012 + SPJ",
        DimensionTTLRelevance:      "NIST SP 800-53 SI-18",
}

var GradeOrder = map[string]int{
        GradeExcellent: 4,
        GradeGood:      3,
        GradeAdequate:  2,
        GradeDegraded:  1,
        GradeStale:     0,
}

var GradeDisplayNames = map[string]string{
        GradeExcellent: "Excellent",
        GradeGood:      "Good",
        GradeAdequate:  "Adequate",
        GradeDegraded:  "Degraded",
        GradeStale:     "Stale",
}

var GradeBootstrapClass = map[string]string{
        GradeExcellent: "success",
        GradeGood:      "success",
        GradeAdequate:  "info",
        GradeDegraded:  "warning",
        GradeStale:     "danger",
}

type DimensionScore struct {
        Dimension   string  `json:"dimension"`
        Standard    string  `json:"standard"`
        Grade       string  `json:"grade"`
        Score       float64 `json:"score"`
        Details     string  `json:"details"`
        RecordTypes int     `json:"record_types_evaluated"`
}

type CurrencyReport struct {
        OverallGrade string           `json:"overall_grade"`
        OverallScore float64          `json:"overall_score"`
        Dimensions   []DimensionScore `json:"dimensions"`
        ResolverCount int             `json:"resolver_count"`
        RecordCount   int             `json:"record_count"`
        Guidance      string          `json:"guidance"`
}

func (r CurrencyReport) BootstrapClass() string {
        if c, ok := GradeBootstrapClass[r.OverallGrade]; ok {
                return c
        }
        return "secondary"
}

func (r CurrencyReport) OverallGradeDisplay() string {
        if d, ok := GradeDisplayNames[r.OverallGrade]; ok {
                return d
        }
        return "Unknown"
}

func (d DimensionScore) BootstrapClass() string {
        if c, ok := GradeBootstrapClass[d.Grade]; ok {
                return c
        }
        return "secondary"
}

func (d DimensionScore) GradeDisplay() string {
        if g, ok := GradeDisplayNames[d.Grade]; ok {
                return g
        }
        return "Unknown"
}

func (d DimensionScore) DisplayName() string {
        if n, ok := DimensionDisplayNames[d.Dimension]; ok {
                return n
        }
        return d.Dimension
}

type RecordCurrency struct {
        RecordType  string  `json:"record_type"`
        ObservedTTL uint32  `json:"observed_ttl"`
        TypicalTTL  uint32  `json:"typical_ttl"`
        DataAgeS    float64 `json:"data_age_seconds"`
        TTLRatio    float64 `json:"ttl_ratio"`
}

type ResolverAgreement struct {
        RecordType    string `json:"record_type"`
        AgreeCount    int    `json:"agree_count"`
        TotalResolvers int   `json:"total_resolvers"`
        Unanimous     bool   `json:"unanimous"`
}

var typicalTTLs = map[string]uint32{
        "A":       300,
        "AAAA":    300,
        "MX":      3600,
        "TXT":     3600,
        "NS":      86400,
        "CNAME":   300,
        "CAA":     3600,
        "SOA":     3600,
        "SPF":     3600,
        "DMARC":   3600,
        "DKIM":    3600,
        "MTA-STS": 86400,
        "TLS-RPT": 3600,
        "BIMI":    3600,
        "TLSA":    3600,
        "DNSSEC":  86400,
        "DANE":    3600,
}

var expectedRecordTypes = []string{
        "A", "AAAA", "MX", "TXT", "NS", "SOA",
        "SPF", "DMARC", "DKIM", "MTA-STS", "TLS-RPT",
        "BIMI", "TLSA", "DNSSEC", "CAA",
}

func TypicalTTLFor(recordType string) uint32 {
        if ttl, ok := typicalTTLs[recordType]; ok {
                return ttl
        }
        return 300
}

func scoreToGrade(score float64) string {
        switch {
        case score >= 90:
                return GradeExcellent
        case score >= 75:
                return GradeGood
        case score >= 50:
                return GradeAdequate
        case score >= 25:
                return GradeDegraded
        default:
                return GradeStale
        }
}

func EvaluateCurrentness(records []RecordCurrency) DimensionScore {
        if len(records) == 0 {
                return DimensionScore{
                        Dimension:   DimensionCurrentness,
                        Standard:    DimensionStandards[DimensionCurrentness],
                        Grade:       GradeStale,
                        Score:       0,
                        Details:     "No record currency data available",
                        RecordTypes: 0,
                }
        }

        totalScore := 0.0
        for _, r := range records {
                validWindow := float64(r.ObservedTTL)
                if validWindow == 0 {
                        validWindow = float64(r.TypicalTTL)
                }
                if validWindow == 0 {
                        validWindow = 300
                }

                if r.DataAgeS <= validWindow {
                        totalScore += 100.0
                } else if r.DataAgeS <= validWindow*2 {
                        totalScore += 50.0
                } else {
                        totalScore += 0.0
                }
        }

        avg := totalScore / float64(len(records))
        return DimensionScore{
                Dimension:   DimensionCurrentness,
                Standard:    DimensionStandards[DimensionCurrentness],
                Grade:       scoreToGrade(avg),
                Score:       avg,
                Details:     currentnessDetails(avg, len(records)),
                RecordTypes: len(records),
        }
}

func currentnessDetails(score float64, count int) string {
        grade := scoreToGrade(score)
        switch grade {
        case GradeExcellent:
                return "All record data is within its TTL validity window"
        case GradeGood:
                return "Most record data is within its TTL validity window"
        case GradeAdequate:
                return "Some records may have aged beyond their TTL windows"
        case GradeDegraded:
                return "Multiple records have aged beyond TTL validity — consider re-scanning"
        default:
                return "Record data has significantly aged beyond TTL windows — re-scan recommended"
        }
}

func EvaluateTTLCompliance(resolverTTLs, authTTLs map[string]uint32) DimensionScore {
        if len(authTTLs) == 0 {
                return DimensionScore{
                        Dimension:   DimensionTTLCompliance,
                        Standard:    DimensionStandards[DimensionTTLCompliance],
                        Grade:       GradeAdequate,
                        Score:       50,
                        Details:     "No authoritative TTL data for comparison",
                        RecordTypes: 0,
                }
        }

        compliant := 0
        total := 0
        for rt, authTTL := range authTTLs {
                resTTL, ok := resolverTTLs[rt]
                if !ok {
                        continue
                }
                total++
                if resTTL <= authTTL {
                        compliant++
                }
        }

        if total == 0 {
                return DimensionScore{
                        Dimension:   DimensionTTLCompliance,
                        Standard:    DimensionStandards[DimensionTTLCompliance],
                        Grade:       GradeAdequate,
                        Score:       50,
                        Details:     "No overlapping resolver/authoritative records for TTL comparison",
                        RecordTypes: 0,
                }
        }

        score := (float64(compliant) / float64(total)) * 100
        return DimensionScore{
                Dimension:   DimensionTTLCompliance,
                Standard:    DimensionStandards[DimensionTTLCompliance],
                Grade:       scoreToGrade(score),
                Score:       score,
                Details:     ttlComplianceDetails(compliant, total),
                RecordTypes: total,
        }
}

func ttlComplianceDetails(compliant, total int) string {
        if compliant == total {
                return "All resolver TTLs are within authoritative limits (RFC 8767 compliant)"
        }
        violated := total - compliant
        if violated == 1 {
                return "1 resolver TTL exceeds its authoritative value — possible caching violation"
        }
        return fmt.Sprintf("%d of %d resolver TTLs exceed authoritative values — possible caching violations", violated, total)
}

func EvaluateCompleteness(observedTypes map[string]bool) DimensionScore {
        found := 0
        for _, rt := range expectedRecordTypes {
                if observedTypes[rt] {
                        found++
                }
        }

        score := (float64(found) / float64(len(expectedRecordTypes))) * 100
        return DimensionScore{
                Dimension:   DimensionCompleteness,
                Standard:    DimensionStandards[DimensionCompleteness],
                Grade:       scoreToGrade(score),
                Score:       score,
                Details:     completenessDetails(found, len(expectedRecordTypes)),
                RecordTypes: found,
        }
}

func completenessDetails(found, total int) string {
        if found == total {
                return "All expected record types have authoritative TTL data"
        }
        missing := total - found
        if missing == 1 {
                return "1 expected record type is missing TTL data"
        }
        return fmt.Sprintf("%d of %d expected record types are missing TTL data", missing, total)
}

func EvaluateSourceCredibility(agreements []ResolverAgreement) DimensionScore {
        if len(agreements) == 0 {
                return DimensionScore{
                        Dimension:   DimensionSourceCredibility,
                        Standard:    DimensionStandards[DimensionSourceCredibility],
                        Grade:       GradeStale,
                        Score:       0,
                        Details:     "No multi-resolver data available for credibility assessment",
                        RecordTypes: 0,
                }
        }

        totalScore := 0.0
        for _, a := range agreements {
                if a.TotalResolvers == 0 {
                        continue
                }
                ratio := float64(a.AgreeCount) / float64(a.TotalResolvers)
                totalScore += ratio * 100
        }

        avg := totalScore / float64(len(agreements))
        return DimensionScore{
                Dimension:   DimensionSourceCredibility,
                Standard:    DimensionStandards[DimensionSourceCredibility],
                Grade:       scoreToGrade(avg),
                Score:       avg,
                Details:     credibilityDetails(avg),
                RecordTypes: len(agreements),
        }
}

func credibilityDetails(score float64) string {
        grade := scoreToGrade(score)
        switch grade {
        case GradeExcellent:
                return "All resolvers return consistent data — high source credibility"
        case GradeGood:
                return "Most resolvers agree — good source credibility"
        case GradeAdequate:
                return "Some resolver disagreements detected — moderate credibility"
        case GradeDegraded:
                return "Significant resolver disagreements — credibility concerns"
        default:
                return "Resolvers return conflicting data — investigate DNS propagation"
        }
}

func EvaluateTTLRelevance(resolverTTLs map[string]uint32) DimensionScore {
        if len(resolverTTLs) == 0 {
                return DimensionScore{
                        Dimension:   DimensionTTLRelevance,
                        Standard:    DimensionStandards[DimensionTTLRelevance],
                        Grade:       GradeAdequate,
                        Score:       50,
                        Details:     "No TTL data available for relevance analysis",
                        RecordTypes: 0,
                }
        }

        totalScore := 0.0
        evaluated := 0
        for rt, observedTTL := range resolverTTLs {
                typical, ok := typicalTTLs[rt]
                if !ok {
                        continue
                }
                evaluated++
                ratio := float64(observedTTL) / float64(typical)
                switch {
                case ratio >= 0.5 && ratio <= 2.0:
                        totalScore += 100
                case ratio >= 0.1 && ratio <= 5.0:
                        totalScore += 50
                default:
                        totalScore += 0
                }
        }

        if evaluated == 0 {
                return DimensionScore{
                        Dimension:   DimensionTTLRelevance,
                        Standard:    DimensionStandards[DimensionTTLRelevance],
                        Grade:       GradeAdequate,
                        Score:       50,
                        Details:     "No matching record types for TTL relevance comparison",
                        RecordTypes: 0,
                }
        }

        avg := totalScore / float64(evaluated)
        return DimensionScore{
                Dimension:   DimensionTTLRelevance,
                Standard:    DimensionStandards[DimensionTTLRelevance],
                Grade:       scoreToGrade(avg),
                Score:       avg,
                Details:     ttlRelevanceDetails(avg),
                RecordTypes: evaluated,
        }
}

func ttlRelevanceDetails(score float64) string {
        grade := scoreToGrade(score)
        switch grade {
        case GradeExcellent:
                return "All observed TTLs are within typical ranges for their record types"
        case GradeGood:
                return "Most TTLs are within expected ranges"
        case GradeAdequate:
                return "Some TTLs deviate from typical ranges — may indicate custom configuration"
        case GradeDegraded:
                return "Multiple TTLs significantly deviate from standards — review DNS configuration"
        default:
                return "TTL values are far outside expected ranges — possible misconfiguration"
        }
}

func BuildCurrencyReport(
        records []RecordCurrency,
        resolverTTLs, authTTLs map[string]uint32,
        observedTypes map[string]bool,
        agreements []ResolverAgreement,
        resolverCount int,
) CurrencyReport {
        dims := []DimensionScore{
                EvaluateCurrentness(records),
                EvaluateTTLCompliance(resolverTTLs, authTTLs),
                EvaluateCompleteness(observedTypes),
                EvaluateSourceCredibility(agreements),
                EvaluateTTLRelevance(resolverTTLs),
        }

        totalScore := 0.0
        for _, d := range dims {
                totalScore += d.Score
        }
        overallScore := totalScore / float64(len(dims))

        return CurrencyReport{
                OverallGrade:  scoreToGrade(overallScore),
                OverallScore:  overallScore,
                Dimensions:    dims,
                ResolverCount: resolverCount,
                RecordCount:   len(records),
                Guidance:      overallGuidance(overallScore),
        }
}

func overallGuidance(score float64) string {
        grade := scoreToGrade(score)
        switch grade {
        case GradeExcellent:
                return "DNS data is fresh, consistent, and comprehensive — high intelligence currency"
        case GradeGood:
                return "DNS data is mostly current with minor gaps — good intelligence currency"
        case GradeAdequate:
                return "DNS data shows some aging or gaps — consider re-scanning for critical decisions"
        case GradeDegraded:
                return "DNS data currency is degraded — re-scan recommended before making security decisions"
        default:
                return "DNS data may be stale — immediate re-scan strongly recommended"
        }
}
