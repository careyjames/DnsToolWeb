// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package icuae

import (
        "testing"
)

func TestScoreToGrade(t *testing.T) {
        tests := []struct {
                score float64
                want  string
        }{
                {100, GradeExcellent},
                {95, GradeExcellent},
                {90, GradeExcellent},
                {89.9, GradeGood},
                {75, GradeGood},
                {74.9, GradeAdequate},
                {50, GradeAdequate},
                {49.9, GradeDegraded},
                {25, GradeDegraded},
                {24.9, GradeStale},
                {0, GradeStale},
        }
        for _, tt := range tests {
                got := scoreToGrade(tt.score)
                if got != tt.want {
                        t.Errorf("scoreToGrade(%v) = %q, want %q", tt.score, got, tt.want)
                }
        }
}

func TestEvaluateCurrentness_AllFresh(t *testing.T) {
        records := []RecordCurrency{
                {RecordType: "A", ObservedTTL: 300, DataAgeS: 100},
                {RecordType: "MX", ObservedTTL: 3600, DataAgeS: 1000},
                {RecordType: "TXT", ObservedTTL: 3600, DataAgeS: 500},
        }
        result := EvaluateCurrentness(records)
        if result.Grade != GradeExcellent {
                t.Errorf("all fresh records: expected %q, got %q (score: %.1f)", GradeExcellent, result.Grade, result.Score)
        }
        if result.Score != 100 {
                t.Errorf("all fresh records: expected score 100, got %.1f", result.Score)
        }
        if result.RecordTypes != 3 {
                t.Errorf("expected 3 record types, got %d", result.RecordTypes)
        }
}

func TestEvaluateCurrentness_AllStale(t *testing.T) {
        records := []RecordCurrency{
                {RecordType: "A", ObservedTTL: 300, DataAgeS: 700},
                {RecordType: "MX", ObservedTTL: 3600, DataAgeS: 8000},
        }
        result := EvaluateCurrentness(records)
        if result.Grade != GradeStale {
                t.Errorf("all stale records: expected %q, got %q (score: %.1f)", GradeStale, result.Grade, result.Score)
        }
        if result.Score != 0 {
                t.Errorf("all stale records: expected score 0, got %.1f", result.Score)
        }
}

func TestEvaluateCurrentness_Mixed(t *testing.T) {
        records := []RecordCurrency{
                {RecordType: "A", ObservedTTL: 300, DataAgeS: 100},
                {RecordType: "MX", ObservedTTL: 3600, DataAgeS: 5000},
        }
        result := EvaluateCurrentness(records)
        if result.Score != 75 {
                t.Errorf("mixed: expected score 75 (100+50)/2, got %.1f", result.Score)
        }
        if result.Grade != GradeGood {
                t.Errorf("mixed: expected %q, got %q", GradeGood, result.Grade)
        }
}

func TestEvaluateCurrentness_Empty(t *testing.T) {
        result := EvaluateCurrentness(nil)
        if result.Grade != GradeStale {
                t.Errorf("empty: expected %q, got %q", GradeStale, result.Grade)
        }
        if result.Score != 0 {
                t.Errorf("empty: expected score 0, got %.1f", result.Score)
        }
}

func TestEvaluateCurrentness_ZeroTTLFallback(t *testing.T) {
        records := []RecordCurrency{
                {RecordType: "A", ObservedTTL: 0, TypicalTTL: 300, DataAgeS: 100},
        }
        result := EvaluateCurrentness(records)
        if result.Score != 100 {
                t.Errorf("zero TTL fallback to typical: expected score 100, got %.1f", result.Score)
        }
}

func TestEvaluateCurrentness_BothTTLZeroDefaultsFallback(t *testing.T) {
        records := []RecordCurrency{
                {RecordType: "CUSTOM", ObservedTTL: 0, TypicalTTL: 0, DataAgeS: 100},
        }
        result := EvaluateCurrentness(records)
        if result.Score != 100 {
                t.Errorf("both TTLs zero, default 300, age 100: expected score 100, got %.1f", result.Score)
        }
}

func TestEvaluateTTLCompliance_AllCompliant(t *testing.T) {
        resolver := map[string]uint32{"A": 200, "MX": 3000}
        auth := map[string]uint32{"A": 300, "MX": 3600}
        result := EvaluateTTLCompliance(resolver, auth)
        if result.Score != 100 {
                t.Errorf("all compliant: expected 100, got %.1f", result.Score)
        }
        if result.Grade != GradeExcellent {
                t.Errorf("all compliant: expected %q, got %q", GradeExcellent, result.Grade)
        }
}

func TestEvaluateTTLCompliance_OneViolation(t *testing.T) {
        resolver := map[string]uint32{"A": 500, "MX": 3000}
        auth := map[string]uint32{"A": 300, "MX": 3600}
        result := EvaluateTTLCompliance(resolver, auth)
        if result.Score != 50 {
                t.Errorf("one violation: expected 50, got %.1f", result.Score)
        }
}

func TestEvaluateTTLCompliance_NoAuthData(t *testing.T) {
        resolver := map[string]uint32{"A": 300}
        result := EvaluateTTLCompliance(resolver, map[string]uint32{})
        if result.Grade != GradeAdequate {
                t.Errorf("no auth data: expected %q, got %q", GradeAdequate, result.Grade)
        }
        if result.Score != 50 {
                t.Errorf("no auth data: expected 50, got %.1f", result.Score)
        }
}

func TestEvaluateTTLCompliance_EqualTTL(t *testing.T) {
        resolver := map[string]uint32{"A": 300}
        auth := map[string]uint32{"A": 300}
        result := EvaluateTTLCompliance(resolver, auth)
        if result.Score != 100 {
                t.Errorf("equal TTL should be compliant: expected 100, got %.1f", result.Score)
        }
}

func TestEvaluateCompleteness_AllPresent(t *testing.T) {
        observed := map[string]bool{}
        for _, rt := range expectedRecordTypes {
                observed[rt] = true
        }
        result := EvaluateCompleteness(observed)
        if result.Score != 100 {
                t.Errorf("all present: expected 100, got %.1f", result.Score)
        }
        if result.Grade != GradeExcellent {
                t.Errorf("all present: expected %q, got %q", GradeExcellent, result.Grade)
        }
}

func TestEvaluateCompleteness_NonePresent(t *testing.T) {
        result := EvaluateCompleteness(map[string]bool{})
        if result.Score != 0 {
                t.Errorf("none present: expected 0, got %.1f", result.Score)
        }
        if result.Grade != GradeStale {
                t.Errorf("none present: expected %q, got %q", GradeStale, result.Grade)
        }
}

func TestEvaluateCompleteness_Partial(t *testing.T) {
        observed := map[string]bool{
                "A": true, "AAAA": true, "MX": true, "TXT": true,
                "NS": true, "SOA": true, "SPF": true, "DMARC": true,
        }
        result := EvaluateCompleteness(observed)
        expected := (float64(8) / float64(len(expectedRecordTypes))) * 100
        if result.Score != expected {
                t.Errorf("partial: expected %.1f, got %.1f", expected, result.Score)
        }
}

func TestEvaluateSourceCredibility_AllUnanimous(t *testing.T) {
        agreements := []ResolverAgreement{
                {RecordType: "A", AgreeCount: 5, TotalResolvers: 5, Unanimous: true},
                {RecordType: "MX", AgreeCount: 5, TotalResolvers: 5, Unanimous: true},
        }
        result := EvaluateSourceCredibility(agreements)
        if result.Score != 100 {
                t.Errorf("all unanimous: expected 100, got %.1f", result.Score)
        }
        if result.Grade != GradeExcellent {
                t.Errorf("all unanimous: expected %q, got %q", GradeExcellent, result.Grade)
        }
}

func TestEvaluateSourceCredibility_PartialAgreement(t *testing.T) {
        agreements := []ResolverAgreement{
                {RecordType: "A", AgreeCount: 3, TotalResolvers: 5, Unanimous: false},
        }
        result := EvaluateSourceCredibility(agreements)
        if result.Score != 60 {
                t.Errorf("3/5 agreement: expected 60, got %.1f", result.Score)
        }
}

func TestEvaluateSourceCredibility_Empty(t *testing.T) {
        result := EvaluateSourceCredibility(nil)
        if result.Grade != GradeStale {
                t.Errorf("empty: expected %q, got %q", GradeStale, result.Grade)
        }
}

func TestEvaluateTTLRelevance_AllNormal(t *testing.T) {
        ttls := map[string]uint32{"A": 300, "MX": 3600, "NS": 86400}
        result := EvaluateTTLRelevance(ttls)
        if result.Score != 100 {
                t.Errorf("all normal: expected 100, got %.1f", result.Score)
        }
}

func TestEvaluateTTLRelevance_SlightlyOff(t *testing.T) {
        ttls := map[string]uint32{"A": 150}
        result := EvaluateTTLRelevance(ttls)
        if result.Score != 100 {
                t.Errorf("A=150 (ratio 0.5): expected 100, got %.1f", result.Score)
        }
}

func TestEvaluateTTLRelevance_VeryLow(t *testing.T) {
        ttls := map[string]uint32{"A": 10}
        result := EvaluateTTLRelevance(ttls)
        if result.Score != 0 {
                t.Errorf("A=10 (ratio 0.033, below 0.1 threshold): expected 0, got %.1f", result.Score)
        }
}

func TestEvaluateTTLRelevance_ExtremeMismatch(t *testing.T) {
        ttls := map[string]uint32{"A": 1}
        result := EvaluateTTLRelevance(ttls)
        if result.Score != 0 {
                t.Errorf("A=1 (ratio 0.003): expected 0, got %.1f", result.Score)
        }
}

func TestEvaluateTTLRelevance_Empty(t *testing.T) {
        result := EvaluateTTLRelevance(map[string]uint32{})
        if result.Grade != GradeAdequate {
                t.Errorf("empty: expected %q, got %q", GradeAdequate, result.Grade)
        }
}

func TestBuildCurrencyReport_Integration(t *testing.T) {
        records := []RecordCurrency{
                {RecordType: "A", ObservedTTL: 300, DataAgeS: 100},
                {RecordType: "MX", ObservedTTL: 3600, DataAgeS: 1000},
        }
        resolver := map[string]uint32{"A": 300, "MX": 3600}
        auth := map[string]uint32{"A": 300, "MX": 3600}
        observed := map[string]bool{"A": true, "MX": true}
        agreements := []ResolverAgreement{
                {RecordType: "A", AgreeCount: 5, TotalResolvers: 5, Unanimous: true},
        }

        report := BuildCurrencyReport(records, resolver, auth, observed, agreements, 5)

        if len(report.Dimensions) != 5 {
                t.Fatalf("expected 5 dimensions, got %d", len(report.Dimensions))
        }

        if report.ResolverCount != 5 {
                t.Errorf("expected resolver count 5, got %d", report.ResolverCount)
        }

        if report.RecordCount != 2 {
                t.Errorf("expected record count 2, got %d", report.RecordCount)
        }

        if report.OverallGrade == "" {
                t.Error("overall grade should not be empty")
        }

        if report.OverallScore <= 0 {
                t.Errorf("overall score should be positive, got %.1f", report.OverallScore)
        }

        if report.Guidance == "" {
                t.Error("guidance should not be empty")
        }

        dimNames := map[string]bool{}
        for _, d := range report.Dimensions {
                dimNames[d.Dimension] = true
                if d.Standard == "" {
                        t.Errorf("dimension %q missing standard citation", d.Dimension)
                }
                if d.Grade == "" {
                        t.Errorf("dimension %q missing grade", d.Dimension)
                }
                if d.Details == "" {
                        t.Errorf("dimension %q missing details", d.Dimension)
                }
        }

        expectedDims := []string{
                DimensionCurrentness, DimensionTTLCompliance,
                DimensionCompleteness, DimensionSourceCredibility, DimensionTTLRelevance,
        }
        for _, d := range expectedDims {
                if !dimNames[d] {
                        t.Errorf("missing dimension %q in report", d)
                }
        }
}

func TestBuildCurrencyReport_EmptyInputs(t *testing.T) {
        report := BuildCurrencyReport(nil, nil, nil, nil, nil, 0)

        if len(report.Dimensions) != 5 {
                t.Fatalf("expected 5 dimensions even with nil inputs, got %d", len(report.Dimensions))
        }

        if report.OverallGrade == "" {
                t.Error("grade should not be empty even with nil inputs")
        }

        if report.Guidance == "" {
                t.Error("guidance should not be empty even with nil inputs")
        }
}

func TestGradeConstants(t *testing.T) {
        if len(GradeOrder) != 5 {
                t.Errorf("expected 5 grades, got %d", len(GradeOrder))
        }
        if len(GradeDisplayNames) != 5 {
                t.Errorf("expected 5 grade display names, got %d", len(GradeDisplayNames))
        }
        if len(GradeBootstrapClass) != 5 {
                t.Errorf("expected 5 grade bootstrap classes, got %d", len(GradeBootstrapClass))
        }
}

func TestDimensionConstants(t *testing.T) {
        if len(DimensionDisplayNames) != 5 {
                t.Errorf("expected 5 dimension display names, got %d", len(DimensionDisplayNames))
        }
        if len(DimensionStandards) != 5 {
                t.Errorf("expected 5 dimension standards, got %d", len(DimensionStandards))
        }
}

func TestEvaluateTTLCompliance_NilMaps(t *testing.T) {
        result := EvaluateTTLCompliance(nil, nil)
        if result.Grade != GradeAdequate {
                t.Errorf("nil maps: expected %q, got %q", GradeAdequate, result.Grade)
        }
}

func TestEvaluateCompleteness_NilMap(t *testing.T) {
        result := EvaluateCompleteness(nil)
        if result.Grade != GradeStale {
                t.Errorf("nil map: expected %q, got %q", GradeStale, result.Grade)
        }
}

func TestEvaluateTTLRelevance_UnknownRecordType(t *testing.T) {
        ttls := map[string]uint32{"CUSTOM": 500}
        result := EvaluateTTLRelevance(ttls)
        if result.Grade != GradeAdequate {
                t.Errorf("unknown type: expected %q, got %q", GradeAdequate, result.Grade)
        }
}
