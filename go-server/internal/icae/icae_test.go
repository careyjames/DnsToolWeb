// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package icae

import (
        "testing"
        "time"
)

func TestICAEAnalysisCases(t *testing.T) {
        cases := AnalysisTestCases()
        if len(cases) == 0 {
                t.Fatal("expected analysis test cases, got 0")
        }

        runner := NewRunner("test", "000000", "unit")
        runner.Register(cases...)

        summary := runner.Run()

        t.Logf("ICAE Analysis: %d cases, %d passed, %d failed (%.1f%%)",
                summary.TotalCases, summary.TotalPassed, summary.TotalFailed,
                float64(summary.TotalPassed)/float64(summary.TotalCases)*100)

        for _, r := range summary.Results {
                if !r.Passed {
                        t.Errorf("FAIL [%s] %s: expected %q, got %q",
                                r.CaseID, r.CaseName, r.Expected, r.Actual)
                }
        }
}

func TestICAECollectionCases(t *testing.T) {
        cases := CollectionTestCases()
        if len(cases) == 0 {
                t.Fatal("expected collection test cases, got 0")
        }

        runner := NewRunner("test", "000000", "unit")
        runner.Register(cases...)

        summary := runner.Run()

        t.Logf("ICAE Collection: %d cases, %d passed, %d failed (%.1f%%)",
                summary.TotalCases, summary.TotalPassed, summary.TotalFailed,
                float64(summary.TotalPassed)/float64(summary.TotalCases)*100)

        for _, r := range summary.Results {
                if !r.Passed {
                        t.Errorf("FAIL [%s] %s: expected %q, got %q",
                                r.CaseID, r.CaseName, r.Expected, r.Actual)
                }
        }
}

func TestComputeMaturity(t *testing.T) {
        tests := []struct {
                name              string
                consecutivePasses int
                daysSinceFirst    int
                hasFirstPass      bool
                daysSinceRegress  int
                hasRegression     bool
                expected          string
        }{
                {"zero passes", 0, 0, false, 0, false, MaturityDevelopment},
                {"50 passes", 50, 10, true, 0, false, MaturityDevelopment},
                {"100 passes, 5 days", 100, 5, true, 0, false, MaturityVerified},
                {"500 passes, 30 days", 500, 30, true, 0, false, MaturityConsistent},
                {"1000 passes, 90 days", 1000, 90, true, 0, false, MaturityGold},
                {"5000 passes, 180 days", 5000, 180, true, 0, false, MaturityGoldMaster},
                {"1000 passes but recent regression", 1000, 90, true, 10, true, MaturityVerified},
                {"500 passes, only 15 days", 500, 15, true, 0, false, MaturityVerified},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        var fp, lr *time.Time

                        if tt.hasFirstPass {
                                firstPass := time.Now().Add(-time.Duration(tt.daysSinceFirst) * 24 * time.Hour)
                                fp = &firstPass
                        }

                        if tt.hasRegression {
                                regress := time.Now().Add(-time.Duration(tt.daysSinceRegress) * 24 * time.Hour)
                                lr = &regress
                        }

                        got := ComputeMaturity(tt.consecutivePasses, fp, lr)
                        if got != tt.expected {
                                t.Errorf("ComputeMaturity(%d passes, %d days) = %q, want %q",
                                        tt.consecutivePasses, tt.daysSinceFirst, got, tt.expected)
                        }
                })
        }
}

func TestOverallMaturity(t *testing.T) {
        t.Run("both layers present", func(t *testing.T) {
                protocols := []ProtocolReport{
                        {CollectionLevel: MaturityGold, HasCollection: true, AnalysisLevel: MaturityGold, HasAnalysis: true},
                        {CollectionLevel: MaturityGold, HasCollection: true, AnalysisLevel: MaturityVerified, HasAnalysis: true},
                }
                got := OverallMaturity(protocols)
                if got != MaturityVerified {
                        t.Errorf("expected %q, got %q", MaturityVerified, got)
                }
        })

        t.Run("analysis only no collection", func(t *testing.T) {
                protocols := []ProtocolReport{
                        {CollectionLevel: MaturityDevelopment, HasCollection: false, AnalysisLevel: MaturityVerified, HasAnalysis: true},
                        {CollectionLevel: MaturityDevelopment, HasCollection: false, AnalysisLevel: MaturityVerified, HasAnalysis: true},
                }
                got := OverallMaturity(protocols)
                if got != MaturityVerified {
                        t.Errorf("expected %q, got %q (collection without data should not drag overall down)", MaturityVerified, got)
                }
        })

        t.Run("no data at all", func(t *testing.T) {
                protocols := []ProtocolReport{
                        {CollectionLevel: MaturityDevelopment, HasCollection: false, AnalysisLevel: MaturityDevelopment, HasAnalysis: false},
                }
                got := OverallMaturity(protocols)
                if got != MaturityDevelopment {
                        t.Errorf("expected %q, got %q", MaturityDevelopment, got)
                }
        })

        t.Run("mixed layers one protocol has collection", func(t *testing.T) {
                protocols := []ProtocolReport{
                        {CollectionLevel: MaturityConsistent, HasCollection: true, AnalysisLevel: MaturityGold, HasAnalysis: true},
                        {CollectionLevel: MaturityDevelopment, HasCollection: false, AnalysisLevel: MaturityVerified, HasAnalysis: true},
                }
                got := OverallMaturity(protocols)
                if got != MaturityVerified {
                        t.Errorf("expected %q, got %q", MaturityVerified, got)
                }
        })
}

func TestComputeNextTier(t *testing.T) {
        tests := []struct {
                name      string
                level     string
                passes    int
                days      int
                wantName  string
                wantMax   bool
                wantPMet  bool
                wantDMet  bool
        }{
                {"dev to verified", MaturityDevelopment, 50, 0, "Verified", false, false, true},
                {"dev passes met", MaturityDevelopment, 100, 0, "Verified", false, true, true},
                {"verified needs time", MaturityVerified, 510, 1, "Consistent", false, true, false},
                {"verified both met", MaturityVerified, 510, 30, "Consistent", false, true, true},
                {"consistent needs passes", MaturityConsistent, 800, 90, "Gold", false, false, true},
                {"gold master is max", MaturityGoldMaster, 10000, 365, "", true, true, true},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        name, _, _, pMet, dMet, atMax := ComputeNextTier(tt.level, tt.passes, tt.days)
                        if name != tt.wantName {
                                t.Errorf("nextName: got %q, want %q", name, tt.wantName)
                        }
                        if atMax != tt.wantMax {
                                t.Errorf("atMax: got %v, want %v", atMax, tt.wantMax)
                        }
                        if pMet != tt.wantPMet {
                                t.Errorf("passesMet: got %v, want %v", pMet, tt.wantPMet)
                        }
                        if dMet != tt.wantDMet {
                                t.Errorf("daysMet: got %v, want %v", dMet, tt.wantDMet)
                        }
                })
        }
}

func TestIsDegraded(t *testing.T) {
        if !IsDegraded(MaturityGold, MaturityVerified) {
                t.Error("Gold -> Verified should be degraded")
        }
        if IsDegraded(MaturityVerified, MaturityGold) {
                t.Error("Verified -> Gold should not be degraded")
        }
}

func TestRunnerBasics(t *testing.T) {
        runner := NewRunner("1.0.0", "abc123", "test")

        runner.Register(TestCase{
                CaseID:   "test-001",
                CaseName: "always pass",
                Protocol: "spf",
                Layer:    LayerAnalysis,
                Expected: "ok",
                RunFn:    func() (string, bool) { return "ok", true },
        }, TestCase{
                CaseID:   "test-002",
                CaseName: "always fail",
                Protocol: "spf",
                Layer:    LayerAnalysis,
                Expected: "ok",
                RunFn:    func() (string, bool) { return "nope", false },
        })

        summary := runner.Run()

        if summary.TotalCases != 2 {
                t.Errorf("expected 2 cases, got %d", summary.TotalCases)
        }
        if summary.TotalPassed != 1 {
                t.Errorf("expected 1 passed, got %d", summary.TotalPassed)
        }
        if summary.TotalFailed != 1 {
                t.Errorf("expected 1 failed, got %d", summary.TotalFailed)
        }
}
