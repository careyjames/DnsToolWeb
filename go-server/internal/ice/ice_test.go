// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package ice

import (
	"testing"
	"time"
)

func TestICEAnalysisCases(t *testing.T) {
	cases := AnalysisTestCases()
	if len(cases) == 0 {
		t.Fatal("expected analysis test cases, got 0")
	}

	runner := NewRunner("test", "000000", "unit")
	runner.Register(cases...)

	summary := runner.Run()

	t.Logf("ICE Analysis: %d cases, %d passed, %d failed (%.1f%%)",
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
		{"5000 passes, 180 days", 5000, 180, true, 0, false, MaturityMasterGold},
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
	protocols := []ProtocolReport{
		{CollectionLevel: MaturityGold, AnalysisLevel: MaturityGold},
		{CollectionLevel: MaturityGold, AnalysisLevel: MaturityVerified},
	}
	got := OverallMaturity(protocols)
	if got != MaturityVerified {
		t.Errorf("OverallMaturity: expected %q, got %q", MaturityVerified, got)
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
