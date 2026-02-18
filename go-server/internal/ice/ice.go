// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package ice

import (
	"time"
)

const (
	LayerCollection = "collection"
	LayerAnalysis   = "analysis"

	MaturityDevelopment = "development"
	MaturityVerified    = "verified"
	MaturityConsistent  = "consistent"
	MaturityGold        = "gold"
	MaturityMasterGold  = "master_gold"

	ThresholdVerified   = 100
	ThresholdConsistent = 500
	ThresholdGold       = 1000
	ThresholdMasterGold = 5000

	ConsistentDays  = 30
	GoldDays        = 90
	MasterGoldDays  = 180
)

var Protocols = []string{
	"spf", "dkim", "dmarc", "dane", "dnssec",
	"bimi", "mta_sts", "tlsrpt", "caa",
}

var ProtocolDisplayNames = map[string]string{
	"spf":     "SPF",
	"dkim":    "DKIM",
	"dmarc":   "DMARC",
	"dane":    "DANE/TLSA",
	"dnssec":  "DNSSEC",
	"bimi":    "BIMI",
	"mta_sts": "MTA-STS",
	"tlsrpt":  "TLS-RPT",
	"caa":     "CAA",
}

var MaturityDisplayNames = map[string]string{
	MaturityDevelopment: "Development",
	MaturityVerified:    "Verified",
	MaturityConsistent:  "Consistent",
	MaturityGold:        "Gold",
	MaturityMasterGold:  "Master Gold",
}

var MaturityOrder = map[string]int{
	MaturityDevelopment: 0,
	MaturityVerified:    1,
	MaturityConsistent:  2,
	MaturityGold:        3,
	MaturityMasterGold:  4,
}

type TestCase struct {
	CaseID     string
	CaseName   string
	Protocol   string
	Layer      string
	RFCSection string
	Expected   string
	RunFn      func() (actual string, passed bool)
}

type TestResult struct {
	CaseID     string
	CaseName   string
	Protocol   string
	Layer      string
	RFCSection string
	Expected   string
	Actual     string
	Passed     bool
	Notes      string
}

type RunSummary struct {
	AppVersion  string
	GitCommit   string
	RunType     string
	TotalCases  int
	TotalPassed int
	TotalFailed int
	DurationMs  int
	Results     []TestResult
	CreatedAt   time.Time
}

type ProtocolMaturity struct {
	Protocol          string
	Layer             string
	Maturity          string
	MaturityDisplay   string
	TotalRuns         int
	ConsecutivePasses int
	FirstPassAt       *time.Time
	LastRegressionAt  *time.Time
	LastEvaluatedAt   time.Time
}

type ReportMetrics struct {
	Protocols       []ProtocolReport
	LastRunAt       *time.Time
	LastRunVersion  string
	TotalProtocols  int
	OverallMaturity string
}

type ProtocolReport struct {
	Protocol          string
	DisplayName       string
	CollectionLevel   string
	CollectionDisplay string
	CollectionRuns    int
	AnalysisLevel     string
	AnalysisDisplay   string
	AnalysisRuns      int
}

func ComputeMaturity(consecutivePasses int, firstPassAt *time.Time, lastRegressionAt *time.Time) string {
	if consecutivePasses < ThresholdVerified {
		return MaturityDevelopment
	}

	if firstPassAt == nil {
		return MaturityVerified
	}

	daysSinceFirst := int(time.Since(*firstPassAt).Hours() / 24)

	regressedRecently := false
	if lastRegressionAt != nil {
		daysSinceRegression := int(time.Since(*lastRegressionAt).Hours() / 24)
		if daysSinceRegression < ConsistentDays {
			regressedRecently = true
		}
	}

	if regressedRecently {
		if consecutivePasses >= ThresholdVerified {
			return MaturityVerified
		}
		return MaturityDevelopment
	}

	if consecutivePasses >= ThresholdMasterGold && daysSinceFirst >= MasterGoldDays {
		return MaturityMasterGold
	}
	if consecutivePasses >= ThresholdGold && daysSinceFirst >= GoldDays {
		return MaturityGold
	}
	if consecutivePasses >= ThresholdConsistent && daysSinceFirst >= ConsistentDays {
		return MaturityConsistent
	}
	if consecutivePasses >= ThresholdVerified {
		return MaturityVerified
	}

	return MaturityDevelopment
}

func OverallMaturity(protocols []ProtocolReport) string {
	lowest := MaturityMasterGold
	lowestOrder := MaturityOrder[lowest]

	for _, p := range protocols {
		for _, level := range []string{p.CollectionLevel, p.AnalysisLevel} {
			order, ok := MaturityOrder[level]
			if !ok {
				return MaturityDevelopment
			}
			if order < lowestOrder {
				lowestOrder = order
				lowest = level
			}
		}
	}

	return lowest
}

func IsDegraded(previousMaturity, newMaturity string) bool {
	return MaturityOrder[newMaturity] < MaturityOrder[previousMaturity]
}
