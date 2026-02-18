// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package ice

import (
	"context"
	"log/slog"

	"dnstool/go-server/internal/dbq"

	"github.com/jackc/pgx/v5/pgtype"
)

type DBTX interface {
	ICEGetAllMaturity(ctx context.Context) ([]dbq.ICEGetAllMaturityRow, error)
}

func LoadReportMetrics(ctx context.Context, queries DBTX) *ReportMetrics {
	rows, err := queries.ICEGetAllMaturity(ctx)
	if err != nil {
		slog.Warn("ICE: failed to load maturity data", "error", err)
		return nil
	}

	maturityMap := make(map[string]map[string]dbq.ICEGetAllMaturityRow)
	for _, row := range rows {
		if maturityMap[row.Protocol] == nil {
			maturityMap[row.Protocol] = make(map[string]dbq.ICEGetAllMaturityRow)
		}
		maturityMap[row.Protocol][row.Layer] = row
	}

	var protocols []ProtocolReport
	for _, proto := range Protocols {
		pr := ProtocolReport{
			Protocol:    proto,
			DisplayName: ProtocolDisplayNames[proto],
		}

		if col, ok := maturityMap[proto][LayerCollection]; ok {
			pr.CollectionLevel = col.Maturity
			pr.CollectionDisplay = MaturityDisplayNames[col.Maturity]
			pr.CollectionRuns = int(col.TotalRuns)
		} else {
			pr.CollectionLevel = MaturityDevelopment
			pr.CollectionDisplay = MaturityDisplayNames[MaturityDevelopment]
		}

		if anal, ok := maturityMap[proto][LayerAnalysis]; ok {
			pr.AnalysisLevel = anal.Maturity
			pr.AnalysisDisplay = MaturityDisplayNames[anal.Maturity]
			pr.AnalysisRuns = int(anal.TotalRuns)
		} else {
			pr.AnalysisLevel = MaturityDevelopment
			pr.AnalysisDisplay = MaturityDisplayNames[MaturityDevelopment]
		}

		protocols = append(protocols, pr)
	}

	metrics := &ReportMetrics{
		Protocols:       protocols,
		TotalProtocols:  len(protocols),
		OverallMaturity: OverallMaturity(protocols),
	}

	return metrics
}

func TimestampToTimePtr(ts pgtype.Timestamp) *string {
	if !ts.Valid {
		return nil
	}
	s := ts.Time.Format("2006-01-02")
	return &s
}
