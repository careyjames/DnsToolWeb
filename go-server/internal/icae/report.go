// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package icae

import (
        "context"
        "log/slog"

        "dnstool/go-server/internal/dbq"

        "github.com/jackc/pgx/v5/pgtype"
)

type DBTX interface {
        ICAEGetAllMaturity(ctx context.Context) ([]dbq.ICAEGetAllMaturityRow, error)
}

func LoadReportMetrics(ctx context.Context, queries DBTX) *ReportMetrics {
        rows, err := queries.ICAEGetAllMaturity(ctx)
        if err != nil {
                slog.Warn("ICAE: failed to load maturity data", "error", err)
                return nil
        }

        maturityMap := make(map[string]map[string]dbq.ICAEGetAllMaturityRow)
        for _, row := range rows {
                if maturityMap[row.Protocol] == nil {
                        maturityMap[row.Protocol] = make(map[string]dbq.ICAEGetAllMaturityRow)
                }
                maturityMap[row.Protocol][row.Layer] = row
        }

        var protocols []ProtocolReport
        for _, proto := range Protocols {
                pr := ProtocolReport{
                        Protocol:    proto,
                        DisplayName: ProtocolDisplayNames[proto],
                }

                colData, hasCol := maturityMap[proto][LayerCollection]
                analData, hasAnal := maturityMap[proto][LayerAnalysis]

                if hasCol {
                        pr.CollectionLevel = colData.Maturity
                        pr.CollectionDisplay = MaturityDisplayNames[colData.Maturity]
                        pr.CollectionRuns = int(colData.TotalRuns)
                } else {
                        pr.CollectionLevel = MaturityDevelopment
                        pr.CollectionDisplay = MaturityDisplayNames[MaturityDevelopment]
                }

                if hasAnal {
                        pr.AnalysisLevel = analData.Maturity
                        pr.AnalysisDisplay = MaturityDisplayNames[analData.Maturity]
                        pr.AnalysisRuns = int(analData.TotalRuns)
                } else {
                        pr.AnalysisLevel = MaturityDevelopment
                        pr.AnalysisDisplay = MaturityDisplayNames[MaturityDevelopment]
                }

                hasRuns := (hasCol && colData.TotalRuns > 0) || (hasAnal && analData.TotalRuns > 0)
                pr.HasRuns = hasRuns

                protocols = append(protocols, pr)
        }

        evaluatedCount := 0
        for _, p := range protocols {
                if p.HasRuns {
                        evaluatedCount++
                }
        }

        overall := OverallMaturity(protocols)

        byKey := make(map[string]ProtocolReport, len(protocols))
        for _, p := range protocols {
                byKey[p.Protocol] = p
        }

        metrics := &ReportMetrics{
                Protocols:              protocols,
                ByKey:                  byKey,
                TotalProtocols:         len(protocols),
                EvaluatedCount:         evaluatedCount,
                OverallMaturity:        overall,
                OverallMaturityDisplay: MaturityDisplayNames[overall],
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
