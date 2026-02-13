// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
package analyzer

import (
        "context"

        "dnstool/go-server/internal/analyzer/ai_surface"
)

func (a *Analyzer) AnalyzeAISurface(ctx context.Context, domain string) map[string]any {
        scanner := ai_surface.NewScanner(a.HTTP)
        return scanner.Scan(ctx, domain)
}
