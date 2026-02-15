// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"context"
)

func (a *Analyzer) ScanSecretExposure(ctx context.Context, domain string) map[string]any {
	scanner := NewSecretScanner(a.HTTP)
	return scanner.Scan(ctx, domain)
}
