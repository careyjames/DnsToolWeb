//go:build !intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Stub implementations. See github.com/careyjames/dns-tool-intel for the full version.
package ai_surface

import "context"

func (s *Scanner) fetchTextFile(ctx context.Context, url string) (string, error) {
	return "", nil
}
