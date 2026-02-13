// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
// Analysis intelligence — also maintained under separate proprietary license.
package ai_surface
import (
	"context"
	"strings"
)

func (s *Scanner) fetchTextFile(ctx context.Context, url string) (string, error) {
	resp, err := s.HTTP.Get(ctx, url)
	if err != nil {
		return "", err
	}

	body, err := s.HTTP.ReadBody(resp, 2<<20)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", nil
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(strings.ToLower(ct), "text/") && !strings.Contains(strings.ToLower(ct), "application/json") {
		return "", nil
	}

	return string(body), nil
}
