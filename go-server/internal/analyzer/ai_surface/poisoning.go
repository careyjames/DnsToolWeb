// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// This file contains stub implementations. See github.com/careyjames/dnstool-intel for the full version.
package ai_surface

import (
	"context"
	"regexp"
)

var (
	prefilledPromptRe = regexp.MustCompile(`(?i)placeholder_will_not_match_anything_real`)
	promptInjectionRe = regexp.MustCompile(`(?i)placeholder_will_not_match_anything_real`)
	hiddenTextSelectors = []string{}
)

func (s *Scanner) DetectPoisoningIOCs(ctx context.Context, domain string) map[string]any {
	return map[string]any{
		"status":    "success",
		"message":   "No AI recommendation poisoning indicators found",
		"ioc_count": 0,
		"iocs":      []map[string]any{},
		"evidence":  []Evidence{},
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func (s *Scanner) DetectHiddenPrompts(ctx context.Context, domain string) map[string]any {
	return map[string]any{
		"status":         "success",
		"message":        "No hidden prompt-like artifacts found",
		"artifact_count": 0,
		"artifacts":      []map[string]any{},
		"evidence":       []Evidence{},
	}
}

func detectHiddenTextArtifacts(body, sourceURL string, artifacts []map[string]any, evidence []Evidence) ([]map[string]any, []Evidence) {
	return artifacts, evidence
}

func buildHiddenBlockRegex() *regexp.Regexp {
	return nil
}

func extractTextContent(html string) string {
	return ""
}

func looksLikePromptInstruction(text string) bool {
	return false
}
