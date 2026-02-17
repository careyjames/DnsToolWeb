//go:build intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Full implementation — private repo only.
package ai_surface

import "context"

var knownAICrawlers = []string{
	// TODO: Populate with full AI crawler list
}

func (s *Scanner) CheckRobotsTxtAI(ctx context.Context, domain string) map[string]any {
	// TODO: Implement full robots.txt AI crawler analysis
	return map[string]any{
		"found":              false,
		"url":                nil,
		"blocks_ai_crawlers": false,
		"allows_ai_crawlers": false,
		"blocked_crawlers":   []string{},
		"allowed_crawlers":   []string{},
		"directives":         []robotsDirective{},
		"evidence":           []Evidence{},
	}
}

func parseRobotsForAI(body string) (blocked []string, allowed []string, directives []robotsDirective) {
	// TODO: Implement full robots.txt AI directive parser
	return nil, nil, nil
}

func processRobotsLine(lower, line string, currentUA string, seenBlocked, seenAllowed map[string]bool, directives *[]robotsDirective) {
	// TODO: Implement robots.txt line processor
}

func matchAICrawler(userAgent string) string {
	// TODO: Implement AI crawler matching logic
	return ""
}
