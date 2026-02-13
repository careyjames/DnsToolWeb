// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
// This file contains stub implementations. See github.com/careyjames/dnstool-intel for the full version.
package ai_surface

import "context"

var knownAICrawlers = []string{}

type robotsDirective struct {
	UserAgent string `json:"user_agent"`
	Action    string `json:"action"`
	Path      string `json:"path"`
}

func (s *Scanner) CheckRobotsTxtAI(ctx context.Context, domain string) map[string]any {
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
	return nil, nil, nil
}

func processRobotsLine(lower, line string, currentUA string, seenBlocked, seenAllowed map[string]bool, directives *[]robotsDirective) {
}

func matchAICrawler(userAgent string) string {
	return ""
}
