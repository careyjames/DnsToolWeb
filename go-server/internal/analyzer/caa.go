package analyzer

import (
	"context"
	"strings"
)

func identifyCAIssuer(record string) string {
	lower := strings.ToLower(record)
	switch {
	case strings.Contains(lower, "letsencrypt"):
		return "Let's Encrypt"
	case strings.Contains(lower, "digicert"):
		return "DigiCert"
	case strings.Contains(lower, "sectigo") || strings.Contains(lower, "comodo"):
		return "Sectigo"
	case strings.Contains(lower, "globalsign"):
		return "GlobalSign"
	case strings.Contains(lower, "amazon"):
		return "Amazon"
	case strings.Contains(lower, "google"):
		return "Google Trust Services"
	default:
		parts := strings.Fields(record)
		if len(parts) >= 3 {
			return strings.Trim(parts[len(parts)-1], "\"")
		}
		return ""
	}
}

func (a *Analyzer) AnalyzeCAA(ctx context.Context, domain string) map[string]any {
	records := a.DNS.QueryDNS(ctx, "CAA", domain)

	if len(records) == 0 {
		return map[string]any{
			"status":       "warning",
			"message":      "No CAA records found - any CA can issue certificates",
			"records":      []string{},
			"issuers":      []string{},
			"has_wildcard": false,
			"has_iodef":    false,
		}
	}

	issuerSet := make(map[string]bool)
	hasWildcard := false
	hasIodef := false

	for _, record := range records {
		lower := strings.ToLower(record)

		if strings.Contains(lower, "issue ") || strings.Contains(lower, "issue\"") {
			issuer := identifyCAIssuer(record)
			if issuer != "" {
				issuerSet[issuer] = true
			}
		}

		if strings.Contains(lower, "issuewild") {
			hasWildcard = true
		}
		if strings.Contains(lower, "iodef") {
			hasIodef = true
		}
	}

	var issuers []string
	for issuer := range issuerSet {
		issuers = append(issuers, issuer)
	}

	messageParts := []string{"CAA configured"}
	if len(issuers) > 0 {
		messageParts = append(messageParts, "- only "+strings.Join(issuers, ", ")+" can issue certificates")
	} else {
		messageParts = append(messageParts, "- specific CAs authorized")
	}

	if hasWildcard {
		messageParts = append(messageParts, "(including wildcards)")
	}

	return map[string]any{
		"status":       "success",
		"message":      strings.Join(messageParts, " "),
		"records":      records,
		"issuers":      issuers,
		"has_wildcard": hasWildcard,
		"has_iodef":    hasIodef,
		"mpic_note":    "Since September 2025, all public CAs must verify domain control from multiple geographic locations (Multi-Perspective Issuance Corroboration, CA/B Forum Ballot SC-067). CAA records are now checked from multiple network perspectives before certificate issuance.",
	}
}
