package analyzer

import (
	"context"
	"strings"
)

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
			switch {
			case strings.Contains(lower, "letsencrypt"):
				issuerSet["Let's Encrypt"] = true
			case strings.Contains(lower, "digicert"):
				issuerSet["DigiCert"] = true
			case strings.Contains(lower, "sectigo") || strings.Contains(lower, "comodo"):
				issuerSet["Sectigo"] = true
			case strings.Contains(lower, "globalsign"):
				issuerSet["GlobalSign"] = true
			case strings.Contains(lower, "amazon"):
				issuerSet["Amazon"] = true
			case strings.Contains(lower, "google"):
				issuerSet["Google Trust Services"] = true
			default:
				parts := strings.Fields(record)
				if len(parts) >= 3 {
					issuerSet[strings.Trim(parts[len(parts)-1], "\"")] = true
				}
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
