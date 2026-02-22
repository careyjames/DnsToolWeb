// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"fmt"
	"math"
)

type CurrencyEntry struct {
	RecordType      string `json:"record_type"`
	ObservedTTL     uint32 `json:"observed_ttl_seconds"`
	TypicalTTL      uint32 `json:"typical_ttl_seconds"`
	RescanAfter     uint32 `json:"rescan_after_seconds"`
	RescanLabel     string `json:"rescan_label"`
	PropagationNote string `json:"propagation_note"`
}

var typicalTTLs = map[string]uint32{
	"A":       300,
	"AAAA":    300,
	"MX":      3600,
	"TXT":     3600,
	"NS":      86400,
	"CNAME":   300,
	"CAA":     3600,
	"SOA":     3600,
	"SPF":     3600,
	"DMARC":   3600,
	"DKIM":    3600,
	"MTA-STS": 86400,
	"TLS-RPT": 3600,
	"BIMI":    3600,
	"TLSA":    3600,
	"DNSSEC":  86400,
	"DANE":    3600,
}

var propagationNotes = map[string]string{
	"A":       "A records typically propagate within 5 minutes. Some resolvers may cache up to the TTL value.",
	"AAAA":    "AAAA records follow the same propagation pattern as A records.",
	"MX":      "MX record changes may take up to 1 hour to propagate. Mail delivery may be affected during transition.",
	"TXT":     "TXT records (including SPF) typically propagate within 1 hour. Verify with multiple resolvers.",
	"NS":      "Nameserver changes can take 24\u201348 hours for full global propagation due to parent zone TTLs.",
	"CNAME":   "CNAME changes propagate quickly but downstream records inherit the CNAME TTL.",
	"CAA":     "CAA record changes take effect within TTL. Certificate authorities check at issuance time.",
	"SOA":     "SOA changes propagate to secondaries based on the Refresh interval in the SOA record.",
	"SPF":     "SPF record changes propagate within the TXT record TTL. Test with dig before relying on scan results.",
	"DMARC":   "DMARC policy changes at _dmarc subdomain propagate within TTL. Reporting changes take 24\u201348h to reflect in aggregate reports.",
	"DKIM":    "DKIM selector records propagate within TTL. New selectors are available immediately once published; key rotation requires overlap period.",
	"MTA-STS": "MTA-STS policy changes require updating both the DNS TXT record AND the policy file at /.well-known/mta-sts.txt. The max_age directive in the policy controls how long senders cache it.",
	"TLS-RPT": "TLS-RPT changes propagate within TTL. Report delivery changes take effect in the next reporting period (typically 24 hours).",
	"BIMI":    "BIMI record changes propagate within TTL. VMC certificate validation by mail providers may take additional time.",
	"TLSA":    "TLSA/DANE records must be published BEFORE rotating TLS certificates. Premature certificate rotation breaks DANE validation.",
	"DNSSEC":  "DNSSEC signing changes (DS record updates at registrar) can take 24\u201348 hours. Key rollovers require careful timing per RFC 7583.",
	"DANE":    "DANE/TLSA record updates follow the TLSA TTL. Coordinate with TLS certificate lifecycle.",
}

const (
	currencyFloorSeconds   = 30
	currencyCeilingSeconds = 86400
)

func BuildCurrencyMatrix(resolverTTL, authTTL map[string]uint32) map[string]any {
	entries := []CurrencyEntry{}

	allTypes := []string{"A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA", "SOA"}

	protocolTypes := []string{"SPF", "DMARC", "DKIM", "MTA-STS", "TLS-RPT", "BIMI", "TLSA", "DNSSEC", "DANE"}
	allTypes = append(allTypes, protocolTypes...)

	for _, rt := range allTypes {
		entry := CurrencyEntry{
			RecordType: rt,
			TypicalTTL: typicalTTLs[rt],
		}

		if ttl, ok := resolverTTL[rt]; ok {
			entry.ObservedTTL = ttl
		} else if ttl, ok := authTTL[rt]; ok {
			entry.ObservedTTL = ttl
		}

		entry.RescanAfter = computeRescanInterval(entry.ObservedTTL, entry.TypicalTTL)
		entry.RescanLabel = formatRescanLabel(entry.RescanAfter)

		if note, ok := propagationNotes[rt]; ok {
			entry.PropagationNote = note
		}

		entries = append(entries, entry)
	}

	matrix := map[string]any{
		"entries":     entries,
		"entry_count": len(entries),
		"min_rescan":  currencyFloorSeconds,
		"max_rescan":  currencyCeilingSeconds,
		"guidance":    "Re-scan times are based on observed TTL values from authoritative and resolver responses. After making DNS changes, wait at least the recommended interval before re-scanning for updated results.",
	}

	return matrix
}

func computeRescanInterval(observed, typical uint32) uint32 {
	ttl := observed
	if ttl == 0 {
		ttl = typical
	}
	if ttl == 0 {
		ttl = 300
	}

	rescan := uint32(math.Ceil(float64(ttl) * 1.1))

	if rescan < currencyFloorSeconds {
		rescan = currencyFloorSeconds
	}
	if rescan > currencyCeilingSeconds {
		rescan = currencyCeilingSeconds
	}

	return rescan
}

func formatRescanLabel(seconds uint32) string {
	if seconds < 60 {
		return fmt.Sprintf("%d seconds", seconds)
	}
	if seconds < 3600 {
		mins := seconds / 60
		if mins == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", mins)
	}
	if seconds < 86400 {
		hours := seconds / 3600
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	}
	return "24 hours"
}
