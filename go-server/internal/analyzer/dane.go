package analyzer

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"dnstool/go-server/internal/providers"
)

var daneUsageNames = map[int]string{
	0: "PKIX-TA (CA constraint)",
	1: "PKIX-EE (Certificate constraint)",
	2: "DANE-TA (Trust anchor)",
	3: "DANE-EE (Domain-issued certificate)",
}

var daneSelectorNames = map[int]string{
	0: "Full certificate",
	1: "Public key only (SubjectPublicKeyInfo)",
}

var daneMatchingNames = map[int]string{
	0: "Exact match",
	1: "SHA-256",
	2: "SHA-512",
}

func (a *Analyzer) detectMXDANECapability(mxHosts []string) map[string]any {
	mxStr := strings.ToLower(strings.Join(mxHosts, " "))
	for _, info := range providers.DANEMXCapability {
		for _, pattern := range info.Patterns {
			if strings.Contains(mxStr, pattern) {
				result := map[string]any{
					"provider_name": info.Name,
					"dane_inbound":  info.DANEInbound,
					"dane_outbound": info.DANEOutbound,
					"reason":        info.Reason,
					"alternative":   info.Alternative,
				}
				return result
			}
		}
	}
	return nil
}

func (a *Analyzer) checkMXTLSA(ctx context.Context, mxHost string) (string, []map[string]any) {
	tlsaName := fmt.Sprintf("_25._tcp.%s", mxHost)
	var found []map[string]any

	raw := a.DNS.QueryDNS(ctx, "TLSA", tlsaName)
	if len(raw) == 0 {
		return mxHost, found
	}

	for _, entry := range raw {
		parts := strings.Fields(entry)
		if len(parts) < 4 {
			continue
		}
		usage, _ := strconv.Atoi(parts[0])
		selector, _ := strconv.Atoi(parts[1])
		mtype, _ := strconv.Atoi(parts[2])
		certData := strings.Join(parts[3:], "")

		certDisplay := certData
		if len(certData) > 64 {
			certDisplay = certData[:64] + "..."
		}

		rec := map[string]any{
			"mx_host":          mxHost,
			"tlsa_name":        tlsaName,
			"usage":            usage,
			"usage_name":       lookupName(daneUsageNames, usage),
			"selector":         selector,
			"selector_name":    lookupName(daneSelectorNames, selector),
			"matching_type":    mtype,
			"matching_name":    lookupName(daneMatchingNames, mtype),
			"certificate_data": certDisplay,
			"full_record":      fmt.Sprintf("%d %d %d %s", usage, selector, mtype, certDisplay),
		}

		if usage == 0 || usage == 1 {
			rec["recommendation"] = "RFC 7672 §3.1 recommends usage 2 (DANE-TA) or 3 (DANE-EE) for SMTP"
		}

		found = append(found, rec)
	}

	return mxHost, found
}

func lookupName(m map[int]string, key int) string {
	if name, ok := m[key]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (%d)", key)
}

func extractMXHosts(mxRecords []string) []string {
	var mxHosts []string
	seen := make(map[string]bool)
	for _, mx := range mxRecords {
		parts := strings.Fields(strings.TrimSpace(mx))
		var host string
		if len(parts) >= 2 {
			host = strings.TrimRight(parts[len(parts)-1], ".")
		} else if len(parts) == 1 {
			host = strings.TrimRight(parts[0], ".")
		}
		if host != "" && host != "." && !seen[host] {
			seen[host] = true
			mxHosts = append(mxHosts, host)
		}
	}
	return mxHosts
}

func buildDANEVerdict(allTLSA []map[string]any, hostsWithDANE, mxHosts []string, mxCapability map[string]any) (string, string, []string) {
	var issues []string

	if len(allTLSA) == 0 {
		if mxCapability != nil && !mxCapability["dane_inbound"].(bool) {
			providerName := mxCapability["provider_name"].(string)
			return "info", fmt.Sprintf("DANE not available — %s does not support inbound DANE/TLSA on its MX infrastructure", providerName), issues
		}
		plural := ""
		if len(mxHosts) > 1 {
			plural = "s"
		}
		return "info", fmt.Sprintf("No DANE/TLSA records found (checked %d MX host%s)", len(mxHosts), plural), issues
	}

	for _, rec := range allTLSA {
		usage := rec["usage"].(int)
		if usage == 0 || usage == 1 {
			issues = append(issues, fmt.Sprintf("TLSA for %s: usage %d (PKIX-based) — RFC 7672 §3.1 recommends usage 2 or 3 for SMTP", rec["mx_host"], usage))
		}
		if rec["matching_type"].(int) == 0 {
			issues = append(issues, fmt.Sprintf("TLSA for %s: exact match (type 0) — SHA-256 (type 1) is preferred for resilience", rec["mx_host"]))
		}
	}

	plural := ""
	if len(mxHosts) > 1 {
		plural = "s"
	}

	if len(hostsWithDANE) == len(mxHosts) {
		return "success", fmt.Sprintf("DANE configured — TLSA records found for all %d MX host%s", len(mxHosts), plural), issues
	}

	var missing []string
	for _, h := range mxHosts {
		found := false
		for _, dh := range hostsWithDANE {
			if h == dh {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, h)
		}
	}
	if len(missing) > 3 {
		missing = missing[:3]
	}
	issues = append(issues, fmt.Sprintf("Missing DANE for: %s", strings.Join(missing, ", ")))

	return "warning", fmt.Sprintf("DANE partially configured — TLSA records on %d/%d MX hosts", len(hostsWithDANE), len(mxHosts)), issues
}

func (a *Analyzer) AnalyzeDANE(ctx context.Context, domain string, mxRecords []string) map[string]any {
	baseResult := map[string]any{
		"status":             "info",
		"message":            "No DANE/TLSA records found for mail servers",
		"has_dane":           false,
		"mx_hosts_checked":   0,
		"mx_hosts_with_dane": 0,
		"tlsa_records":       []map[string]any{},
		"requires_dnssec":    true,
		"issues":             []string{},
		"mx_provider":        nil,
		"dane_deployable":    true,
	}

	if len(mxRecords) == 0 {
		baseResult["message"] = "No MX records available — DANE check skipped"
		return baseResult
	}

	mxHosts := extractMXHosts(mxRecords)

	if len(mxHosts) == 0 {
		baseResult["message"] = "No valid MX hosts — DANE check skipped"
		return baseResult
	}

	if len(mxHosts) > 10 {
		mxHosts = mxHosts[:10]
	}

	mxCapability := a.detectMXDANECapability(mxHosts)
	if mxCapability != nil {
		baseResult["mx_provider"] = mxCapability
		baseResult["dane_deployable"] = mxCapability["dane_inbound"]
		if !mxCapability["dane_inbound"].(bool) {
			slog.Info("MX provider does not support inbound DANE",
				"provider", mxCapability["provider_name"], "domain", domain)
		}
	}

	var allTLSA []map[string]any
	var hostsWithDANE []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	workers := len(mxHosts)
	if workers > 5 {
		workers = 5
	}

	for _, host := range mxHosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			mxHost, records := a.checkMXTLSA(ctx, h)
			mu.Lock()
			if len(records) > 0 {
				hostsWithDANE = append(hostsWithDANE, mxHost)
				allTLSA = append(allTLSA, records...)
			}
			mu.Unlock()
		}(host)
	}
	wg.Wait()

	baseResult["mx_hosts_checked"] = len(mxHosts)
	baseResult["mx_hosts_with_dane"] = len(hostsWithDANE)
	baseResult["tlsa_records"] = allTLSA

	status, message, issues := buildDANEVerdict(allTLSA, hostsWithDANE, mxHosts, mxCapability)
	baseResult["status"] = status
	baseResult["message"] = message
	if len(allTLSA) > 0 {
		baseResult["has_dane"] = true
	}
	if mxCapability != nil && !mxCapability["dane_inbound"].(bool) {
		baseResult["dane_deployable"] = false
	}
	baseResult["issues"] = issues

	return baseResult
}
