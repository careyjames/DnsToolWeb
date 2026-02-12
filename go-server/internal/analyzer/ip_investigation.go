package analyzer

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
)

type IPRelationship struct {
	Classification string `json:"classification"`
	Evidence       string `json:"evidence"`
	RecordType     string `json:"record_type,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
}

var (
	ipv4Re = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	ipv6Re = regexp.MustCompile(`(?i)^[0-9a-f:]+$`)

	spfIPv4Re = regexp.MustCompile(`(?i)ip4:([^\s;]+)`)
	spfIPv6Re = regexp.MustCompile(`(?i)ip6:([^\s;]+)`)
)

func ValidateIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

func IsPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() || parsed.IsUnspecified()
}

func IsIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}

func (a *Analyzer) InvestigateIP(ctx context.Context, domain, ip string) map[string]any {
	result := map[string]any{
		"status":          "success",
		"domain":          domain,
		"ip":              ip,
		"ip_version":      "IPv4",
		"relationships":   []map[string]any{},
		"ptr_records":     []string{},
		"fcrdns_match":    false,
		"asn_info":        map[string]any{},
		"geolocation":     map[string]any{},
		"is_cdn":          false,
		"cdn_provider":    "",
		"summary":         "",
		"classification":  "Unrelated",
		"match_count":     0,
	}

	if IsIPv6(ip) {
		result["ip_version"] = "IPv6"
	}

	var relationships []map[string]any

	relationships = a.checkPTRRecords(ctx, ip, domain, result, relationships)
	relationships = a.checkDomainARecords(ctx, domain, ip, relationships)
	relationships = a.checkMXRecords(ctx, domain, ip, relationships)
	relationships = a.checkNSRecords(ctx, domain, ip, relationships)
	relationships = a.checkSPFAuthorization(ctx, domain, ip, relationships)
	relationships = a.checkCTSubdomains(ctx, domain, ip, relationships)

	asnInfo := a.lookupInvestigationASN(ctx, ip)
	result["asn_info"] = asnInfo

	cdnProvider := checkASNForCDNDirect(asnInfo)
	if cdnProvider != "" {
		result["is_cdn"] = true
		result["cdn_provider"] = cdnProvider
		relationships = append(relationships, map[string]any{
			"classification": "CDN/Edge Network",
			"evidence":       fmt.Sprintf("IP belongs to %s (ASN %s)", cdnProvider, mapGetStr(asnInfo, "asn")),
			"record_type":    "ASN",
		})
	}

	result["relationships"] = relationships
	result["match_count"] = len(relationships)

	classification, summary := classifyOverall(relationships, cdnProvider, result)
	result["classification"] = classification
	result["summary"] = summary

	return result
}

func (a *Analyzer) checkPTRRecords(ctx context.Context, ip, domain string, result map[string]any, rels []map[string]any) []map[string]any {
	arpaName := buildArpaName(ip)
	if arpaName == "" {
		return rels
	}

	ptrRecords := a.DNS.QueryDNS(ctx, "PTR", arpaName)
	var cleaned []string
	for _, ptr := range ptrRecords {
		ptr = strings.TrimSuffix(ptr, ".")
		cleaned = append(cleaned, ptr)
	}
	result["ptr_records"] = cleaned

	for _, ptr := range cleaned {
		ptrLower := strings.ToLower(ptr)
		domainLower := strings.ToLower(domain)

		if ptrLower == domainLower || strings.HasSuffix(ptrLower, "."+domainLower) {
			result["fcrdns_match"] = true
			rels = append(rels, map[string]any{
				"classification": "Direct Asset (Reverse DNS)",
				"evidence":       fmt.Sprintf("PTR record %s matches domain %s", ptr, domain),
				"record_type":    "PTR",
				"hostname":       ptr,
			})
		}

		fwdIPs := a.DNS.QueryDNS(ctx, "A", ptr+".")
		for _, fwdIP := range fwdIPs {
			if fwdIP == ip {
				if !result["fcrdns_match"].(bool) {
					result["fcrdns_match"] = true
				}
				break
			}
		}
	}

	return rels
}

func (a *Analyzer) checkDomainARecords(ctx context.Context, domain, ip string, rels []map[string]any) []map[string]any {
	for _, host := range []string{domain, "www." + domain} {
		aRecords := a.DNS.QueryDNS(ctx, "A", host)
		for _, rec := range aRecords {
			if rec == ip {
				rels = append(rels, map[string]any{
					"classification": "Direct Asset (A Record)",
					"evidence":       fmt.Sprintf("%s resolves to %s", host, ip),
					"record_type":    "A",
					"hostname":       host,
				})
			}
		}

		aaaaRecords := a.DNS.QueryDNS(ctx, "AAAA", host)
		for _, rec := range aaaaRecords {
			if rec == ip {
				rels = append(rels, map[string]any{
					"classification": "Direct Asset (AAAA Record)",
					"evidence":       fmt.Sprintf("%s resolves to %s", host, ip),
					"record_type":    "AAAA",
					"hostname":       host,
				})
			}
		}
	}
	return rels
}

func (a *Analyzer) checkMXRecords(ctx context.Context, domain, ip string, rels []map[string]any) []map[string]any {
	mxRecords := a.DNS.QueryDNS(ctx, "MX", domain)
	for _, mx := range mxRecords {
		mxHost := extractMXHost(mx)
		if mxHost == "" {
			continue
		}

		aRecords := a.DNS.QueryDNS(ctx, "A", mxHost+".")
		for _, rec := range aRecords {
			if rec == ip {
				rels = append(rels, map[string]any{
					"classification": "Email Provider (MX)",
					"evidence":       fmt.Sprintf("MX host %s resolves to %s", mxHost, ip),
					"record_type":    "MX",
					"hostname":       mxHost,
				})
			}
		}

		aaaaRecords := a.DNS.QueryDNS(ctx, "AAAA", mxHost+".")
		for _, rec := range aaaaRecords {
			if rec == ip {
				rels = append(rels, map[string]any{
					"classification": "Email Provider (MX)",
					"evidence":       fmt.Sprintf("MX host %s resolves to %s", mxHost, ip),
					"record_type":    "MX",
					"hostname":       mxHost,
				})
			}
		}
	}
	return rels
}

func (a *Analyzer) checkNSRecords(ctx context.Context, domain, ip string, rels []map[string]any) []map[string]any {
	nsRecords := a.DNS.QueryDNS(ctx, "NS", domain)
	for _, ns := range nsRecords {
		ns = strings.TrimSuffix(ns, ".")

		aRecords := a.DNS.QueryDNS(ctx, "A", ns+".")
		for _, rec := range aRecords {
			if rec == ip {
				rels = append(rels, map[string]any{
					"classification": "DNS Provider (NS)",
					"evidence":       fmt.Sprintf("Nameserver %s resolves to %s", ns, ip),
					"record_type":    "NS",
					"hostname":       ns,
				})
			}
		}
	}
	return rels
}

func (a *Analyzer) checkSPFAuthorization(ctx context.Context, domain, ip string, rels []map[string]any) []map[string]any {
	txtRecords := a.DNS.QueryDNS(ctx, "TXT", domain)

	for _, txt := range txtRecords {
		lower := strings.ToLower(txt)
		if !strings.HasPrefix(lower, "v=spf1") && !strings.HasPrefix(lower, "\"v=spf1") {
			continue
		}

		if checkIPInSPFRecord(txt, ip) {
			rels = append(rels, map[string]any{
				"classification": "SPF-Authorized Sender",
				"evidence":       fmt.Sprintf("IP %s is directly authorized in SPF record", ip),
				"record_type":    "SPF",
			})
		}

		includeMatches := spfIncludeRe.FindAllStringSubmatch(lower, -1)
		for _, m := range includeMatches {
			includeDomain := m[1]
			includeTXTs := a.DNS.QueryDNS(ctx, "TXT", includeDomain)
			for _, iTXT := range includeTXTs {
				if checkIPInSPFRecord(iTXT, ip) {
					rels = append(rels, map[string]any{
						"classification": "SPF-Authorized Sender (via include)",
						"evidence":       fmt.Sprintf("IP %s authorized via include:%s", ip, includeDomain),
						"record_type":    "SPF",
						"hostname":       includeDomain,
					})
				}
			}
		}

		break
	}
	return rels
}

func checkIPInSPFRecord(spfRecord, ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	ipv4Matches := spfIPv4Re.FindAllStringSubmatch(spfRecord, -1)
	for _, m := range ipv4Matches {
		mechanism := m[1]
		if strings.Contains(mechanism, "/") {
			_, cidr, err := net.ParseCIDR(mechanism)
			if err == nil && cidr.Contains(parsedIP) {
				return true
			}
		} else if mechanism == ip {
			return true
		}
	}

	ipv6Matches := spfIPv6Re.FindAllStringSubmatch(spfRecord, -1)
	for _, m := range ipv6Matches {
		mechanism := m[1]
		if strings.Contains(mechanism, "/") {
			_, cidr, err := net.ParseCIDR(mechanism)
			if err == nil && cidr.Contains(parsedIP) {
				return true
			}
		} else if strings.EqualFold(mechanism, ip) {
			return true
		}
	}

	return false
}

func (a *Analyzer) checkCTSubdomains(ctx context.Context, domain, ip string, rels []map[string]any) []map[string]any {
	ctResult := a.DiscoverSubdomains(ctx, domain)
	subdomains, ok := ctResult["subdomains"].([]map[string]any)
	if !ok {
		return rels
	}

	for _, sub := range subdomains {
		subdomain, _ := sub["subdomain"].(string)
		if subdomain == "" {
			continue
		}

		aRecords := a.DNS.QueryDNS(ctx, "A", subdomain+".")
		for _, rec := range aRecords {
			if rec == ip {
				rels = append(rels, map[string]any{
					"classification": "CT Subdomain Match",
					"evidence":       fmt.Sprintf("CT-discovered subdomain %s resolves to %s", subdomain, ip),
					"record_type":    "A (CT)",
					"hostname":       subdomain,
				})
			}
		}
	}
	return rels
}

func (a *Analyzer) lookupInvestigationASN(ctx context.Context, ip string) map[string]any {
	if IsIPv6(ip) {
		return a.lookupIPv6ASN(ctx, ip)
	}
	return a.lookupIPv4ASN(ctx, ip)
}

func checkASNForCDNDirect(asnInfo map[string]any) string {
	asn, _ := asnInfo["asn"].(string)
	if asn == "" {
		return ""
	}
	if cdn, ok := cdnASNs[asn]; ok {
		return cdn
	}
	return ""
}

func buildArpaName(ip string) string {
	if IsIPv6(ip) {
		reversed := reverseIPv6(ip)
		if reversed == "" {
			return ""
		}
		return reversed + ".ip6.arpa"
	}
	reversed := reverseIPv4(ip)
	if reversed == "" {
		return ""
	}
	return reversed + ".in-addr.arpa"
}

func extractMXHost(mx string) string {
	parts := strings.Fields(mx)
	if len(parts) >= 2 {
		return strings.TrimSuffix(parts[1], ".")
	}
	if len(parts) == 1 {
		return strings.TrimSuffix(parts[0], ".")
	}
	return ""
}

func classifyOverall(rels []map[string]any, cdnProvider string, result map[string]any) (string, string) {
	if len(rels) == 0 {
		ip, _ := result["ip"].(string)
		domain, _ := result["domain"].(string)
		asnInfo, _ := result["asn_info"].(map[string]any)
		asName, _ := asnInfo["as_name"].(string)
		if asName != "" {
			return "Unrelated", fmt.Sprintf("IP %s (AS: %s) has no direct relationship to %s in DNS records, SPF authorization, MX/NS infrastructure, or CT-discovered subdomains.", ip, asName, domain)
		}
		return "Unrelated", fmt.Sprintf("IP %s has no direct relationship to %s in DNS records, SPF authorization, MX/NS infrastructure, or CT-discovered subdomains.", ip, domain)
	}

	priorities := map[string]int{
		"Direct Asset (A Record)":          1,
		"Direct Asset (AAAA Record)":       1,
		"Direct Asset (Reverse DNS)":       2,
		"Email Provider (MX)":              3,
		"DNS Provider (NS)":                4,
		"SPF-Authorized Sender":            5,
		"SPF-Authorized Sender (via include)": 6,
		"CT Subdomain Match":               7,
		"CDN/Edge Network":                 8,
	}

	best := rels[0]
	bestPriority := 99
	for _, rel := range rels {
		class, _ := rel["classification"].(string)
		if p, ok := priorities[class]; ok && p < bestPriority {
			bestPriority = p
			best = rel
		}
	}

	classification, _ := best["classification"].(string)
	evidence, _ := best["evidence"].(string)

	if len(rels) == 1 {
		return classification, evidence
	}
	return classification, fmt.Sprintf("%s (and %d other relationship(s) found)", evidence, len(rels)-1)
}

func mapGetStr(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}
