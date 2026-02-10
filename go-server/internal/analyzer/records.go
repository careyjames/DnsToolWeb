package analyzer

import (
	"context"
	"fmt"
	"sync"
)

type BasicRecords struct {
	A     []string            `json:"A"`
	AAAA  []string            `json:"AAAA"`
	MX    []string            `json:"MX"`
	TXT   []string            `json:"TXT"`
	NS    []string            `json:"NS"`
	CNAME []string            `json:"CNAME"`
	CAA   []string            `json:"CAA"`
	SOA   []string            `json:"SOA"`
	SRV   []string            `json:"SRV"`
	TTLs  map[string]uint32   `json:"_ttl"`
}

var srvPrefixes = []string{
	"_autodiscover._tcp",
	"_sip._tls",
	"_sipfederationtls._tcp",
	"_xmpp-client._tcp",
	"_caldavs._tcp",
	"_carddavs._tcp",
	"_imaps._tcp",
	"_submission._tcp",
}

func (a *Analyzer) GetBasicRecords(ctx context.Context, domain string) map[string]any {
	recordTypes := []string{"A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA", "SOA"}
	records := make(map[string]any)
	for _, t := range recordTypes {
		records[t] = []string{}
	}
	records["SRV"] = []string{}
	ttls := make(map[string]uint32)

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, rt := range recordTypes {
		wg.Add(1)
		go func(rtype string) {
			defer wg.Done()
			result := a.DNS.QueryDNSWithTTL(ctx, rtype, domain)
			mu.Lock()
			records[rtype] = result.Records
			if result.TTL != nil {
				ttls[rtype] = *result.TTL
			}
			mu.Unlock()
		}(rt)
	}

	for _, prefix := range srvPrefixes {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			srvResults := a.DNS.QueryDNS(ctx, "SRV", fmt.Sprintf("%s.%s", p, domain))
			if len(srvResults) > 0 {
				mu.Lock()
				existing := records["SRV"].([]string)
				for _, rec := range srvResults {
					existing = append(existing, fmt.Sprintf("%s: %s", p, rec))
				}
				records["SRV"] = existing
				mu.Unlock()
			}
		}(prefix)
	}

	wg.Wait()
	records["_ttl"] = ttls
	return records
}

func (a *Analyzer) GetAuthoritativeRecords(ctx context.Context, domain string) map[string]any {
	recordTypes := []string{"A", "AAAA", "MX", "TXT", "NS", "CAA", "SOA"}
	emailSubdomains := map[string]string{
		"DMARC":   fmt.Sprintf("_dmarc.%s", domain),
		"MTA-STS": fmt.Sprintf("_mta-sts.%s", domain),
		"TLS-RPT": fmt.Sprintf("_smtp._tls.%s", domain),
	}

	results := make(map[string]any)
	for _, t := range recordTypes {
		results[t] = []string{}
	}
	for key := range emailSubdomains {
		results[key] = []string{}
	}
	results["_query_status"] = map[string]string{}
	results["_ttl"] = map[string]uint32{}

	nsRecords := a.DNS.QueryDNS(ctx, "NS", domain)
	if len(nsRecords) == 0 {
		parts := splitDomain(domain)
		if len(parts) > 2 {
			parent := joinDomain(parts[len(parts)-2:])
			nsRecords = a.DNS.QueryDNS(ctx, "NS", parent)
		}
	}

	if len(nsRecords) == 0 {
		return results
	}

	nsHost := nsRecords[0]
	if nsHost[len(nsHost)-1] == '.' {
		nsHost = nsHost[:len(nsHost)-1]
	}
	nsIPs := a.DNS.QueryDNS(ctx, "A", nsHost)
	if len(nsIPs) == 0 {
		return results
	}

	resolverIP := nsIPs[0]

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, rt := range recordTypes {
		wg.Add(1)
		go func(rtype string) {
			defer wg.Done()
			r := a.DNS.QueryWithTTLFromResolver(ctx, rtype, domain, resolverIP)
			mu.Lock()
			if len(r.Records) > 0 {
				results[rtype] = r.Records
			}
			if r.TTL != nil {
				ttls := results["_ttl"].(map[string]uint32)
				ttls[rtype] = *r.TTL
			}
			mu.Unlock()
		}(rt)
	}

	for key, subdomain := range emailSubdomains {
		wg.Add(1)
		go func(k, sd string) {
			defer wg.Done()
			recs, err := a.DNS.QuerySpecificResolver(ctx, "TXT", sd, resolverIP)
			mu.Lock()
			if err == nil && len(recs) > 0 {
				results[k] = recs
			}
			mu.Unlock()
		}(key, subdomain)
	}

	wg.Wait()
	return results
}

func splitDomain(domain string) []string {
	return split(domain, ".")
}

func joinDomain(parts []string) string {
	return join(parts, ".")
}

func split(s, sep string) []string {
	var result []string
	for _, p := range splitString(s, sep) {
		result = append(result, p)
	}
	return result
}

func join(parts []string, sep string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += sep
		}
		result += p
	}
	return result
}

func splitString(s, sep string) []string {
	var result []string
	for {
		idx := indexOf(s, sep)
		if idx < 0 {
			result = append(result, s)
			break
		}
		result = append(result, s[:idx])
		s = s[idx+len(sep):]
	}
	return result
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
