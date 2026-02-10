package analyzer

import (
	"fmt"
	"strings"
)

type providerInfo struct {
	Name     string
	Tier     string
	Features []string
}

var enterpriseProviders = map[string]providerInfo{
	"cloudflare":       {Name: "Cloudflare", Tier: "enterprise", Features: []string{"DDoS protection", "Anycast", "Auto-DNSSEC available"}},
	"awsdns":           {Name: "Amazon Route 53", Tier: "enterprise", Features: []string{"DDoS protection", "Anycast", "Health checks"}},
	"route53":          {Name: "Amazon Route 53", Tier: "enterprise", Features: []string{"DDoS protection", "Anycast", "Health checks"}},
	"ultradns":         {Name: "Vercara UltraDNS", Tier: "enterprise", Features: []string{"DDoS protection", "Anycast", "DNSSEC support"}},
	"akam":             {Name: "Akamai Edge DNS", Tier: "enterprise", Features: []string{"DDoS protection", "Anycast", "Global distribution"}},
	"dynect":           {Name: "Oracle Dyn", Tier: "enterprise", Features: []string{"DDoS protection", "Anycast", "Traffic management"}},
	"nsone":            {Name: "NS1 (IBM)", Tier: "enterprise", Features: []string{"DDoS protection", "Anycast", "Intelligent DNS"}},
	"azure-dns":        {Name: "Azure DNS", Tier: "enterprise", Features: []string{"DDoS protection", "Anycast", "Azure integration"}},
	"google":           {Name: "Google Cloud DNS", Tier: "enterprise", Features: []string{"DDoS protection", "Anycast", "Auto-scaling"}},
	"verisign":         {Name: "Verisign DNS", Tier: "enterprise", Features: []string{"DDoS protection", "Anycast", "Critical infrastructure"}},
	"csc.com":          {Name: "CSC Global DNS", Tier: "enterprise", Features: []string{"Enterprise management", "Brand protection", "Global infrastructure"}},
	"cscdns":           {Name: "CSC Global DNS", Tier: "enterprise", Features: []string{"Enterprise management", "Brand protection", "Global infrastructure"}},
	"markmonitor":      {Name: "MarkMonitor DNS", Tier: "enterprise", Features: []string{"Brand protection", "Enterprise management", "Anti-fraud"}},
}

var selfHostedEnterprise = map[string]providerInfo{
	"ns.apple.com":      {Name: "Apple (Self-Hosted)", Tier: "enterprise", Features: []string{"Self-managed infrastructure", "Global Anycast", "Enterprise security"}},
	"microsoft.com":     {Name: "Microsoft (Self-Hosted)", Tier: "enterprise", Features: []string{"Self-managed infrastructure", "Global Anycast", "Enterprise security"}},
	"facebook.com":      {Name: "Meta (Self-Hosted)", Tier: "enterprise", Features: []string{"Self-managed infrastructure", "Global Anycast", "Enterprise security"}},
	"amazon.com":        {Name: "Amazon (Self-Hosted)", Tier: "enterprise", Features: []string{"Self-managed infrastructure", "Global Anycast", "Enterprise security"}},
}

var governmentDomains = map[string]providerInfo{
	".gov":    {Name: "U.S. Government", Tier: "enterprise", Features: []string{"Government security standards", "FISMA compliance", "Protected infrastructure"}},
	".mil":    {Name: "U.S. Military", Tier: "enterprise", Features: []string{"Military security standards", "DoD compliance", "Protected infrastructure"}},
	".gov.uk": {Name: "UK Government", Tier: "enterprise", Features: []string{"Government security standards", "NCSC compliance", "Protected infrastructure"}},
	".gov.au": {Name: "Australian Government", Tier: "enterprise", Features: []string{"Government security standards", "ASD compliance", "Protected infrastructure"}},
	".gc.ca":  {Name: "Canadian Government", Tier: "enterprise", Features: []string{"Government security standards", "GC compliance", "Protected infrastructure"}},
}

var managedProviders = map[string]providerInfo{
	"digitalocean":      {Name: "DigitalOcean", Tier: "managed"},
	"linode":            {Name: "Linode", Tier: "managed"},
	"vultr":             {Name: "Vultr", Tier: "managed"},
	"porkbun":           {Name: "Porkbun", Tier: "managed"},
	"namecheap":         {Name: "Namecheap", Tier: "managed"},
	"registrar-servers": {Name: "Namecheap", Tier: "managed"},
	"godaddy":           {Name: "GoDaddy", Tier: "managed"},
	"domaincontrol":     {Name: "GoDaddy", Tier: "managed"},
}

func (a *Analyzer) AnalyzeDNSInfrastructure(domain string, results map[string]any) map[string]any {
	basicRecords, _ := results["basic_records"].(map[string]any)
	nsRecords, _ := basicRecords["NS"].([]string)
	nsStr := strings.ToLower(strings.Join(nsRecords, " "))
	nsList := make([]string, len(nsRecords))
	for i, ns := range nsRecords {
		nsList[i] = strings.ToLower(ns)
	}

	var matched *providerInfo
	providerTier := "standard"
	var providerFeatures []string

	bestKey := ""
	bestCount := 0
	for key, info := range enterpriseProviders {
		count := 0
		for _, ns := range nsList {
			if strings.Contains(ns, key) {
				count++
			}
		}
		if count > bestCount {
			bestCount = count
			bestKey = key
			_ = info
		}
	}
	if bestKey != "" {
		info := enterpriseProviders[bestKey]
		matched = &info
		providerTier = "enterprise"
		providerFeatures = info.Features
	}

	if matched == nil {
		for key, info := range selfHostedEnterprise {
			if strings.Contains(nsStr, key) {
				matched = &info
				providerTier = "enterprise"
				providerFeatures = info.Features
				break
			}
		}
	}

	if matched == nil {
		for key, info := range managedProviders {
			if strings.Contains(nsStr, key) {
				matched = &info
				providerTier = "managed"
				providerFeatures = info.Features
				break
			}
		}
	}

	isGovernment := false
	for suffix, info := range governmentDomains {
		if strings.HasSuffix(domain, suffix) {
			isGovernment = true
			if matched == nil {
				matched = &info
				providerTier = "enterprise"
				providerFeatures = info.Features
			}
			break
		}
	}

	var altSecurityItems []string
	caaAnalysis, _ := results["caa_analysis"].(map[string]any)
	dnssecAnalysis, _ := results["dnssec_analysis"].(map[string]any)

	if caaAnalysis != nil && caaAnalysis["status"] == "success" {
		altSecurityItems = append(altSecurityItems, "CAA records configured")
	}
	if dnssecAnalysis != nil && dnssecAnalysis["status"] == "success" {
		altSecurityItems = append(altSecurityItems, "DNSSEC validated")
	}

	var assessment string
	switch providerTier {
	case "enterprise":
		assessment = "Enterprise-grade DNS infrastructure"
	case "managed":
		assessment = "Managed DNS hosting"
	default:
		assessment = "Standard DNS"
	}

	result := map[string]any{
		"provider_tier":      providerTier,
		"provider_features":  providerFeatures,
		"is_government":      isGovernment,
		"alt_security_items": altSecurityItems,
		"assessment":         assessment,
	}

	if matched != nil {
		result["provider_name"] = matched.Name
	}

	return result
}

func (a *Analyzer) GetHostingInfo(domain string, results map[string]any) map[string]any {
	basicRecords, _ := results["basic_records"].(map[string]any)
	aRecords, _ := basicRecords["A"].([]string)
	nsRecords, _ := basicRecords["NS"].([]string)
	mxRecords, _ := basicRecords["MX"].([]string)

	hosting := detectProvider(aRecords, hostingProviders)
	dnsHosting := detectProvider(nsRecords, dnsHostingProviders)
	emailHosting := detectProvider(mxRecords, emailHostingProviders)

	if hosting == "" {
		hosting = "Unknown"
	}
	if dnsHosting == "" {
		dnsHosting = "Unknown"
	}
	if emailHosting == "" {
		emailHosting = "Unknown"
	}

	return map[string]any{
		"hosting":       hosting,
		"dns_hosting":   dnsHosting,
		"email_hosting": emailHosting,
		"domain":        domain,
	}
}

var hostingProviders = map[string]string{
	"cloudflare": "Cloudflare", "amazon": "AWS", "azure": "Azure",
	"google": "Google Cloud", "digitalocean": "DigitalOcean",
	"linode": "Linode", "vultr": "Vultr", "hetzner": "Hetzner",
	"ovh": "OVH", "netlify": "Netlify", "vercel": "Vercel",
	"heroku": "Heroku", "github": "GitHub Pages",
	"squarespace": "Squarespace", "wix": "Wix", "shopify": "Shopify",
}

var dnsHostingProviders = map[string]string{
	"cloudflare": "Cloudflare", "awsdns": "Amazon Route 53",
	"azure-dns": "Azure DNS", "google": "Google Cloud DNS",
	"ultradns": "Vercara UltraDNS", "nsone": "NS1",
	"digitalocean": "DigitalOcean", "linode": "Linode",
	"domaincontrol": "GoDaddy", "registrar-servers": "Namecheap",
}

var emailHostingProviders = map[string]string{
	"google": "Google Workspace", "outlook": "Microsoft 365",
	"protection.outlook": "Microsoft 365", "zoho": "Zoho Mail",
	"protonmail": "ProtonMail", "fastmail": "Fastmail",
	"mx.cloudflare": "Cloudflare Email",
}

func detectProvider(records []string, providers map[string]string) string {
	combined := strings.ToLower(strings.Join(records, " "))
	for key, name := range providers {
		if strings.Contains(combined, key) {
			return name
		}
	}
	return ""
}

func (a *Analyzer) DetectEmailSecurityManagement(spf, dmarc, tlsrpt, mtasts map[string]any, domain string, dkim map[string]any) map[string]any {
	result := map[string]any{
		"actively_managed": false,
		"providers":        []string{},
		"spf_flattening":   nil,
		"provider_count":   0,
	}

	var managementProviders []string
	ruaStr := ""
	if rua, ok := dmarc["rua"]; ok && rua != nil {
		ruaStr = fmt.Sprint(rua)
	}

	monitoringProviders := map[string]string{
		"agari.com": "Agari", "dmarcian.com": "Dmarcian",
		"valimail.com": "Valimail", "postmarkapp.com": "Postmark",
		"easydmarc.com": "EasyDMARC", "uriports.com": "URIports",
		"dmarc.report": "DMARC Report",
	}

	for pattern, provider := range monitoringProviders {
		if strings.Contains(ruaStr, pattern) {
			managementProviders = append(managementProviders, provider)
		}
	}

	result["providers"] = managementProviders
	result["provider_count"] = len(managementProviders)
	result["actively_managed"] = len(managementProviders) > 0

	return result
}
