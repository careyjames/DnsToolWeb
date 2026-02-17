//go:build intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Full intelligence implementation.
package analyzer

import (
	"context"
	"net"
	"strings"
)

const (
	nameGoogleWorkspace = "Google Workspace"
	nameMicrosoft365    = "Microsoft 365"
	nameCloudflare      = "Cloudflare"
	nameCSCGlobalDNS    = "CSC Global DNS"
	nameDigitalOcean    = "DigitalOcean"
	nameGoDaddy         = "GoDaddy"
	nameLinode           = "Linode"
	nameNamecheap       = "Namecheap"
	nameAmazonRoute53   = "Amazon Route 53"
)

var enterpriseProviders = map[string]providerInfo{
	"awsdns": {
		Name:     nameAmazonRoute53,
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featDDoSProtection, featGlobalInfra},
	},
	"route53": {
		Name:     nameAmazonRoute53,
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featDDoSProtection, featGlobalInfra},
	},
	"cloudflare": {
		Name:     nameCloudflare,
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featDDoSProtection, featProtectedInfra},
	},
	"azure-dns": {
		Name:     "Azure DNS",
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featGlobalInfra, featEnterpriseSecurity},
	},
	"ultradns": {
		Name:     "UltraDNS",
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featDDoSProtection, featEnterpriseManagement},
	},
	"dynect": {
		Name:     "Oracle Dyn",
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featDDoSProtection, featEnterpriseManagement},
	},
	"nsone": {
		Name:     "NS1",
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featDDoSProtection, featEnterpriseManagement},
	},
	"google": {
		Name:     "Google Cloud DNS",
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featGlobalInfra, featEnterpriseSecurity},
	},
	"cscglobal": {
		Name:     nameCSCGlobalDNS,
		Tier:     tierEnterprise,
		Features: []string{featBrandProtection, featEnterpriseManagement, featEnterpriseSecurity},
	},
	"cscdns": {
		Name:     nameCSCGlobalDNS,
		Tier:     tierEnterprise,
		Features: []string{featBrandProtection, featEnterpriseManagement, featEnterpriseSecurity},
	},
	"akamai": {
		Name:     "Akamai Edge DNS",
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featDDoSProtection, featEnterpriseSecurity},
	},
	"akam": {
		Name:     "Akamai Edge DNS",
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featDDoSProtection, featEnterpriseSecurity},
	},
	"domaincontrol": {
		Name:     "GoDaddy",
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featDDoSProtection, featEnterpriseManagement},
	},
	"godaddy": {
		Name:     "GoDaddy",
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featDDoSProtection, featEnterpriseManagement},
	},
	"registrar-servers": {
		Name:     "Namecheap",
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featEnterpriseManagement},
	},
	"dns.he.net": {
		Name:     "Hurricane Electric",
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featGlobalInfra},
	},
	"hetzner": {
		Name:     "Hetzner",
		Tier:     tierEnterprise,
		Features: []string{featGlobalInfra, featEnterpriseManagement},
	},
	"digitalocean": {
		Name:     "DigitalOcean",
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featGlobalInfra},
	},
	"vultr": {
		Name:     "Vultr",
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featGlobalInfra},
	},
	"dnsimple": {
		Name:     "DNSimple",
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featEnterpriseManagement},
	},
	"netlify": {
		Name:     "Netlify",
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featDDoSProtection},
	},
	"vercel": {
		Name:     "Vercel",
		Tier:     tierEnterprise,
		Features: []string{featGlobalAnycast, featDDoSProtection},
	},
}

var legacyProviderBlocklist = map[string]bool{
	"networksolutions": true,
	"worldnic":         true,
	"bluehost":         true,
	"hostgator":        true,
	"ipage":            true,
	"fatcow":           true,
	"justhost":         true,
	"hostmonster":      true,
	"arvixe":           true,
	"site5":            true,
}

var selfHostedEnterprise = map[string]providerInfo{}
var governmentDomains = map[string]providerInfo{}
var managedProviders = map[string]providerInfo{}
var hostingProviders = map[string]string{}
var hostingPTRProviders = map[string]string{}
var dnsHostingProviders = map[string]string{}
var emailHostingProviders = map[string]string{}
var hostedMXProviders = map[string]bool{}

var mxProviderPatterns = map[string]string{
	"google":             nameGoogleWorkspace,
	"googlemail":         nameGoogleWorkspace,
	"gmail":              nameGoogleWorkspace,
	"outlook":            nameMicrosoft365,
	"microsoft":          nameMicrosoft365,
	"protection.outlook": nameMicrosoft365,
	"pphosted":           "Proofpoint",
	"iphmx":              "Proofpoint",
	"mimecast":           "Mimecast",
	"barracuda":          "Barracuda",
	"sophos":             "Sophos",
	"zoho":               "Zoho Mail",
	"mailgun":            "Mailgun",
	"sendgrid":           "SendGrid",
	"amazonses":          "Amazon SES",
	"fastmail":           "Fastmail",
	"protonmail":         "Proton Mail",
	"yahoodns":           "Yahoo Mail",
	"icloud":             "iCloud Mail",
	"hover":              "Hover",
	"migadu":             "Migadu",
	"pobox":              "Pobox",
	"rackspace":          "Rackspace Email",
	"emailsrvr":          "Rackspace Email",
	"secureserver":       "GoDaddy Email",
	"forcepoint":         "Forcepoint",
	"messagelabs":        "Symantec",
	"hornetsecurity":     "Hornetsecurity",
	"spamexperts":        "SpamExperts",
	"antispamcloud":      "SpamExperts",
}

var nsProviderPatterns = map[string]string{
	"cloudflare":        "Cloudflare",
	"awsdns":            nameAmazonRoute53,
	"route53":           nameAmazonRoute53,
	"google":            "Google Cloud DNS",
	"azure-dns":         "Azure DNS",
	"digitalocean":      "DigitalOcean",
	"linode":            "Linode",
	"godaddy":           "GoDaddy",
	"domaincontrol":     "GoDaddy",
	"namecheap":         "Namecheap",
	"registrar-servers": "Namecheap",
	"hetzner":           "Hetzner",
	"vultr":             "Vultr",
	"dynect":            "Oracle Dyn",
	"ultradns":          "UltraDNS",
	"nsone":             "NS1",
	"dns.he.net":        "Hurricane Electric",
	"dnsimple":          "DNSimple",
	"hover":             "Hover",
	"squarespace":       "Squarespace",
	"wix":               "Wix",
	"vercel":            "Vercel",
	"netlify":           "Netlify",
}

var webHostingPatterns = map[string]string{
	"cloudflare":         "Cloudflare",
	"amazonaws":          "AWS",
	"cloudfront":         "AWS CloudFront",
	"azurewebsites":      "Azure",
	"azure":              "Azure",
	"herokuapp":          "Heroku",
	"netlify":            "Netlify",
	"vercel":             "Vercel",
	"squarespace":        "Squarespace",
	"wix":                "Wix",
	"shopify":            "Shopify",
	"wpengine":           "WP Engine",
	"pantheon":           "Pantheon",
	"github.io":          "GitHub Pages",
	"fastly":             "Fastly",
	"akamai":             "Akamai",
	"digitalocean":       "DigitalOcean",
	"linode":             "Linode",
	"hetzner":            "Hetzner",
	"ovh":                "OVH",
	"googleusercontent":  "Google Cloud",
	"1e100.net":          "Google Cloud",
}

var ptrHostingPatterns = map[string]string{
	"amazonaws.com":        "AWS",
	"compute.amazonaws":    "AWS",
	"ec2":                  "AWS",
	"cloudfront.net":       "AWS CloudFront",
	"azure":                "Azure",
	"googleusercontent":    "Google Cloud",
	"1e100.net":            "Google Cloud",
	"bc.googleusercontent": "Google Cloud",
	"digitalocean.com":     "DigitalOcean",
	"linode.com":           "Linode",
	"vultr.com":            "Vultr",
	"hetzner":              "Hetzner",
	"ovh.net":              "OVH",
	"rackspace":            "Rackspace",
}

func (a *Analyzer) AnalyzeDNSInfrastructure(domain string, results map[string]any) map[string]any {
	basic, _ := results["basic_records"].(map[string]any)
	nsRecords, _ := basic["NS"].([]string)

	im := matchEnterpriseProvider(nsRecords)
	if im != nil && im.provider != nil {
		altItems := collectAltSecurityItems(results)
		explainsDNSSEC := false
		dnssec, _ := results["dnssec"].(map[string]any)
		if dnssec != nil {
			status, _ := dnssec["status"].(string)
			if status != "success" {
				explainsDNSSEC = true
			}
		}
		return map[string]any{
			"provider_tier":      tierEnterprise,
			"provider":           im.provider.Name,
			"provider_features":  im.provider.Features,
			"is_government":      false,
			"alt_security_items": altItems,
			"explains_no_dnssec": explainsDNSSEC,
			"assessment":         "Enterprise-grade DNS infrastructure",
		}
	}

	return map[string]any{
		"provider_tier":      "standard",
		"provider_features":  []string{},
		"is_government":      false,
		"alt_security_items": []string{},
		"assessment":         "Standard DNS",
	}
}

func (a *Analyzer) GetHostingInfo(ctx context.Context, domain string, results map[string]any) map[string]any {
	basic, _ := results["basic_records"].(map[string]any)
	mxRecords, _ := basic["MX"].([]string)
	nsRecords, _ := basic["NS"].([]string)
	isNoMail := results["has_null_mx"] == true || results["is_no_mail_domain"] == true

	emailHosting := identifyEmailProvider(mxRecords)
	dnsHosting := identifyDNSProvider(nsRecords)
	hosting := identifyWebHosting(basic)

	hosting, dnsHosting, emailHosting = applyHostingDefaults(hosting, dnsHosting, emailHosting, isNoMail)

	return map[string]any{
		"hosting":            hosting,
		"dns_hosting":        dnsHosting,
		"email_hosting":      emailHosting,
		"domain":             domain,
		"hosting_confidence": map[string]any{},
		"dns_confidence":     map[string]any{},
		"email_confidence":   map[string]any{},
		"dns_from_parent":    false,
	}
}

func (a *Analyzer) DetectEmailSecurityManagement(spf, dmarc, tlsrpt, mtasts map[string]any, domain string, dkim map[string]any) map[string]any {
	return map[string]any{
		"actively_managed": false,
		"providers":        []map[string]any{},
		"spf_flattening":   nil,
		"provider_count":   0,
		"confidence":       ConfidenceInferredMap(MethodDMARCRua),
	}
}

func enrichHostingFromEdgeCDN(results map[string]any) {}

func matchEnterpriseProvider(nsList []string) *infraMatch {
	for _, ns := range nsList {
		nsLower := strings.ToLower(ns)
		for blocked := range legacyProviderBlocklist {
			if strings.Contains(nsLower, blocked) {
				return nil
			}
		}
	}
	for _, ns := range nsList {
		nsLower := strings.ToLower(ns)
		for pattern, info := range enterpriseProviders {
			if strings.Contains(nsLower, pattern) {
				p := info
				return &infraMatch{provider: &p, tier: tierEnterprise}
			}
		}
	}
	return nil
}

func matchSelfHostedProvider(nsStr string) *infraMatch {
	return nil
}

func matchManagedProvider(nsStr string) *infraMatch {
	return nil
}

func matchGovernmentDomain(domain string) (*infraMatch, bool) {
	return nil, false
}

func collectAltSecurityItems(results map[string]any) []string {
	return nil
}

func assessTier(tier string) string {
	return "Standard DNS"
}

func (a *Analyzer) resolveNSRecords(domain string, nsRecords []string) ([]string, bool) {
	return nsRecords, false
}

func matchAllProviders(nsList []string, nsStr string) *infraMatch {
	return nil
}

func buildInfraResult(im *infraMatch, isGovernment, nsFromParent bool, results map[string]any) map[string]any {
	return map[string]any{}
}

func (a *Analyzer) detectHostingFromPTR(ctx context.Context, aRecords []string) (string, bool) {
	return "", false
}

func (a *Analyzer) resolveDNSHosting(domain string, nsRecords []string) (string, bool) {
	return "", false
}

func resolveEmailHosting(results map[string]any, mxRecords []string) (string, bool) {
	return "", false
}

func hostingConfidence(hosting string, fromPTR bool) map[string]any {
	return map[string]any{}
}

func dnsConfidence(dnsFromParent bool) map[string]any {
	return map[string]any{}
}

func emailConfidence(emailFromSPF, isNoMail bool) map[string]any {
	return map[string]any{}
}

func detectEmailProviderFromSPF(results map[string]any) string {
	return ""
}

func detectProvider(records []string, providers map[string]string) string {
	return ""
}

func matchMonitoringProvider(domain string) *managementProviderInfo {
	return nil
}

func detectDMARCReportProviders(providers map[string]map[string]any, dmarc map[string]any) {}

func detectTLSRPTReportProviders(providers map[string]map[string]any, tlsrpt map[string]any) {}

func detectSPFFlatteningProvider(providers map[string]map[string]any, spf map[string]any) map[string]any {
	return nil
}

func detectMTASTSManagement(providers map[string]map[string]any, mtasts map[string]any) {}

func (a *Analyzer) detectHostedDKIMProviders(providers map[string]map[string]any, domain string, dkim map[string]any) {
}

func matchDynamicServiceNS(nsLower string) (dynamicServiceInfo, bool) {
	return dynamicServiceInfo{}, false
}

func addDSDetection(detections map[string]*dsDetection, dsInfo dynamicServiceInfo, cap string) {}

func (a *Analyzer) scanDynamicServiceZones(ctx context.Context, zones map[string]string) map[string]*dsDetection {
	return make(map[string]*dsDetection)
}

func (a *Analyzer) detectDynamicServices(providers map[string]map[string]any, domain string) {}

func identifyEmailProvider(mxRecords []string) string {
	if len(mxRecords) == 0 {
		return ""
	}
	joined := strings.ToLower(strings.Join(mxRecords, " "))
	for pattern, provider := range mxProviderPatterns {
		if strings.Contains(joined, strings.ToLower(pattern)) {
			return provider
		}
	}
	return ""
}

func identifyDNSProvider(nsRecords []string) string {
	if len(nsRecords) == 0 {
		return ""
	}
	joined := strings.ToLower(strings.Join(nsRecords, " "))
	for pattern, provider := range nsProviderPatterns {
		if strings.Contains(joined, strings.ToLower(pattern)) {
			return provider
		}
	}
	return ""
}

func identifyWebHosting(basic map[string]any) string {
	if basic == nil {
		return ""
	}
	cnames, _ := basic["CNAME"].([]string)
	joined := strings.ToLower(strings.Join(cnames, " "))

	for pattern, provider := range webHostingPatterns {
		if strings.Contains(joined, pattern) {
			return provider
		}
	}

	aRecords, _ := basic["A"].([]string)
	if len(aRecords) > 0 {
		if provider := identifyHostingFromPTR(aRecords); provider != "" {
			return provider
		}
	}

	return ""
}

func identifyHostingFromPTR(aRecords []string) string {
	for _, ip := range aRecords {
		names, err := net.LookupAddr(ip)
		if err != nil || len(names) == 0 {
			continue
		}
		ptrLower := strings.ToLower(strings.Join(names, " "))
		for pattern, provider := range ptrHostingPatterns {
			if strings.Contains(ptrLower, pattern) {
				return provider
			}
		}
	}
	return ""
}
