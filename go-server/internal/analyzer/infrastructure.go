package analyzer

import (
        "context"
        "fmt"
        "strings"
        "time"
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
        providers := make(map[string]map[string]any)

        detectDMARCReportProviders(providers, dmarc)
        detectTLSRPTReportProviders(providers, tlsrpt)
        spfFlattening := detectSPFFlatteningProvider(providers, spf)
        detectMTASTSManagement(providers, mtasts)
        a.detectHostedDKIMProviders(providers, domain, dkim)
        a.detectDynamicServices(providers, domain)

        providerList := make([]map[string]any, 0, len(providers))
        for _, prov := range providers {
                providerList = append(providerList, prov)
        }

        return map[string]any{
                "actively_managed": len(providers) > 0,
                "providers":        providerList,
                "spf_flattening":   spfFlattening,
                "provider_count":   len(providerList),
        }
}

func extractMailtoDomains(ruaStr string) []string {
        if ruaStr == "" {
                return nil
        }
        var domains []string
        for _, part := range strings.Split(ruaStr, ",") {
                part = strings.TrimSpace(part)
                if idx := strings.Index(part, "mailto:"); idx >= 0 {
                        email := part[idx+7:]
                        if atIdx := strings.Index(email, "@"); atIdx >= 0 {
                                domain := strings.TrimRight(email, " ;,")
                                domain = domain[atIdx+1:]
                                if bangIdx := strings.Index(domain, "!"); bangIdx >= 0 {
                                        domain = domain[:bangIdx]
                                }
                                if domain != "" {
                                        domains = append(domains, strings.ToLower(domain))
                                }
                        }
                }
        }
        return domains
}

func matchMonitoringProvider(domain string) *managementProviderInfo {
        domainLower := strings.ToLower(domain)
        for pattern, info := range dmarcMonitoringProviders {
                if domainLower == pattern || strings.HasSuffix(domainLower, "."+pattern) {
                        result := info
                        return &result
                }
        }
        return nil
}

func addOrMergeProvider(providers map[string]map[string]any, info *managementProviderInfo, detectedFrom, source string) {
        name := info.Name
        if existing, ok := providers[name]; ok {
                df := existing["detected_from"].([]string)
                if !containsStr(df, detectedFrom) {
                        existing["detected_from"] = append(df, detectedFrom)
                }
                sources := existing["sources"].([]string)
                existing["sources"] = append(sources, source)
                caps := existing["capabilities"].([]string)
                for _, c := range info.Capabilities {
                        if !containsStr(caps, c) {
                                caps = append(caps, c)
                        }
                }
                existing["capabilities"] = caps
        } else {
                providers[name] = map[string]any{
                        "name":          info.Name,
                        "vendor":        info.Vendor,
                        "capabilities":  append([]string{}, info.Capabilities...),
                        "sources":       []string{source},
                        "detected_from": []string{detectedFrom},
                }
        }
}

func containsStr(ss []string, s string) bool {
        for _, v := range ss {
                if v == s {
                        return true
                }
        }
        return false
}

func detectDMARCReportProviders(providers map[string]map[string]any, dmarc map[string]any) {
        ruaStr := getStr(dmarc, "rua")
        rufStr := getStr(dmarc, "ruf")

        ruaDomains := extractMailtoDomains(ruaStr)
        rufDomains := extractMailtoDomains(rufStr)

        ruaDomainSet := make(map[string]bool)
        for _, d := range ruaDomains {
                ruaDomainSet[d] = true
        }
        rufDomainSet := make(map[string]bool)
        for _, d := range rufDomains {
                rufDomainSet[d] = true
        }

        allDomains := make(map[string]bool)
        for _, d := range ruaDomains {
                allDomains[d] = true
        }
        for _, d := range rufDomains {
                allDomains[d] = true
        }

        for domain := range allDomains {
                info := matchMonitoringProvider(domain)
                if info == nil {
                        continue
                }

                inRua := ruaDomainSet[domain]
                inRuf := rufDomainSet[domain]

                var source string
                switch {
                case inRua && inRuf:
                        source = "DMARC aggregate (rua) and forensic (ruf) reports"
                case inRuf:
                        source = "DMARC forensic reports (ruf)"
                default:
                        source = "DMARC aggregate reports (rua)"
                }
                addOrMergeProvider(providers, info, "DMARC", source)
        }
}

func detectTLSRPTReportProviders(providers map[string]map[string]any, tlsrpt map[string]any) {
        ruaStr := getStr(tlsrpt, "rua")
        domains := extractMailtoDomains(ruaStr)

        for _, domain := range domains {
                info := matchMonitoringProvider(domain)
                if info == nil {
                        continue
                }
                addOrMergeProvider(providers, info, "TLS-RPT", "TLS-RPT delivery reports")
        }
}

func detectSPFFlatteningProvider(providers map[string]map[string]any, spf map[string]any) map[string]any {
        includes, _ := spf["includes"].([]string)
        if len(includes) == 0 {
                return nil
        }

        for _, include := range includes {
                includeLower := strings.ToLower(include)
                for pattern, info := range spfFlatteningProviders {
                        if strings.HasSuffix(includeLower, pattern) || strings.Contains(includeLower, pattern) {
                                mpi := &managementProviderInfo{
                                        Name:         info.Name,
                                        Vendor:       info.Vendor,
                                        Capabilities: []string{"SPF management", "SPF flattening"},
                                }
                                addOrMergeProvider(providers, mpi, "SPF flattening", fmt.Sprintf("SPF flattening (include:%s)", include))

                                return map[string]any{
                                        "provider": info.Name,
                                        "vendor":   info.Vendor,
                                        "include":  include,
                                }
                        }
                }
        }
        return nil
}

func detectMTASTSManagement(providers map[string]map[string]any, mtasts map[string]any) {
        status := getStr(mtasts, "status")
        if status != "success" && status != "warning" {
                return
        }
        if getStr(mtasts, "record") == "" {
                return
        }

        hostingCNAME := getStr(mtasts, "hosting_cname")

        for name, prov := range providers {
                caps, _ := prov["capabilities"].([]string)
                if containsStr(caps, "MTA-STS hosting") {
                        df, _ := prov["detected_from"].([]string)
                        if !containsStr(df, "MTA-STS") {
                                providers[name]["detected_from"] = append(df, "MTA-STS")
                                sources, _ := prov["sources"].([]string)
                                providers[name]["sources"] = append(sources, "MTA-STS policy hosting")
                        }
                        return
                }
        }

        if hostingCNAME == "" {
                return
        }

        for pattern, info := range dmarcMonitoringProviders {
                if !containsStr(info.Capabilities, "MTA-STS hosting") {
                        continue
                }
                if !strings.Contains(hostingCNAME, pattern) {
                        continue
                }
                mpi := &managementProviderInfo{
                        Name:         info.Name,
                        Vendor:       info.Vendor,
                        Capabilities: info.Capabilities,
                }
                addOrMergeProvider(providers, mpi, "MTA-STS", fmt.Sprintf("MTA-STS hosting (CNAME: %s)", hostingCNAME))
                return
        }
}

func (a *Analyzer) detectHostedDKIMProviders(providers map[string]map[string]any, domain string, dkim map[string]any) {
        if domain == "" || dkim == nil {
                return
        }
        selectors, _ := dkim["selectors"].(map[string]any)
        if selectors == nil {
                return
        }

        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        for selName := range selectors {
                dkimFQDN := selName + "." + domain
                cnames := a.DNS.QueryDNS(ctx, "CNAME", dkimFQDN)
                for _, cname := range cnames {
                        cnameLower := strings.ToLower(strings.TrimRight(cname, "."))
                        for cnamePattern, info := range hostedDKIMProviders {
                                if !strings.HasSuffix(cnameLower, cnamePattern) {
                                        continue
                                }
                                selShort := strings.ReplaceAll(selName, "._domainkey", "")
                                mpi := &managementProviderInfo{
                                        Name:         info.Name,
                                        Vendor:       info.Vendor,
                                        Capabilities: []string{"DKIM hosting"},
                                }
                                addOrMergeProvider(providers, mpi, "Hosted DKIM", fmt.Sprintf("Hosted DKIM (CNAME: %s → %s)", selShort, cnameLower))
                                break
                        }
                }
        }
}

func (a *Analyzer) detectDynamicServices(providers map[string]map[string]any, domain string) {
        if domain == "" {
                return
        }

        zones := map[string]string{
                "_dmarc":     fmt.Sprintf("_dmarc.%s", domain),
                "_domainkey": fmt.Sprintf("_domainkey.%s", domain),
                "_mta-sts":   fmt.Sprintf("_mta-sts.%s", domain),
                "_smtp._tls": fmt.Sprintf("_smtp._tls.%s", domain),
        }

        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        type dsDetection struct {
                info         dynamicServiceInfo
                capabilities []string
        }
        detections := make(map[string]*dsDetection)

        for zoneKey, zoneFQDN := range zones {
                nsRecords := a.DNS.QueryDNS(ctx, "NS", zoneFQDN)
                for _, ns := range nsRecords {
                        nsLower := strings.ToLower(strings.TrimRight(ns, "."))
                        for nsPattern, dsInfo := range dynamicServicesProviders {
                                if !strings.HasSuffix(nsLower, nsPattern) {
                                        continue
                                }
                                cap := dynamicServicesZones[zoneKey]
                                if cap == "" {
                                        cap = zoneKey + " management"
                                }
                                if det, ok := detections[dsInfo.Name]; ok {
                                        if !containsStr(det.capabilities, cap) {
                                                det.capabilities = append(det.capabilities, cap)
                                        }
                                } else {
                                        detections[dsInfo.Name] = &dsDetection{
                                                info:         dsInfo,
                                                capabilities: []string{cap},
                                        }
                                }
                                break
                        }
                }
        }

        for _, det := range detections {
                capLabels := strings.Join(det.capabilities, ", ")
                mpi := &managementProviderInfo{
                        Name:         det.info.Name,
                        Vendor:       det.info.Vendor,
                        Capabilities: det.capabilities,
                }
                addOrMergeProvider(providers, mpi, "Dynamic services", fmt.Sprintf("Dynamic services (%s)", capLabels))
        }
}

