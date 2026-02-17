// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Remediation engine — generates actionable security fixes from scan results.
package analyzer

import (
        "fmt"
        "sort"
        "strings"
)

const (
        severityCritical = "Critical"
        severityHigh     = "High"
        severityMedium   = "Medium"
        severityLow      = "Low"

        colorCritical = "danger"
        colorHigh     = "warning"
        colorMedium   = "info"
        colorLow      = "secondary"

        rfcDMARCPolicy    = "RFC 7489 §6.3"
        rfcDMARCPolicyURL = "https://datatracker.ietf.org/doc/html/rfc7489#section-6.3"

        dkimRecordExampleGeneric = "selector1._domainkey.%s TXT \"v=DKIM1; k=rsa; p=<public_key>\""

        tlsrptDescDefault = "TLS-RPT (TLS Reporting) sends you reports about TLS connection failures when other servers try to deliver mail to your domain."
        tlsrptDescDANE    = "Your domain has DNSSEC + DANE — the strongest email transport security available."
        tlsrptDescMTASTS  = "Your domain has MTA-STS configured for transport encryption."
)

type fix struct {
        Title         string
        Description   string
        DNSRecord     string
        DNSHost       string
        DNSType       string
        DNSValue      string
        DNSPurpose    string
        DNSHostHelp   string
        RFC           string
        RFCURL        string
        Severity      string
        SeverityColor string
        SeverityOrder int
        Section       string
}

type mailFlags struct {
        hasSPF      bool
        hasDMARC    bool
        hasDKIM     bool
        hasNullMX   bool
        hasMX       bool
        spfDenyAll  bool
        dmarcReject bool
        dmarcPolicy string
}

type dnsRecord struct {
        RecordType string `json:"record_type"`
        Host       string `json:"host"`
        Value      string `json:"value"`
        Purpose    string `json:"purpose"`
        HostHelp   string `json:"host_help"`
}

type mailClassification struct {
        classification string
        label          string
        color          string
        icon           string
        summary        string
        isNoMail       bool
        recommended    []dnsRecord
}

type noMailSignalDef struct {
        key         string
        present     bool
        rfc         string
        label       string
        description string
        missingRisk string
}

type missingStepDef struct {
        missing bool
        control string
        rfc     string
        rfcURL  string
        action  string
        risk    string
}

func providerSupportsDANE(provider string) bool {
        if provider == "" {
                return true
        }
        return !isHostedEmailProvider(provider)
}

func providerSupportsBIMI(provider string) bool {
        if provider == "" {
                return true
        }
        return isBIMICapableProvider(provider)
}

func (a *Analyzer) GenerateRemediation(results map[string]any) map[string]any {
        ps := evaluateProtocolStates(results)
        ds := classifyDKIMState(ps)
        domain := extractDomain(results)

        var fixes []fix

        if ps.isNoMailDomain {
                fixes = appendNoMailHardeningFixes(fixes, ps, domain)
        } else if ps.probableNoMail {
                fixes = appendProbableNoMailFixes(fixes, ps, domain)
        } else {
                fixes = appendSPFFixes(fixes, ps, ds, results, domain)
                fixes = appendDMARCFixes(fixes, ps, results, domain)
                fixes = appendDKIMFixes(fixes, ps, ds, results, domain)
                fixes = appendMTASTSFixes(fixes, ps, domain)
                fixes = appendTLSRPTFixes(fixes, ps, domain)
                fixes = appendBIMIFixes(fixes, ps, domain)
        }
        fixes = appendDNSSECFixes(fixes, ps)
        fixes = appendDANEFixes(fixes, ps, results, domain)
        fixes = appendCAAFixes(fixes, ps, domain)

        sortFixes(fixes)

        allFixMaps := make([]map[string]any, 0, len(fixes))
        for _, f := range fixes {
                allFixMaps = append(allFixMaps, fixToMap(f))
        }

        topCount := 3
        if len(allFixMaps) < topCount {
                topCount = len(allFixMaps)
        }
        topFixMaps := allFixMaps[:topCount]

        return map[string]any{
                "top_fixes":          topFixMaps,
                "all_fixes":          allFixMaps,
                "fix_count":          float64(len(allFixMaps)),
                "posture_achievable": computeAchievablePosture(ps, fixes),
                "per_section":        buildPerSection(fixes),
        }
}

func dkimRecordExample(domain, provider string) string {
        selector := dkimSelectorForProvider(provider)
        return fmt.Sprintf(dkimRecordExampleGeneric, selector+"._domainkey."+domain)
}

func dkimSelectorForProvider(provider string) string {
        lower := strings.ToLower(provider)
        if strings.Contains(lower, "google") {
                return "google"
        }
        if strings.Contains(lower, "microsoft") || strings.Contains(lower, "office") {
                return "selector1"
        }
        return "selector1"
}

func extractDomain(results map[string]any) string {
        if d, ok := results["domain"].(string); ok {
                return d
        }
        return "yourdomain.com"
}

func fixToMap(f fix) map[string]any {
        m := map[string]any{
                "title":          f.Title,
                "fix":            f.Description,
                "severity_label": f.Severity,
                "severity_color": f.SeverityColor,
                "rfc":            f.RFC,
                "rfc_url":        f.RFCURL,
                "rfc_title":      f.RFC,
                "rfc_obsolete":   false,
                "section":        f.Section,
        }
        if f.DNSHost != "" {
                m["dns_host"] = f.DNSHost
                m["dns_type"] = f.DNSType
                m["dns_value"] = f.DNSValue
                m["dns_purpose"] = f.DNSPurpose
                m["dns_host_help"] = f.DNSHostHelp
        }
        if f.DNSRecord != "" {
                m["dns_record"] = f.DNSRecord
        }
        return m
}

func sortFixes(fixes []fix) {
        sort.SliceStable(fixes, func(i, j int) bool {
                if fixes[i].SeverityOrder != fixes[j].SeverityOrder {
                        return fixes[i].SeverityOrder < fixes[j].SeverityOrder
                }
                return fixes[i].Title < fixes[j].Title
        })
}

func buildSPFValue(includes []string, qualifier string) string {
        parts := []string{"v=spf1"}
        for _, inc := range includes {
                parts = append(parts, "include:"+inc)
        }
        parts = append(parts, qualifier)
        return strings.Join(parts, " ")
}

func buildSPFRecordExample(domain string, includes []string, qualifier string) string {
        value := buildSPFValue(includes, qualifier)
        return fmt.Sprintf("%s TXT \"%s\"", domain, value)
}

func extractSPFIncludes(results map[string]any) []string {
        spf, _ := results["spf_analysis"].(map[string]any)
        if spf == nil {
                return nil
        }
        if includes, ok := spf["includes"].([]string); ok {
                return includes
        }
        if includes, ok := spf["includes"].([]any); ok {
                var result []string
                for _, inc := range includes {
                        if s, ok := inc.(string); ok {
                                result = append(result, s)
                        }
                }
                return result
        }
        return nil
}

func appendSPFFixes(fixes []fix, ps protocolState, ds DKIMState, results map[string]any, domain string) []fix {
        if ps.spfMissing {
                includes := extractSPFIncludes(results)
                value := "v=spf1 ~all"
                if len(includes) > 0 {
                        value = buildSPFValue(includes, "~all")
                }
                fixes = append(fixes, fix{
                        Title:         "Publish SPF Record",
                        Description:   "Add an SPF record to authorize mail servers for this domain.",
                        DNSHost:       domain,
                        DNSType:       "TXT",
                        DNSValue:      value,
                        DNSPurpose:    "SPF tells receiving servers which IPs may send mail for your domain.",
                        DNSHostHelp:   "(root of domain)",
                        RFC:           "RFC 7208",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7208",
                        Severity:      severityCritical,
                        SeverityColor: colorCritical,
                        SeverityOrder: 1,
                        Section:       "SPF",
                })
                return fixes
        }
        if ps.spfDangerous {
                fixes = append(fixes, fix{
                        Title:         "Remove Dangerous SPF +all",
                        Description:   "Your SPF record uses +all which allows anyone to send mail as your domain. Change to ~all immediately.",
                        DNSHost:       domain,
                        DNSType:       "TXT",
                        DNSValue:      "v=spf1 [your includes] ~all",
                        DNSPurpose:    "The +all qualifier is dangerous — it authorizes the entire internet to send as your domain.",
                        DNSHostHelp:   "(root of domain)",
                        RFC:           "RFC 7208 §5.1",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7208#section-5.1",
                        Severity:      severityCritical,
                        SeverityColor: colorCritical,
                        SeverityOrder: 1,
                        Section:       "SPF",
                })
        }
        if ps.spfNeutral {
                fixes = append(fixes, fix{
                        Title:         "Upgrade SPF from ?all",
                        Description:   "Your SPF record uses ?all (neutral) which provides no protection. Upgrade to ~all (soft fail) for proper SPF enforcement.",
                        RFC:           "RFC 7208 §5.1",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7208#section-5.1",
                        Severity:      severityHigh,
                        SeverityColor: colorHigh,
                        SeverityOrder: 2,
                        Section:       "SPF",
                })
        }
        fixes = appendSPFLookupFix(fixes, ps)
        fixes = appendSPFUpgradeFix(fixes, ps, ds, domain, extractSPFIncludes(results))
        return fixes
}

func appendSPFLookupFix(fixes []fix, ps protocolState) []fix {
        if ps.spfLookupExceeded {
                fixes = append(fixes, fix{
                        Title:         "Reduce SPF Lookup Count",
                        Description:   fmt.Sprintf("Your SPF record uses %d DNS lookups, exceeding the RFC limit of 10. Some receivers may ignore your SPF policy.", ps.spfLookupCount),
                        RFC:           "RFC 7208 §4.6.4",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4",
                        Severity:      severityMedium,
                        SeverityColor: colorMedium,
                        SeverityOrder: 3,
                        Section:       "SPF",
                })
        }
        return fixes
}

func appendSPFUpgradeFix(fixes []fix, ps protocolState, ds DKIMState, domain string, includes []string) []fix {
        return fixes
}

func appendDMARCFixes(fixes []fix, ps protocolState, results map[string]any, domain string) []fix {
        if ps.dmarcMissing {
                fixes = append(fixes, fix{
                        Title:         "Publish DMARC Record",
                        Description:   "Add a DMARC record to protect your domain against email spoofing and receive authentication reports.",
                        DNSHost:       "_dmarc." + domain,
                        DNSType:       "TXT",
                        DNSValue:      "v=DMARC1; p=none; rua=mailto:dmarc-reports@" + domain,
                        DNSPurpose:    "DMARC tells receivers how to handle mail that fails SPF/DKIM checks.",
                        DNSHostHelp:   "(DMARC policy record)",
                        RFC:           rfcDMARCPolicy,
                        RFCURL:        rfcDMARCPolicyURL,
                        Severity:      severityCritical,
                        SeverityColor: colorCritical,
                        SeverityOrder: 1,
                        Section:       "DMARC",
                })
                return fixes
        }
        if ps.dmarcPolicy == "none" {
                fixes = append(fixes, fix{
                        Title:         "Upgrade DMARC from p=none",
                        Description:   "Your DMARC policy is monitor-only (p=none). Upgrade to p=quarantine or p=reject after reviewing reports to actively prevent spoofing.",
                        DNSHost:       "_dmarc." + domain,
                        DNSType:       "TXT",
                        DNSValue:      "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@" + domain,
                        DNSPurpose:    "A quarantine or reject policy instructs receivers to take action on failing mail.",
                        DNSHostHelp:   "(DMARC policy record)",
                        RFC:           rfcDMARCPolicy,
                        RFCURL:        rfcDMARCPolicyURL,
                        Severity:      severityHigh,
                        SeverityColor: colorHigh,
                        SeverityOrder: 2,
                        Section:       "DMARC",
                })
        }
        if ps.dmarcPolicy == "quarantine" && ps.dmarcPct >= 100 {
                fixes = append(fixes, fix{
                        Title:         "Upgrade DMARC to Reject",
                        Description:   "Your DMARC policy is set to quarantine. Upgrade to p=reject for maximum protection — reject instructs receivers to discard spoofed mail entirely rather than quarantining it.",
                        DNSHost:       "_dmarc." + domain,
                        DNSType:       "TXT",
                        DNSValue:      "v=DMARC1; p=reject; rua=mailto:dmarc-reports@" + domain,
                        DNSPurpose:    "A reject policy provides the strongest protection against domain spoofing.",
                        DNSHostHelp:   "(update existing DMARC record)",
                        RFC:           "RFC 7489 §6.3",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7489#section-6.3",
                        Severity:      severityMedium,
                        SeverityColor: colorMedium,
                        SeverityOrder: 3,
                        Section:       "DMARC",
                })
        }
        if ps.dmarcPolicy == "quarantine" && ps.dmarcPct < 100 && ps.dmarcPct > 0 {
                fixes = append(fixes, fix{
                        Title:         "Increase DMARC Coverage",
                        Description:   fmt.Sprintf("Your DMARC policy only applies to %d%% of mail. Increase pct to 100 for full protection.", ps.dmarcPct),
                        RFC:           "RFC 7489 §6.3",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7489#section-6.3",
                        Severity:      severityMedium,
                        SeverityColor: colorMedium,
                        SeverityOrder: 3,
                        Section:       "DMARC",
                })
        }
        if !ps.dmarcHasRua {
                fixes = append(fixes, fix{
                        Title:         "Add DMARC Aggregate Reporting",
                        Description:   "Add a rua= tag to receive aggregate DMARC reports. Without reporting, you cannot monitor authentication failures.",
                        DNSHost:       "_dmarc." + domain,
                        DNSType:       "TXT",
                        DNSValue:      "rua=mailto:dmarc-reports@" + domain,
                        DNSPurpose:    "Aggregate reports show who is sending mail as your domain and whether it passes authentication.",
                        DNSHostHelp:   "(add to existing DMARC record)",
                        RFC:           "RFC 7489 §7.1",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7489#section-7.1",
                        Severity:      severityMedium,
                        SeverityColor: colorMedium,
                        SeverityOrder: 3,
                        Section:       "DMARC",
                })
        }
        return fixes
}

func appendDKIMFixes(fixes []fix, ps protocolState, ds DKIMState, results map[string]any, domain string) []fix {
        if ds == DKIMWeakKeysOnly {
                fixes = append(fixes, weakKeysFix(domain))
        }
        if ds == DKIMAbsent || ds == DKIMInconclusive {
                selector := dkimSelectorForProvider(ps.primaryProvider)
                fixes = append(fixes, fix{
                        Title:         "Configure DKIM Signing",
                        Description:   "No DKIM records were discovered for common selectors. Configure DKIM signing with your mail provider to authenticate outbound messages.",
                        DNSHost:       selector + "._domainkey." + domain,
                        DNSType:       "TXT (or CNAME)",
                        DNSValue:      "v=DKIM1; k=rsa; p=<public_key>",
                        DNSPurpose:    "DKIM lets receivers verify that messages were authorized by the domain owner and not altered in transit.",
                        DNSHostHelp:   "(DKIM selector record — your provider supplies the exact value)",
                        RFC:           "RFC 6376",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc6376",
                        Severity:      severityHigh,
                        SeverityColor: colorHigh,
                        SeverityOrder: 2,
                        Section:       "DKIM",
                })
        }
        if ds == DKIMThirdPartyOnly {
                fixes = append(fixes, fix{
                        Title:         "Add Primary Domain DKIM",
                        Description:   "DKIM records were found for third-party services but not for your primary mail platform. Configure DKIM for your main sending domain.",
                        RFC:           "RFC 6376",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc6376",
                        Severity:      severityMedium,
                        SeverityColor: colorMedium,
                        SeverityOrder: 3,
                        Section:       "DKIM",
                })
        }
        return fixes
}

func weakKeysFix(domain string) fix {
        return fix{
                Title:         "Upgrade DKIM Key Strength",
                Description:   "One or more DKIM keys use 1024-bit RSA which is considered weak. Upgrade to 2048-bit RSA keys.",
                RFC:           "RFC 8301",
                RFCURL:        "https://datatracker.ietf.org/doc/html/rfc8301",
                Severity:      severityMedium,
                SeverityColor: colorMedium,
                SeverityOrder: 3,
                Section:       "DKIM",
        }
}

func appendCAAFixes(fixes []fix, ps protocolState, domain string) []fix {
        if !ps.caaOK {
                fixes = append(fixes, fix{
                        Title:         "Add CAA Records",
                        Description:   "CAA records specify which Certificate Authorities may issue certificates for your domain, reducing the risk of unauthorized certificate issuance.",
                        DNSHost:       domain,
                        DNSType:       "CAA",
                        DNSValue:      "0 issue \"letsencrypt.org\"",
                        DNSPurpose:    "CAA constrains which CAs can issue certificates for this domain.",
                        DNSHostHelp:   "(root of domain — adjust CA to match your provider)",
                        RFC:           "RFC 8659",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc8659",
                        Severity:      severityLow,
                        SeverityColor: colorLow,
                        SeverityOrder: 4,
                        Section:       "CAA",
                })
        }
        return fixes
}

func appendMTASTSFixes(fixes []fix, ps protocolState, domain string) []fix {
        if !ps.mtaStsOK && !ps.isNoMailDomain {
                fixes = append(fixes, fix{
                        Title:         "Deploy MTA-STS",
                        Description:   "MTA-STS enforces TLS encryption for inbound mail delivery, preventing downgrade attacks on your mail transport.",
                        DNSHost:       "_mta-sts." + domain,
                        DNSType:       "TXT",
                        DNSValue:      "v=STSv1; id=" + domain,
                        DNSPurpose:    "MTA-STS tells sending servers to require TLS when delivering mail to your domain.",
                        DNSHostHelp:   "(MTA-STS policy record)",
                        RFC:           "RFC 8461",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc8461",
                        Severity:      severityLow,
                        SeverityColor: colorLow,
                        SeverityOrder: 4,
                        Section:       "MTA-STS",
                })
        }
        return fixes
}

func appendTLSRPTFixes(fixes []fix, ps protocolState, domain string) []fix {
        if !ps.tlsrptOK && !ps.isNoMailDomain {
                desc := tlsrptDescDefault
                if ps.daneOK {
                        desc = tlsrptDescDANE + " " + tlsrptDescDefault
                } else if ps.mtaStsOK {
                        desc = tlsrptDescMTASTS + " " + tlsrptDescDefault
                }
                fixes = append(fixes, fix{
                        Title:         "Add TLS-RPT Reporting",
                        Description:   desc,
                        DNSHost:       "_smtp._tls." + domain,
                        DNSType:       "TXT",
                        DNSValue:      "v=TLSRPTv1; rua=mailto:tls-reports@" + domain,
                        DNSPurpose:    "TLS-RPT sends you reports about TLS connection failures to your mail servers.",
                        DNSHostHelp:   "(SMTP TLS reporting record)",
                        RFC:           "RFC 8460",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc8460",
                        Severity:      severityLow,
                        SeverityColor: colorLow,
                        SeverityOrder: 4,
                        Section:       "TLS-RPT",
                })
        }
        return fixes
}

func appendDNSSECFixes(fixes []fix, ps protocolState) []fix {
        if ps.dnssecBroken {
                fixes = append(fixes, fix{
                        Title:         "Fix Broken DNSSEC",
                        Description:   "DNSSEC validation is failing for this domain. This can cause resolvers to reject all DNS responses, making your domain unreachable.",
                        RFC:           "RFC 4035",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc4035",
                        Severity:      severityCritical,
                        SeverityColor: colorCritical,
                        SeverityOrder: 1,
                        Section:       "DNSSEC",
                })
        }
        if !ps.dnssecOK && !ps.dnssecBroken {
                fixes = append(fixes, fix{
                        Title:       "Enable DNSSEC",
                        Description: "DNSSEC is not enabled for this domain. DNSSEC provides cryptographic authentication of DNS responses, preventing cache poisoning and DNS spoofing attacks.",
                        RFC:         "RFC 4035",
                        RFCURL:      "https://datatracker.ietf.org/doc/html/rfc4035",
                        Severity:    severityMedium,
                        SeverityColor: colorMedium,
                        SeverityOrder: 3,
                        Section:     "DNSSEC",
                })
        }
        return fixes
}

func appendDANEFixes(fixes []fix, ps protocolState, results map[string]any, domain string) []fix {
        if ps.daneOK && !ps.dnssecOK {
                fixes = append(fixes, fix{
                        Title:         "DANE Requires DNSSEC",
                        Description:   "DANE/TLSA records are present but DNSSEC is not enabled. DANE cannot function without DNSSEC validation.",
                        RFC:           "RFC 7672 §2.1",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7672#section-2.1",
                        Severity:      severityHigh,
                        SeverityColor: colorHigh,
                        SeverityOrder: 2,
                        Section:       "DANE",
                })
        }
        if !ps.daneOK && ps.dnssecOK && !ps.isNoMailDomain && providerSupportsDANE(ps.primaryProvider) {
                mxHost := extractFirstMXHost(results)
                tlsaHost := "_25._tcp." + mxHost
                fixes = append(fixes, fix{
                        Title:       "Add DANE/TLSA Records",
                        Description: "DNSSEC is active — adding TLSA records enables DANE, which cryptographically binds your mail server certificates to DNS and prevents certificate-based MITM attacks.",
                        DNSHost:     tlsaHost,
                        DNSType:     "TLSA",
                        DNSValue:    "3 1 1 <certificate-sha256-hash>",
                        DNSPurpose:  "TLSA pins your mail server's TLS certificate in DNS, verified via DNSSEC.",
                        DNSHostHelp: "(TLSA record for primary MX — generate hash from your server certificate)",
                        RFC:         "RFC 7672",
                        RFCURL:      "https://datatracker.ietf.org/doc/html/rfc7672",
                        Severity:    severityLow,
                        SeverityColor: colorLow,
                        SeverityOrder: 4,
                        Section:     "DANE",
                })
        }
        return fixes
}

func extractFirstMXHost(results map[string]any) string {
        mx, _ := results["mx_records"].([]any)
        if len(mx) > 0 {
                if rec, ok := mx[0].(map[string]any); ok {
                        if host, ok := rec["host"].(string); ok && host != "" {
                                return strings.TrimSuffix(host, ".")
                        }
                        if host, ok := rec["exchange"].(string); ok && host != "" {
                                return strings.TrimSuffix(host, ".")
                        }
                }
        }
        mxAnalysis, _ := results["mx_analysis"].(map[string]any)
        if mxAnalysis != nil {
                if hosts, ok := mxAnalysis["mx_hosts"].([]any); ok && len(hosts) > 0 {
                        if h, ok := hosts[0].(string); ok {
                                return strings.TrimSuffix(h, ".")
                        }
                }
        }
        return "mail.yourdomain.com"
}

func appendNoMailHardeningFixes(fixes []fix, ps protocolState, domain string) []fix {
        if !ps.spfHardFail {
                fixes = append(fixes, fix{
                        Title:       "Harden SPF for Null MX Domain",
                        Description: "This domain publishes a Null MX record (RFC 7505) declaring it does not accept email. Complete the no-mail hardening by adding a strict SPF record that explicitly denies all senders.",
                        Severity:    "high",
                        DNSHost:     domain,
                        DNSType:     "TXT",
                        DNSValue:    "v=spf1 -all",
                        DNSPurpose:  "Explicitly declares no servers are authorized to send email from this null MX domain.",
                        RFC:         "RFC 7208",
                        Section:     "SPF",
                })
        }
        if ps.dmarcMissing || (ps.dmarcPolicy != "reject") {
                fixes = append(fixes, fix{
                        Title:       "Add DMARC Reject for Null MX Domain",
                        Description: "This domain publishes a Null MX record (RFC 7505) but lacks a DMARC reject policy. Without it, attackers can still spoof email from this domain. Complete the no-mail hardening with a strict DMARC reject policy.",
                        Severity:    "high",
                        DNSHost:     "_dmarc." + domain,
                        DNSType:     "TXT",
                        DNSValue:    "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;",
                        DNSPurpose:  "Instructs receiving servers to reject all email from this null MX domain — no legitimate mail is expected.",
                        RFC:         "RFC 7489",
                        Section:     "DMARC",
                })
        }
        return fixes
}

func appendProbableNoMailFixes(fixes []fix, ps protocolState, domain string) []fix {
        if !ps.spfHardFail {
                fixes = append(fixes, fix{
                        Title:       "Lock Down SPF for No-Mail Domain",
                        Description: "This domain has no MX records and appears to be a website-only domain. Publishing a strict SPF record explicitly declares that no servers are authorized to send email, preventing attackers from spoofing your domain.",
                        Severity:    "high",
                        DNSHost:     domain,
                        DNSType:     "TXT",
                        DNSValue:    "v=spf1 -all",
                        DNSPurpose:  "Explicitly declares no servers are authorized to send email from this domain.",
                        RFC:         "RFC 7208",
                        Section:     "SPF",
                })
        }
        if ps.dmarcMissing || (ps.dmarcPolicy != "reject") {
                fixes = append(fixes, fix{
                        Title:       "Add DMARC Reject for No-Mail Domain",
                        Description: "This domain has no MX records and appears to be a website-only domain. A DMARC reject policy tells receiving mail servers to reject any email claiming to be from your domain.",
                        Severity:    "high",
                        DNSHost:     "_dmarc." + domain,
                        DNSType:     "TXT",
                        DNSValue:    "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;",
                        DNSPurpose:  "Instructs receiving servers to reject all email from this domain — no legitimate mail is expected.",
                        RFC:         "RFC 7489",
                        Section:     "DMARC",
                })
        }
        return fixes
}

func appendBIMIFixes(fixes []fix, ps protocolState, domain string) []fix {
        if !ps.bimiOK && ps.dmarcPolicy == "reject" {
                fixes = append(fixes, fix{
                        Title:         "Add BIMI Record",
                        Description:   "Your domain has DMARC reject — you qualify for BIMI, which displays your brand logo in receiving email clients that support it (Gmail, Apple Mail, Yahoo).",
                        DNSHost:       "default._bimi." + domain,
                        DNSType:       "TXT",
                        DNSValue:      "v=BIMI1; l=https://" + domain + "/brand/logo.svg",
                        DNSPurpose:    "BIMI displays your verified brand logo next to your emails in supporting mail clients.",
                        DNSHostHelp:   "(BIMI default record)",
                        RFC:           "RFC 9495",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc9495",
                        Severity:      severityLow,
                        SeverityColor: colorLow,
                        SeverityOrder: 4,
                        Section:       "BIMI",
                })
        }
        return fixes
}

func isDANEDeployable(results map[string]any) bool {
        dnssec, _ := results["dnssec_analysis"].(map[string]any)
        if dnssec == nil {
                return false
        }
        status, _ := dnssec["status"].(string)
        return status == "secure"
}

func buildPerSection(fixes []fix) map[string]any {
        sections := map[string][]map[string]any{}
        for _, f := range fixes {
                if f.Section != "" {
                        sections[f.Section] = append(sections[f.Section], fixToMap(f))
                }
        }
        result := map[string]any{}
        for k, v := range sections {
                result[k] = v
        }
        return result
}

func computeAchievablePosture(ps protocolState, fixes []fix) string {
        coreIssues := countCoreIssues(fixes)
        if coreIssues == 0 {
                return "Secure"
        }
        if !hasSeverity(fixes, severityCritical) {
                return "Low Risk"
        }
        if len(fixes) <= 3 {
                return "Low Risk"
        }
        return "Moderate Risk"
}

func buildMailPosture(results map[string]any) map[string]any {
        ps := evaluateProtocolStates(results)
        mf := extractMailFlags(results, ps)
        signals, presentCount := buildNoMailSignals(mf)
        missingSteps := buildMissingSteps(mf)
        mc := classifyMailPosture(mf, presentCount, extractDomain(results), ps)
        verdict, badge := computeMailVerdict(mf)

        mp := map[string]any{
                "verdict":        verdict,
                "badge":          badge,
                "classification": mc.classification,
                "label":          mc.label,
                "color":          mc.color,
                "icon":           mc.icon,
                "summary":        mc.summary,
                "is_no_mail":     mc.isNoMail,
                "signals":        signals,
                "present_count":  presentCount,
                "total_signals":  3,
                "missing_steps":  missingSteps,
        }

        if mc.isNoMail {
                mp["recommended_records"] = buildNoMailRecommendedRecords(mf, extractDomain(results))
                mp["structured_records"] = buildNoMailStructuredRecords(mf, extractDomain(results))
        }

        return mp
}

func extractMailFlags(results map[string]any, ps protocolState) mailFlags {
        mf := mailFlags{}
        mf.hasSPF = ps.spfOK
        mf.hasDMARC = ps.dmarcOK || ps.dmarcWarning
        mf.hasDKIM = ps.dkimOK || ps.dkimProvider
        mf.hasNullMX = ps.isNoMailDomain
        mf.spfDenyAll = ps.spfHardFail
        mf.dmarcReject = ps.dmarcPolicy == "reject"
        mf.dmarcPolicy = ps.dmarcPolicy

        basic, _ := results["basic_records"].(map[string]any)
        if basic != nil {
                if mx, ok := basic["MX"].([]string); ok && len(mx) > 0 {
                        mf.hasMX = true
                }
        }
        return mf
}

func computeMailVerdict(mf mailFlags) (string, string) {
        if mf.hasNullMX {
                return "no_mail", "No Mail Observed"
        }
        if mf.hasSPF && mf.hasDMARC && mf.hasDKIM {
                if mf.dmarcReject {
                        return "protected", "Strongly Protected"
                }
                return "partial", "Moderately Protected"
        }
        if mf.hasSPF || mf.hasDMARC {
                return "minimal", "Limited Protection"
        }
        return "unprotected", "Unprotected"
}

func buildNoMailSignals(mf mailFlags) (map[string]any, int) {
        signals := map[string]any{}
        count := 0
        defs := []noMailSignalDef{
                {key: "null_mx", present: mf.hasNullMX, rfc: "RFC 7505", label: "Null MX", description: "Null MX record published", missingRisk: "Domain may receive unwanted mail"},
                {key: "spf_deny", present: mf.spfDenyAll, rfc: "RFC 7208", label: "SPF -all", description: "SPF hard fail configured", missingRisk: "Unauthorized senders not explicitly rejected"},
                {key: "dmarc_reject", present: mf.dmarcReject, rfc: "RFC 7489", label: "DMARC reject", description: "DMARC reject policy active", missingRisk: "Spoofed mail may be delivered"},
        }
        for _, d := range defs {
                signals[d.key] = map[string]any{
                        "present":      d.present,
                        "rfc":          d.rfc,
                        "label":        d.label,
                        "description":  d.description,
                        "missing_risk": d.missingRisk,
                }
                if d.present {
                        count++
                }
        }
        return signals, count
}

func buildMissingSteps(mf mailFlags) []map[string]any {
        var steps []map[string]any
        defs := []missingStepDef{
                {missing: !mf.hasSPF, control: "SPF Record", rfc: "RFC 7208", rfcURL: "https://datatracker.ietf.org/doc/html/rfc7208", action: "Publish an SPF record", risk: "No sender authorization"},
                {missing: !mf.hasDMARC, control: "DMARC Policy", rfc: "RFC 7489", rfcURL: "https://datatracker.ietf.org/doc/html/rfc7489", action: "Publish a DMARC record", risk: "No spoofing protection policy"},
                {missing: !mf.hasDKIM, control: "DKIM Signing", rfc: "RFC 6376", rfcURL: "https://datatracker.ietf.org/doc/html/rfc6376", action: "Configure DKIM signing", risk: "Messages cannot be cryptographically verified"},
        }
        for _, d := range defs {
                if d.missing {
                        steps = append(steps, map[string]any{
                                "control": d.control,
                                "rfc":     d.rfc,
                                "rfc_url": d.rfcURL,
                                "action":  d.action,
                                "risk":    d.risk,
                        })
                }
        }
        return steps
}

func classifyMailPosture(mf mailFlags, presentCount int, domain string, ps protocolState) mailClassification {
        if mf.hasNullMX {
                return mailClassification{
                        classification: "no_mail",
                        label:          "No Mail Observed",
                        color:          "secondary",
                        icon:           "fas fa-ban",
                        summary:        "Null MX record observed — this domain appears configured to not accept mail.",
                        isNoMail:       true,
                }
        }
        if mf.hasSPF && mf.hasDMARC && mf.hasDKIM && mf.dmarcReject {
                return mailClassification{
                        classification: "protected",
                        label:          "Strongly Protected",
                        color:          "success",
                        icon:           "fas fa-shield-alt",
                        summary:        "SPF, DKIM, and DMARC reject policy observed — strong anti-spoofing controls detected.",
                }
        }
        if mf.hasSPF && mf.hasDMARC && mf.hasDKIM {
                return mailClassification{
                        classification: "partial",
                        label:          "Moderately Protected",
                        color:          "warning",
                        icon:           "fas fa-exclamation-triangle",
                        summary:        "Core email authentication controls observed but DMARC enforcement could be strengthened.",
                }
        }
        if mf.hasSPF || mf.hasDMARC {
                return mailClassification{
                        classification: "minimal",
                        label:          "Limited Protection",
                        color:          "warning",
                        icon:           "fas fa-exclamation-circle",
                        summary:        "Some email authentication controls observed but critical components are missing.",
                }
        }
        return mailClassification{
                classification: "unprotected",
                label:          "Unprotected",
                color:          "danger",
                icon:           "fas fa-times-circle",
                summary:        "No email authentication controls observed — this domain appears vulnerable to spoofing.",
        }
}

func buildNoMailRecommendedRecords(mf mailFlags, domain string) []string {
        var records []string
        if !mf.hasNullMX {
                records = append(records, domain+" MX 0 .")
        }
        if !mf.spfDenyAll {
                records = append(records, domain+" TXT \"v=spf1 -all\"")
        }
        if !mf.dmarcReject {
                records = append(records, "_dmarc."+domain+" TXT \"v=DMARC1; p=reject;\"")
        }
        return records
}

func buildNoMailStructuredRecords(mf mailFlags, domain string) []dnsRecord {
        var records []dnsRecord
        if !mf.hasNullMX {
                records = append(records, dnsRecord{RecordType: "MX", Host: domain, Value: "0 .", Purpose: "Null MX declares this domain does not accept mail", HostHelp: "(root of domain)"})
        }
        if !mf.spfDenyAll {
                records = append(records, dnsRecord{RecordType: "TXT", Host: domain, Value: "v=spf1 -all", Purpose: "Hard-fail SPF blocks all mail from this domain", HostHelp: "(root of domain)"})
        }
        if !mf.dmarcReject {
                records = append(records, dnsRecord{RecordType: "TXT", Host: "_dmarc." + domain, Value: "v=DMARC1; p=reject;", Purpose: "DMARC reject policy for no-mail domain", HostHelp: "(DMARC policy record)"})
        }
        return records
}

func getVerdict(results map[string]any, key string) string {
        if analysis, ok := results[key].(map[string]any); ok {
                if status, ok := analysis["status"].(string); ok {
                        return status
                }
        }
        return ""
}

func countCoreIssues(fixes []fix) int {
        count := 0
        for _, f := range fixes {
                if f.Severity == severityCritical || f.Severity == severityHigh {
                        count++
                }
        }
        return count
}

func hasSeverity(fixes []fix, severity string) bool {
        for _, f := range fixes {
                if f.Severity == severity {
                        return true
                }
        }
        return false
}

func filterBySeverity(fixes []fix, severity string) []fix {
        var result []fix
        for _, f := range fixes {
                if f.Severity == severity {
                        result = append(result, f)
                }
        }
        return result
}

func joinFixTitles(fixes []fix) string {
        var titles []string
        for _, f := range fixes {
                titles = append(titles, f.Title)
        }
        return strings.Join(titles, ", ")
}
