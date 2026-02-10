package analyzer

import (
        "fmt"
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
)

type fix struct {
        Title         string
        Description   string
        DNSRecord     string
        RFC           string
        RFCURL        string
        Severity      string
        SeverityColor string
        SeverityOrder int
        Section       string
}

func (a *Analyzer) GenerateRemediation(results map[string]any) map[string]any {
        ps := evaluateProtocolStates(results)
        domain := extractDomain(results)

        var fixes []fix

        fixes = appendSPFFixes(fixes, ps, domain)
        fixes = appendDMARCFixes(fixes, ps, results, domain)
        fixes = appendDKIMFixes(fixes, ps, results, domain)
        fixes = appendCAAFixes(fixes, ps, domain)
        fixes = appendMTASTSFixes(fixes, ps, domain)
        fixes = appendTLSRPTFixes(fixes, ps, domain)
        fixes = appendDNSSECFixes(fixes, ps)
        fixes = appendBIMIFixes(fixes, ps, domain)

        sortFixes(fixes)

        topCount := 3
        if len(fixes) < topCount {
                topCount = len(fixes)
        }

        topFixes := make([]map[string]any, topCount)
        for i := 0; i < topCount; i++ {
                topFixes[i] = fixToMap(fixes[i])
        }

        allFixes := make([]map[string]any, len(fixes))
        for i := range fixes {
                allFixes[i] = fixToMap(fixes[i])
        }

        achievable := computeAchievablePosture(ps, fixes)
        perSection := buildPerSection(fixes)

        return map[string]any{
                "top_fixes":          topFixes,
                "all_fixes":          allFixes,
                "fix_count":          float64(len(fixes)),
                "posture_achievable": achievable,
                "per_section":        perSection,
        }
}

func extractDomain(results map[string]any) string {
        if d, ok := results["domain"].(string); ok {
                return d
        }
        return "yourdomain.com"
}

func fixToMap(f fix) map[string]any {
        return map[string]any{
                "title":          f.Title,
                "fix":            f.Description,
                "dns_record":     f.DNSRecord,
                "rfc":            f.RFC,
                "rfc_url":        f.RFCURL,
                "severity_label": f.Severity,
                "severity_color": f.SeverityColor,
                "severity_order": f.SeverityOrder,
                "section":        f.Section,
        }
}

func sortFixes(fixes []fix) {
        for i := 1; i < len(fixes); i++ {
                key := fixes[i]
                j := i - 1
                for j >= 0 && fixes[j].SeverityOrder > key.SeverityOrder {
                        fixes[j+1] = fixes[j]
                        j--
                }
                fixes[j+1] = key
        }
}

func appendSPFFixes(fixes []fix, ps protocolState, domain string) []fix {
        if ps.spfOK || ps.spfWarning {
                return fixes
        }
        return append(fixes, fix{
                Title:         "Publish SPF record",
                Description:   "SPF (Sender Policy Framework) tells receiving mail servers which IP addresses are authorized to send email for your domain. Without SPF, any server can claim to send as your domain.",
                DNSRecord:     fmt.Sprintf("%s TXT \"v=spf1 include:_spf.google.com ~all\"", domain),
                RFC:           "RFC 7208 §4",
                RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7208#section-4",
                Severity:      severityCritical,
                SeverityColor: colorCritical,
                SeverityOrder: 1,
                Section:       "spf",
        })
}

func appendDMARCFixes(fixes []fix, ps protocolState, results map[string]any, domain string) []fix {
        if ps.dmarcOK && ps.dmarcPolicy == "reject" {
                return fixes
        }

        if !ps.dmarcOK && !ps.dmarcWarning {
                return append(fixes, fix{
                        Title:         "Publish DMARC policy",
                        Description:   "DMARC (Domain-based Message Authentication, Reporting & Conformance) tells receivers how to handle messages that fail SPF/DKIM checks. Without DMARC, failed authentication checks are ignored.",
                        DNSRecord:     fmt.Sprintf("_dmarc.%s TXT \"v=DMARC1; p=none; rua=mailto:dmarc-reports@%s\"", domain, domain),
                        RFC:           "RFC 7489 §6.3",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7489#section-6.3",
                        Severity:      severityCritical,
                        SeverityColor: colorCritical,
                        SeverityOrder: 1,
                        Section:       "dmarc",
                })
        }

        if ps.dmarcPolicy == "none" {
                return append(fixes, fix{
                        Title:         "Escalate DMARC from monitoring to enforcement",
                        Description:   "Change your DMARC policy from p=none to p=quarantine (then p=reject). Review your DMARC aggregate reports first to ensure legitimate senders pass authentication.",
                        DNSRecord:     fmt.Sprintf("_dmarc.%s TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@%s\"", domain, domain),
                        RFC:           "RFC 7489 §6.3",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7489#section-6.3",
                        Severity:      severityHigh,
                        SeverityColor: colorHigh,
                        SeverityOrder: 2,
                        Section:       "dmarc",
                })
        }

        if ps.dmarcPolicy == "quarantine" {
                return append(fixes, fix{
                        Title:         "Upgrade DMARC to reject policy",
                        Description:   "Your DMARC policy is quarantine — spoofed messages are flagged. Upgrading to p=reject blocks them entirely. Review aggregate reports to confirm legitimate senders are aligned.",
                        DNSRecord:     fmt.Sprintf("_dmarc.%s TXT \"v=DMARC1; p=reject; rua=mailto:dmarc-reports@%s\"", domain, domain),
                        RFC:           "RFC 7489 §6.3",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7489#section-6.3",
                        Severity:      severityLow,
                        SeverityColor: colorLow,
                        SeverityOrder: 4,
                        Section:       "dmarc",
                })
        }

        return fixes
}

func appendDKIMFixes(fixes []fix, ps protocolState, results map[string]any, domain string) []fix {
        if ps.dkimOK || ps.dkimProvider {
                return fixes
        }

        dkim := getMapResult(results, "dkim_analysis")
        provider, _ := dkim["primary_provider"].(string)

        if ps.dkimPartial && provider != "" && provider != "Unknown" {
                return append(fixes, fix{
                        Title:         fmt.Sprintf("Enable DKIM for %s", provider),
                        Description:   fmt.Sprintf("DKIM is only configured for third-party services, not your primary mail platform (%s). Enable DKIM signing in %s settings to cover all outbound mail.", provider, provider),
                        DNSRecord:     fmt.Sprintf("selector1._domainkey.%s TXT \"v=DKIM1; k=rsa; p=<public_key>\"", domain),
                        RFC:           "RFC 6376 §3.6",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc6376#section-3.6",
                        Severity:      severityMedium,
                        SeverityColor: colorMedium,
                        SeverityOrder: 3,
                        Section:       "dkim",
                })
        }

        return append(fixes, fix{
                Title:         "Configure DKIM signing",
                Description:   "DKIM (DomainKeys Identified Mail) adds a cryptographic signature to outgoing emails, proving they haven't been tampered with. Enable DKIM in your email provider's settings.",
                DNSRecord:     fmt.Sprintf("selector1._domainkey.%s TXT \"v=DKIM1; k=rsa; p=<public_key>\"", domain),
                RFC:           "RFC 6376 §3.6",
                RFCURL:        "https://datatracker.ietf.org/doc/html/rfc6376#section-3.6",
                Severity:      severityCritical,
                SeverityColor: colorCritical,
                SeverityOrder: 1,
                Section:       "dkim",
        })
}

func appendCAAFixes(fixes []fix, ps protocolState, domain string) []fix {
        if ps.caaOK {
                return fixes
        }
        return append(fixes, fix{
                Title:         "Add CAA records",
                Description:   "Publish CAA DNS records to restrict which Certificate Authorities can issue TLS certificates for your domain. Specify your preferred CA (e.g., letsencrypt.org, digicert.com).",
                DNSRecord:     fmt.Sprintf("%s CAA 0 issue \"letsencrypt.org\"", domain),
                RFC:           "RFC 8659 §4",
                RFCURL:        "https://datatracker.ietf.org/doc/html/rfc8659#section-4",
                Severity:      severityMedium,
                SeverityColor: colorMedium,
                SeverityOrder: 3,
                Section:       "caa",
        })
}

func appendMTASTSFixes(fixes []fix, ps protocolState, domain string) []fix {
        if ps.mtaStsOK {
                return fixes
        }
        return append(fixes, fix{
                Title:         "Deploy MTA-STS policy",
                Description:   fmt.Sprintf("Publish an MTA-STS DNS record and host a policy file at https://mta-sts.%s/.well-known/mta-sts.txt. This tells senders to require TLS when delivering mail to your domain.", domain),
                DNSRecord:     fmt.Sprintf("_mta-sts.%s TXT \"v=STSv1; id=20240101\"", domain),
                RFC:           "RFC 8461 §3",
                RFCURL:        "https://datatracker.ietf.org/doc/html/rfc8461#section-3",
                Severity:      severityMedium,
                SeverityColor: colorMedium,
                SeverityOrder: 3,
                Section:       "mta_sts",
        })
}

func appendTLSRPTFixes(fixes []fix, ps protocolState, domain string) []fix {
        if ps.tlsrptOK {
                return fixes
        }
        return append(fixes, fix{
                Title:         "Configure TLS-RPT reporting",
                Description:   "TLS-RPT (TLS Reporting) sends you reports about TLS connection failures when other servers try to deliver mail to your domain. Helps diagnose MTA-STS and STARTTLS issues.",
                DNSRecord:     fmt.Sprintf("_smtp._tls.%s TXT \"v=TLSRPTv1; rua=mailto:tls-reports@%s\"", domain, domain),
                RFC:           "RFC 8460 §3",
                RFCURL:        "https://datatracker.ietf.org/doc/html/rfc8460#section-3",
                Severity:      severityLow,
                SeverityColor: colorLow,
                SeverityOrder: 4,
                Section:       "tlsrpt",
        })
}

func appendDNSSECFixes(fixes []fix, ps protocolState) []fix {
        if ps.dnssecOK {
                return fixes
        }
        return append(fixes, fix{
                Title:         "Enable DNSSEC",
                Description:   "DNSSEC (DNS Security Extensions) cryptographically signs DNS responses, preventing attackers from forging DNS answers. Contact your DNS hosting provider to enable DNSSEC signing.",
                DNSRecord:     "",
                RFC:           "RFC 4033 §2",
                RFCURL:        "https://datatracker.ietf.org/doc/html/rfc4033#section-2",
                Severity:      severityLow,
                SeverityColor: colorLow,
                SeverityOrder: 4,
                Section:       "dnssec",
        })
}

func appendBIMIFixes(fixes []fix, ps protocolState, domain string) []fix {
        if ps.bimiOK {
                return fixes
        }
        if !ps.dmarcOK || (ps.dmarcPolicy != "reject" && ps.dmarcPolicy != "quarantine") {
                return fixes
        }
        return append(fixes, fix{
                Title:         "Configure BIMI brand logo",
                Description:   "Publish a BIMI DNS record pointing to your brand logo (SVG Tiny PS format). For full support in Gmail, you will also need a Verified Mark Certificate (VMC).",
                DNSRecord:     fmt.Sprintf("default._bimi.%s TXT \"v=BIMI1; l=https://%s/logo.svg\"", domain, domain),
                RFC:           "BIMI Spec",
                RFCURL:        "https://bimigroup.org/implementation-guide/",
                Severity:      severityLow,
                SeverityColor: colorLow,
                SeverityOrder: 4,
                Section:       "bimi",
        })
}

func buildPerSection(fixes []fix) map[string]any {
        sections := []string{"spf", "dmarc", "dkim", "dnssec", "dane", "mta_sts", "tlsrpt", "bimi", "caa"}
        perSection := make(map[string]any)

        for _, s := range sections {
                perSection[s] = map[string]any{
                        "status": "ok",
                        "fixes":  []map[string]any{},
                }
        }

        grouped := make(map[string][]map[string]any)
        for _, f := range fixes {
                if f.Section != "" {
                        grouped[f.Section] = append(grouped[f.Section], fixToMap(f))
                }
        }

        for section, sectionFixes := range grouped {
                perSection[section] = map[string]any{
                        "status": "action_needed",
                        "fixes":  sectionFixes,
                }
        }

        return perSection
}

func computeAchievablePosture(ps protocolState, fixes []fix) string {
        hasCritical := false
        hasHigh := false
        for _, f := range fixes {
                if f.Severity == severityCritical {
                        hasCritical = true
                }
                if f.Severity == severityHigh {
                        hasHigh = true
                }
        }

        if !hasCritical && !hasHigh {
                if len(fixes) <= 3 {
                        return "Secure"
                }
                return "Low Risk"
        }

        if hasCritical {
                return "Low Risk"
        }

        return "Low Risk"
}

func buildMailPosture(results map[string]any) map[string]any {
        ps := evaluateProtocolStates(results)
        mp := make(map[string]any)

        hasSPF := ps.spfOK || ps.spfWarning
        hasDMARC := ps.dmarcOK || ps.dmarcWarning
        hasDKIM := ps.dkimOK || ps.dkimProvider

        if hasSPF && hasDMARC && (ps.dmarcPolicy == "reject") && hasDKIM {
                mp["verdict"] = "Protected"
                mp["badge"] = "success"
        } else if hasSPF && hasDMARC && ps.dmarcPolicy == "quarantine" && hasDKIM {
                mp["verdict"] = "Mostly Protected"
                mp["badge"] = "success"
        } else if hasSPF && hasDMARC && hasDKIM {
                mp["verdict"] = "Monitoring"
                mp["badge"] = "info"
        } else if hasSPF || hasDMARC {
                mp["verdict"] = "Partially"
                mp["badge"] = "warning"
        } else {
                mp["verdict"] = "Vulnerable"
                mp["badge"] = "danger"
        }

        hasNullMX := getBool(results, "has_null_mx")

        spf := getMapResult(results, "spf_analysis")
        spfNoMailIntent := getBool(spf, "no_mail_intent")
        spfAllMech, _ := spf["all_mechanism"].(string)
        spfDenyAll := spfNoMailIntent || spfAllMech == "-all"

        dmarcReject := ps.dmarcPolicy == "reject"

        basic := getMapResult(results, "basic_records")
        mxRecords := getSlice(basic, "MX")
        hasMX := len(mxRecords) > 0 && !hasNullMX

        nullMXSignal := map[string]any{
                "present":      hasNullMX,
                "rfc":          "RFC 7505",
                "label":        "Null MX",
                "description":  "A null MX record (0 .) explicitly declares that a domain does not accept email.",
                "missing_risk": "Without a null MX record, senders may still attempt delivery to this domain.",
        }
        spfDenySignal := map[string]any{
                "present":      spfDenyAll,
                "rfc":          "RFC 7208",
                "label":        "SPF -all",
                "description":  "An SPF record with '-all' rejects all mail, signaling the domain sends no email.",
                "missing_risk": "Without SPF -all, mail servers may accept forged messages from this domain.",
        }
        dmarcRejectSignal := map[string]any{
                "present":      dmarcReject,
                "rfc":          "RFC 7489",
                "label":        "DMARC reject",
                "description":  "A DMARC policy of p=reject instructs receivers to discard unauthenticated mail.",
                "missing_risk": "Without DMARC reject, spoofed messages may still be delivered.",
        }

        signals := map[string]any{
                "null_mx":      nullMXSignal,
                "spf_deny_all": spfDenySignal,
                "dmarc_reject": dmarcRejectSignal,
        }

        presentCount := 0
        if hasNullMX {
                presentCount++
        }
        if spfDenyAll {
                presentCount++
        }
        if dmarcReject {
                presentCount++
        }

        var missingSteps []map[string]any
        if !hasNullMX {
                missingSteps = append(missingSteps, map[string]any{
                        "control": "Null MX",
                        "rfc":     "RFC 7505",
                        "rfc_url": "https://datatracker.ietf.org/doc/html/rfc7505",
                        "action":  "Publish a null MX record: 0 .",
                        "risk":    "Without null MX, senders may still attempt delivery.",
                })
        }
        if !spfDenyAll {
                missingSteps = append(missingSteps, map[string]any{
                        "control": "SPF -all",
                        "rfc":     "RFC 7208",
                        "rfc_url": "https://datatracker.ietf.org/doc/html/rfc7208",
                        "action":  "Publish SPF with -all to reject all senders.",
                        "risk":    "Without SPF -all, mail servers may accept forged messages.",
                })
        }
        if !dmarcReject {
                missingSteps = append(missingSteps, map[string]any{
                        "control": "DMARC reject",
                        "rfc":     "RFC 7489",
                        "rfc_url": "https://datatracker.ietf.org/doc/html/rfc7489",
                        "action":  "Publish DMARC with p=reject to discard unauthenticated mail.",
                        "risk":    "Without DMARC reject, spoofed messages may still be delivered.",
                })
        }

        domain := extractDomain(results)

        var classification, label, clColor, clIcon, summary string
        var recommendedRecords []string
        isNoMail := false

        enforce := ps.dmarcPolicy == "reject" || ps.dmarcPolicy == "quarantine"

        if presentCount == 3 {
                classification = "no_mail_verified"
                label = "No-Mail: Verified"
                clColor = "success"
                clIcon = "shield-alt"
                summary = "This domain has verified no-mail controls: null MX, SPF -all, and DMARC reject are all present."
                isNoMail = true
        } else if presentCount >= 1 && !hasMX {
                classification = "no_mail_partial"
                label = "No-Mail: Partial"
                clColor = "warning"
                clIcon = "exclamation-triangle"
                summary = fmt.Sprintf("This domain appears to not send mail but only %d of 3 no-mail signals are present.", presentCount)
                isNoMail = true
                if !hasNullMX {
                        recommendedRecords = append(recommendedRecords, fmt.Sprintf("%s MX 0 .", domain))
                }
                if !spfDenyAll {
                        recommendedRecords = append(recommendedRecords, fmt.Sprintf("%s TXT \"v=spf1 -all\"", domain))
                }
                if !dmarcReject {
                        recommendedRecords = append(recommendedRecords, fmt.Sprintf("_dmarc.%s TXT \"v=DMARC1; p=reject;\"", domain))
                }
        } else if hasSPF && hasDMARC && hasDKIM && enforce {
                classification = "email_enforced"
                label = "Email: Enforced"
                clColor = "success"
                clIcon = "shield-alt"
                summary = "Email authentication is fully enforced with SPF, DKIM, and DMARC policy enforcement."
        } else if hasSPF && hasDMARC && hasDKIM && ps.dmarcPolicy == "none" {
                classification = "email_monitoring"
                label = "Email: Monitoring"
                clColor = "info"
                clIcon = "info-circle"
                summary = "Email authentication is configured with DMARC in monitoring mode (p=none). Enforcement recommended after reviewing reports."
        } else if hasSPF || hasDMARC {
                classification = "email_enabled"
                label = "Email: Enabled"
                clColor = "warning"
                clIcon = "check-circle"
                summary = "Some email authentication is configured but full protection is not yet in place."
        } else {
                classification = "email_ambiguous"
                label = "Email: Ambiguous"
                clColor = "secondary"
                clIcon = "question-circle"
                summary = "No email authentication detected. It is unclear whether this domain sends email."
                if !hasMX {
                        recommendedRecords = append(recommendedRecords, fmt.Sprintf("%s MX 0 .", domain))
                        recommendedRecords = append(recommendedRecords, fmt.Sprintf("%s TXT \"v=spf1 -all\"", domain))
                        recommendedRecords = append(recommendedRecords, fmt.Sprintf("_dmarc.%s TXT \"v=DMARC1; p=reject;\"", domain))
                }
        }

        mp["classification"] = classification
        mp["label"] = label
        mp["color"] = clColor
        mp["icon"] = clIcon
        mp["summary"] = summary
        mp["signals"] = signals
        mp["present_count"] = presentCount
        mp["total_signals"] = 3
        mp["missing_steps"] = missingSteps
        if len(recommendedRecords) > 0 {
                mp["recommended_records"] = recommendedRecords
        } else {
                mp["recommended_records"] = nil
        }
        mp["is_no_mail"] = isNoMail

        dnsInfra := getMapResult(results, "dns_infrastructure")
        if tier, ok := dnsInfra["provider_tier"].(string); ok && tier == "enterprise" {
                mp["dns_tier"] = "enterprise"
        }

        return mp
}

func getVerdict(results map[string]any, key string) string {
        posture := getMapResult(results, "posture")
        verdicts, ok := posture["verdicts"].(map[string]any)
        if !ok {
                return ""
        }
        v, _ := verdicts[key].(string)
        return v
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
        titles := make([]string, len(fixes))
        for i, f := range fixes {
                titles[i] = f.Title
        }
        return strings.Join(titles, ", ")
}
