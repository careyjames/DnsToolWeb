// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "context"
        "encoding/base64"
        "fmt"
        "regexp"
        "sort"
        "strings"
        "sync"
)

const domainkeySuffix = "._domainkey"

const (
        providerMicrosoft365    = "Microsoft 365"
        providerGoogleWS        = "Google Workspace"
        providerMailChimp       = "MailChimp"
        providerSendGrid        = "SendGrid"
        providerMailjet         = "Mailjet"
        providerAmazonSES       = "Amazon SES"
        providerPostmark        = "Postmark"
        providerSparkPost       = "SparkPost"
        providerMailgun         = "Mailgun"
        providerBrevo           = "Brevo (Sendinblue)"
        providerMimecast        = "Mimecast"
        providerProofpoint      = "Proofpoint"
        providerZohoMail        = "Zoho Mail"
        providerFastmail        = "Fastmail"
        providerProtonMail      = "ProtonMail"
        providerCloudflareEmail = "Cloudflare Email"
        providerBarracuda       = "Barracuda"
        providerHornetsecurity  = "Hornetsecurity"
        providerSpamExperts     = "SpamExperts"
        providerZendesk         = "Zendesk"
        providerUnknown         = "Unknown"

        selDefault     = "default._domainkey"
        selDKIM        = "dkim._domainkey"
        selMail        = "mail._domainkey"
        selEmail       = "email._domainkey"
        selK1          = "k1._domainkey"
        selK2          = "k2._domainkey"
        selS1          = "s1._domainkey"
        selS2          = "s2._domainkey"
        selSig1        = "sig1._domainkey"
        selSelector1   = "selector1._domainkey"
        selSelector2   = "selector2._domainkey"
        selGoogle      = "google._domainkey"
        selGoogle2048  = "google2048._domainkey"
        selMailjet     = "mailjet._domainkey"
        selMandrill    = "mandrill._domainkey"
        selAmazonSES   = "amazonses._domainkey"
        selSendgrid    = "sendgrid._domainkey"
        selMailchimp   = "mailchimp._domainkey"
        selPostmark    = "postmark._domainkey"
        selSparkpost   = "sparkpost._domainkey"
        selMailgun     = "mailgun._domainkey"
        selSendinblue  = "sendinblue._domainkey"
        selMimecast    = "mimecast._domainkey"
        selProofpoint  = "proofpoint._domainkey"
        selEverlytic   = "everlytickey1._domainkey"
        selZendesk1    = "zendesk1._domainkey"
        selZendesk2    = "zendesk2._domainkey"
        selCM          = "cm._domainkey"
        selMX          = "mx._domainkey"
        selSMTP        = "smtp._domainkey"
        selMailer      = "mailer._domainkey"
        selProtonmail  = "protonmail._domainkey"
        selProtonmail2 = "protonmail2._domainkey"
        selProtonmail3 = "protonmail3._domainkey"
        selFM1         = "fm1._domainkey"
        selFM2         = "fm2._domainkey"
        selFM3         = "fm3._domainkey"
)

var (
        dkimKeyTypeRe  = regexp.MustCompile(`(?i)\bk=(\w+)`)
        dkimPKeyRe     = regexp.MustCompile(`(?i)\bp=([^;\s]*)`)
        dkimTestFlagRe = regexp.MustCompile(`(?i)\bt=y\b`)
)

var defaultDKIMSelectors = []string{
        selDefault, selDKIM, selMail,
        selEmail, selK1, selK2,
        selS1, selS2, selSig1,
        selSelector1, selSelector2,
        selGoogle, selGoogle2048,
        selMailjet, selMandrill, selAmazonSES,
        selSendgrid, selMailchimp, selPostmark,
        selSparkpost, selMailgun, selSendinblue,
        selMimecast, selProofpoint, selEverlytic,
        selZendesk1, selZendesk2, selCM,
        selMX, selSMTP, selMailer,
        selProtonmail, selProtonmail2, selProtonmail3,
        selFM1, selFM2, selFM3,
}

var selectorProviderMap = map[string]string{
        selSelector1: providerMicrosoft365,
        selSelector2: providerMicrosoft365,
        selGoogle:    providerGoogleWS,
        selGoogle2048: providerGoogleWS,
        selK1:        providerMailChimp,
        selK2:        providerMailChimp,
        "k3._domainkey": providerMailChimp,
        selMailchimp: providerMailChimp,
        selMandrill:  "MailChimp (Mandrill)",
        selS1:        providerSendGrid,
        selS2:        providerSendGrid,
        selSendgrid:  providerSendGrid,
        selMailjet:   providerMailjet,
        selAmazonSES: providerAmazonSES,
        selPostmark:  providerPostmark,
        selSparkpost: providerSparkPost,
        selMailgun:   providerMailgun,
        selSendinblue: providerBrevo,
        selMimecast:  providerMimecast,
        selProofpoint: providerProofpoint,
        selEverlytic: "Everlytic",
        selZendesk1:  providerZendesk,
        selZendesk2:  providerZendesk,
        selCM:        "Campaign Monitor",
}

var mxToDKIMProvider = map[string]string{
        "google":             providerGoogleWS,
        "googlemail":         providerGoogleWS,
        "gmail":              providerGoogleWS,
        "outlook":            providerMicrosoft365,
        "microsoft":          providerMicrosoft365,
        "protection.outlook": providerMicrosoft365,
        "o365":               providerMicrosoft365,
        "exchange":           providerMicrosoft365,
        "intermedia":         providerMicrosoft365,
        "pphosted":           providerProofpoint,
        "gpphosted":          providerProofpoint,
        "iphmx":              providerProofpoint,
        "mimecast":           providerMimecast,
        "barracudanetworks":  providerBarracuda,
        "barracuda":          providerBarracuda,
        "perception-point":   "Perception Point",
        "sophos":             "Sophos",
        "fireeyecloud":       "FireEye",
        "trendmicro":         "Trend Micro",
        "forcepoint":         "Forcepoint",
        "messagelabs":        "Symantec",
        "hornetsecurity":     providerHornetsecurity,
        "antispamcloud":      providerSpamExperts,
        "spamexperts":        providerSpamExperts,
        "zoho":               providerZohoMail,
        "mailgun":            providerMailgun,
        "sendgrid":           providerSendGrid,
        "amazonses":          providerAmazonSES,
        "fastmail":           providerFastmail,
        "protonmail":         providerProtonMail,
        "mx.cloudflare":      providerCloudflareEmail,
}

var securityGateways = map[string]bool{
        providerProofpoint: true, providerMimecast: true, providerBarracuda: true,
        "Perception Point": true, "Sophos": true, "FireEye": true,
        "Trend Micro": true, "Forcepoint": true, "Symantec": true,
        providerHornetsecurity: true, providerSpamExperts: true,
}

var mailboxProviders = map[string]bool{
        providerMicrosoft365:    true,
        providerGoogleWS:        true,
        providerZohoMail:        true,
        providerFastmail:        true,
        providerProtonMail:      true,
        providerCloudflareEmail: true,
}

var primaryProviderSelectors = map[string][]string{
        providerMicrosoft365:    {selSelector1, selSelector2},
        providerGoogleWS:        {selGoogle, selGoogle2048},
        providerProofpoint:      {selProofpoint},
        providerMimecast:        {selMimecast},
        providerMailgun:         {selMailgun},
        providerSendGrid:        {selS1, selS2, selSendgrid},
        providerAmazonSES:       {selAmazonSES},
        providerZohoMail:        {selDefault},
        providerFastmail:        {selFM1, selFM2, selFM3},
        providerProtonMail:      {selProtonmail, selProtonmail2, selProtonmail3},
        providerCloudflareEmail: {selDefault},
}

var spfMailboxProviders = map[string]string{
        "spf.protection.outlook": providerMicrosoft365,
        "_spf.google":            providerGoogleWS,
        "spf.intermedia":         providerMicrosoft365,
        "emg.intermedia":         providerMicrosoft365,
        "zoho.com":               providerZohoMail,
        "messagingengine.com":    providerFastmail,
        "protonmail.ch":          providerProtonMail,
        "mimecast":               providerMimecast,
        "pphosted":               providerProofpoint,
}

var spfAncillarySenders = map[string]string{
        "servers.mcsv.net":  providerMailChimp,
        "spf.mandrillapp":   providerMailChimp,
        "sendgrid.net":      providerSendGrid,
        "amazonses.com":     providerAmazonSES,
        "mailgun.org":       providerMailgun,
        "spf.sparkpostmail": providerSparkPost,
        "mail.zendesk.com":  providerZendesk,
        "spf.brevo.com":     providerBrevo,
        "spf.sendinblue":    providerBrevo,
        "spf.mailjet":       providerMailjet,
        "spf.postmarkapp":   providerPostmark,
        "spf.mtasv.net":     providerPostmark,
        "spf.freshdesk":     "Freshdesk",
        "hostedrt.com":      "Best Practical RT",
}

var ambiguousSelectors = map[string]bool{
        selSelector1: true,
        selSelector2: true,
        selS1:        true,
        selS2:        true,
        selDefault:   true,
        selK1:        true,
        selK2:        true,
}

type ProviderResolution struct {
        Primary          string
        Gateway          string
        SPFAncillaryNote string
        DKIMInferenceNote string
}

func (pr *ProviderResolution) GatewayOrNil() interface{} {
        if pr.Gateway == "" {
                return nil
        }
        return pr.Gateway
}

func matchProviderFromRecords(records string, providerMap map[string]string) string {
        lower := strings.ToLower(records)
        for key, provider := range providerMap {
                if strings.Contains(lower, key) {
                        return provider
                }
        }
        return ""
}

func detectMXProvider(mxRecords []string) string {
        if len(mxRecords) == 0 {
                return ""
        }
        return matchProviderFromRecords(strings.Join(mxRecords, " "), mxToDKIMProvider)
}

func detectSPFMailboxProvider(spfRecord string) string {
        if spfRecord == "" {
                return ""
        }
        return matchProviderFromRecords(spfRecord, spfMailboxProviders)
}

func detectSPFAncillaryProvider(spfRecord string) string {
        if spfRecord == "" {
                return ""
        }
        return matchProviderFromRecords(spfRecord, spfAncillarySenders)
}

func resolveProviderWithGateway(mxProvider, spfMailbox string) (primary, gateway string) {
        if mxProvider != "" && securityGateways[mxProvider] && spfMailbox != "" && spfMailbox != mxProvider {
                return spfMailbox, mxProvider
        }
        if mxProvider != "" {
                return mxProvider, ""
        }
        if spfMailbox != "" {
                return spfMailbox, ""
        }
        return providerUnknown, ""
}

func detectPrimaryMailProvider(mxRecords []string, spfRecord string) ProviderResolution {
        if len(mxRecords) == 0 && spfRecord == "" {
                return ProviderResolution{Primary: providerUnknown}
        }

        mxProvider := detectMXProvider(mxRecords)
        spfMailbox := detectSPFMailboxProvider(spfRecord)

        ancillaryNote := ""

        if spfMailbox != "" && mxProvider != "" && spfMailbox != mxProvider && !securityGateways[mxProvider] {
                ancillaryNote = fmt.Sprintf(
                        "SPF authorizes %s servers, but MX records point to %s. "+
                                "The %s SPF include likely supports ancillary services "+
                                "(e.g., calendar invitations, shared documents) rather than primary mailbox hosting.",
                        spfMailbox, mxProvider, spfMailbox)
                spfMailbox = ""
        }

        if spfMailbox != "" && mxProvider == "" && len(mxRecords) > 0 {
                ancillaryNote = fmt.Sprintf(
                        "SPF authorizes %s servers, but MX records point to self-hosted infrastructure. "+
                                "The %s SPF include likely supports ancillary services "+
                                "(e.g., calendar invitations, shared documents) rather than primary mailbox hosting.",
                        spfMailbox, spfMailbox)
                spfMailbox = ""
                if detectSPFAncillaryProvider(spfRecord) == "" {
                        mxProvider = "Self-hosted"
                }
        }

        if spfMailbox == "" && mxProvider == "" {
                ancillary := detectSPFAncillaryProvider(spfRecord)
                if ancillary != "" {
                        return ProviderResolution{Primary: providerUnknown, SPFAncillaryNote: ancillaryNote}
                }
        }

        primary, gateway := resolveProviderWithGateway(mxProvider, spfMailbox)

        return ProviderResolution{Primary: primary, Gateway: gateway, SPFAncillaryNote: ancillaryNote}
}

func classifySelectorProvider(selectorName, primaryProvider string) string {
        provider, ok := selectorProviderMap[selectorName]
        if !ok {
                return providerUnknown
        }

        if primaryProvider == providerUnknown && ambiguousSelectors[selectorName] {
                return providerUnknown
        }
        return provider
}

func checkDKIMSelector(ctx context.Context, dns interface {
        QueryDNS(ctx context.Context, recordType, domain string) []string
}, selector, domain string) (string, []string) {
        fqdn := fmt.Sprintf("%s.%s", selector, domain)
        records := dns.QueryDNS(ctx, "TXT", fqdn)
        if len(records) == 0 {
                return "", nil
        }

        var dkimRecords []string
        for _, r := range records {
                lower := strings.ToLower(r)
                if strings.Contains(lower, "v=dkim1") || strings.Contains(lower, "k=") || strings.Contains(lower, "p=") {
                        dkimRecords = append(dkimRecords, r)
                }
        }
        if len(dkimRecords) > 0 {
                return selector, dkimRecords
        }
        return "", nil
}

func estimateKeyBits(keyBytes int) int {
        switch {
        case keyBytes <= 140:
                return 1024
        case keyBytes <= 300:
                return 2048
        case keyBytes <= 600:
                return 4096
        default:
                return keyBytes * 8 / 10
        }
}

func analyzePublicKey(record string) (keyBits interface{}, revoked bool, issues []string) {
        m := dkimPKeyRe.FindStringSubmatch(record)
        if m == nil {
                return nil, false, nil
        }
        publicKey := strings.TrimSpace(m[1])
        if publicKey == "" {
                return nil, true, []string{"Key revoked (p= empty)"}
        }
        decoded, err := base64.StdEncoding.DecodeString(publicKey + "==")
        if err != nil {
                return nil, false, nil
        }
        bits := estimateKeyBits(len(decoded))
        if bits == 1024 {
                return bits, false, []string{"1024-bit key (weak, upgrade to 2048)"}
        }
        return bits, false, nil
}

func analyzeDKIMKey(record string) map[string]any {
        keyInfo := map[string]any{
                "key_type":  "rsa",
                "key_bits":  nil,
                "revoked":   false,
                "test_mode": false,
                "issues":    []string{},
        }

        if m := dkimKeyTypeRe.FindStringSubmatch(strings.ToLower(record)); m != nil {
                keyInfo["key_type"] = m[1]
        }

        lower := strings.ToLower(record)
        testMode := dkimTestFlagRe.MatchString(lower)
        keyInfo["test_mode"] = testMode

        keyBits, revoked, pkIssues := analyzePublicKey(record)
        keyInfo["key_bits"] = keyBits
        keyInfo["revoked"] = revoked

        var issues []string
        issues = append(issues, pkIssues...)

        if testMode {
                issues = append(issues, "DKIM key in test mode (t=y per RFC 6376 §3.6.1) — verifiers should treat failures as unsigned, remove t=y for production")
        }

        if issues == nil {
                issues = []string{}
        }
        keyInfo["issues"] = issues
        return keyInfo
}

func buildSelectorList(customSelectors []string) []string {
        selectors := make([]string, 0, len(defaultDKIMSelectors)+len(customSelectors))
        if len(customSelectors) > 0 {
                for _, cs := range customSelectors {
                        if !strings.HasSuffix(cs, domainkeySuffix) {
                                cs = cs + domainkeySuffix
                        }
                        selectors = append(selectors, cs)
                }
        }
        for _, s := range defaultDKIMSelectors {
                found := false
                for _, existing := range selectors {
                        if existing == s {
                                found = true
                                break
                        }
                }
                if !found {
                        selectors = append(selectors, s)
                }
        }
        return selectors
}

func findSPFRecord(records []string) string {
        for _, r := range records {
                if strings.HasPrefix(strings.ToLower(r), "v=spf1") {
                        return r
                }
        }
        return ""
}

func collectUnattributed(foundSelectors map[string]map[string]any) []string {
        var unattributed []string
        for selName, selData := range foundSelectors {
                if selData["provider"].(string) == providerUnknown {
                        unattributed = append(unattributed, selName)
                }
        }
        return unattributed
}

func checkPrimaryHasDKIM(foundSelectors map[string]map[string]any, primaryProvider string, foundProviders map[string]bool) bool {
        expected := primaryProviderSelectors[primaryProvider]
        if len(expected) > 0 {
                for _, s := range expected {
                        if _, ok := foundSelectors[s]; ok {
                                return true
                        }
                }
                return false
        }
        return foundProviders[primaryProvider]
}

func inferUnattributedSelectors(foundSelectors map[string]map[string]any, unattributed []string, primaryProvider string, foundProviders map[string]bool) string {
        for _, selName := range unattributed {
                foundSelectors[selName]["provider"] = primaryProvider
                foundSelectors[selName]["inferred"] = true
                foundProviders[primaryProvider] = true
        }
        var names []string
        for _, s := range unattributed {
                names = append(names, strings.TrimSuffix(s, domainkeySuffix))
        }
        return fmt.Sprintf(
                "DKIM selector(s) %s inferred as %s (custom selector names — not the standard %s selector).",
                strings.Join(names, ", "), primaryProvider, primaryProvider,
        )
}

func buildThirdPartyNote(foundProviders map[string]bool, primaryProvider string) string {
        var providerNames []string
        for p := range foundProviders {
                providerNames = append(providerNames, p)
        }
        sort.Strings(providerNames)
        thirdPartyNames := "third-party services"
        if len(providerNames) > 0 {
                thirdPartyNames = strings.Join(providerNames, ", ")
        }
        return fmt.Sprintf(
                "DKIM verified for %s only — no DKIM found for primary mail platform (%s). "+
                        "The primary provider may use custom selectors not discoverable through standard checks. "+
                        "Try re-scanning with a custom DKIM selector if you know yours.",
                thirdPartyNames, primaryProvider,
        )
}

func attributeSelectors(foundSelectors map[string]map[string]any, primaryProvider string, foundProviders map[string]bool) (bool, string, bool) {
        if primaryProvider == providerUnknown {
                return false, "", false
        }

        unattributed := collectUnattributed(foundSelectors)
        primaryHasDKIM := checkPrimaryHasDKIM(foundSelectors, primaryProvider, foundProviders)

        if !primaryHasDKIM && len(unattributed) > 0 {
                note := inferUnattributedSelectors(foundSelectors, unattributed, primaryProvider, foundProviders)
                return true, note, false
        }

        if len(foundSelectors) > 0 && !primaryHasDKIM {
                return false, buildThirdPartyNote(foundProviders, primaryProvider), true
        }

        return primaryHasDKIM, "", false
}

func buildDKIMVerdict(foundSelectors map[string]map[string]any, keyIssues, keyStrengths []string, primaryProvider string, primaryHasDKIM, thirdPartyOnly bool) (string, string) {
        if len(foundSelectors) == 0 {
                return "info", "DKIM not discoverable via common selectors (large providers use rotating selectors)"
        }

        hasWeakKey := false
        hasRevoked := false
        for _, issue := range keyIssues {
                if strings.Contains(issue, "1024-bit") {
                        hasWeakKey = true
                }
                if strings.Contains(issue, "revoked") {
                        hasRevoked = true
                }
        }

        uniqueStrengths := uniqueStrings(keyStrengths)

        if hasRevoked {
                return "warning", fmt.Sprintf("Found %d DKIM selector(s) but some keys are revoked", len(foundSelectors))
        }
        if hasWeakKey {
                return "warning", fmt.Sprintf("Found %d DKIM selector(s) with weak key(s) (1024-bit)", len(foundSelectors))
        }
        if thirdPartyOnly {
                if len(uniqueStrengths) > 0 {
                        return "partial", fmt.Sprintf("Found DKIM for %d selector(s) (%s) but none for primary mail platform (%s)",
                                len(foundSelectors), strings.Join(uniqueStrengths, ", "), primaryProvider)
                }
                return "partial", fmt.Sprintf("Found DKIM for %d selector(s) but none for primary mail platform (%s)",
                        len(foundSelectors), primaryProvider)
        }

        if len(uniqueStrengths) > 0 {
                return "success", fmt.Sprintf("Found DKIM for %d selector(s) with strong keys (%s)",
                        len(foundSelectors), strings.Join(uniqueStrengths, ", "))
        }
        return "success", fmt.Sprintf("Found DKIM records for %d selector(s)", len(foundSelectors))
}

func isCustomSelector(selectorName string, customSelectors []string) bool {
        for _, cs := range customSelectors {
                csNorm := cs
                if !strings.HasSuffix(csNorm, domainkeySuffix) {
                        csNorm = csNorm + domainkeySuffix
                }
                if csNorm == selectorName {
                        return true
                }
        }
        return false
}

func analyzeRecordKeys(records []string) ([]map[string]any, []string, []string) {
        var keyInfoList []map[string]any
        var issues []string
        var strengths []string
        for _, rec := range records {
                ka := analyzeDKIMKey(rec)
                keyInfoList = append(keyInfoList, ka)
                issues = append(issues, ka["issues"].([]string)...)
                if bits, ok := ka["key_bits"]; ok && bits != nil {
                        if b, ok := bits.(int); ok && b >= 2048 {
                                strengths = append(strengths, fmt.Sprintf("%d-bit", b))
                        }
                }
        }
        return keyInfoList, issues, strengths
}

type dkimScanResult struct {
        selectorName string
        selectorInfo map[string]any
        keyIssues    []string
        keyStrengths []string
}

func processDKIMSelector(ctx context.Context, dns interface {
        QueryDNS(ctx context.Context, recordType, domain string) []string
}, sel, domain, primaryProvider string, customSelectors []string) *dkimScanResult {
        selectorName, records := checkDKIMSelector(ctx, dns, sel, domain)
        if selectorName == "" {
                return nil
        }

        provider := classifySelectorProvider(selectorName, primaryProvider)
        keyInfoList, localIssues, localStrengths := analyzeRecordKeys(records)

        selectorInfo := map[string]any{
                "records":   records,
                "key_info":  keyInfoList,
                "provider":  provider,
                "user_hint": isCustomSelector(selectorName, customSelectors),
        }

        return &dkimScanResult{
                selectorName: selectorName,
                selectorInfo: selectorInfo,
                keyIssues:    localIssues,
                keyStrengths: localStrengths,
        }
}

func collectFoundProviders(foundSelectors map[string]map[string]any) map[string]bool {
        providers := make(map[string]bool)
        for _, selData := range foundSelectors {
                p := selData["provider"].(string)
                if p != providerUnknown {
                        providers[p] = true
                }
        }
        return providers
}

func inferMailboxBehindGateway(res *ProviderResolution, foundProviders map[string]bool) {
        if !securityGateways[res.Primary] {
                return
        }

        var mailboxCandidates []string
        for p := range foundProviders {
                if mailboxProviders[p] {
                        mailboxCandidates = append(mailboxCandidates, p)
                }
        }

        if len(mailboxCandidates) == 1 {
                inferred := mailboxCandidates[0]
                res.DKIMInferenceNote = fmt.Sprintf(
                        "Primary mailbox provider inferred as %s from DKIM selectors (mail routed through %s security gateway).",
                        inferred, res.Primary,
                )
                res.Gateway = res.Primary
                res.Primary = inferred
                return
        }

        if len(mailboxCandidates) > 1 {
                sort.Strings(mailboxCandidates)
                res.DKIMInferenceNote = fmt.Sprintf(
                        "Multiple mailbox providers detected behind %s gateway (%s) — cannot determine single primary from DKIM alone.",
                        res.Primary, strings.Join(mailboxCandidates, ", "),
                )
        }
}

func reclassifyAmbiguousSelectors(foundSelectors map[string]map[string]any, finalPrimary string) {
        for selName, selData := range foundSelectors {
                if selData["provider"].(string) != providerUnknown {
                        continue
                }
                if !ambiguousSelectors[selName] {
                        continue
                }
                if mapped, ok := selectorProviderMap[selName]; ok && finalPrimary != providerUnknown {
                        selData["provider"] = mapped
                        selData["reclassified"] = true
                }
        }
}

func (a *Analyzer) AnalyzeDKIM(ctx context.Context, domain string, mxRecords []string, customSelectors []string) map[string]any {
        selectors := buildSelectorList(customSelectors)

        if len(mxRecords) == 0 {
                mxRecords = a.DNS.QueryDNS(ctx, "MX", domain)
        }

        spfRecord := findSPFRecord(a.DNS.QueryDNS(ctx, "TXT", domain))

        res := detectPrimaryMailProvider(mxRecords, spfRecord)

        foundSelectors := make(map[string]map[string]any)
        var keyIssues []string
        var keyStrengths []string
        var mu sync.Mutex
        var wg sync.WaitGroup

        for _, sel := range selectors {
                wg.Add(1)
                go func(s string) {
                        defer wg.Done()
                        result := processDKIMSelector(ctx, a.DNS, s, domain, res.Primary, customSelectors)
                        if result == nil {
                                return
                        }
                        mu.Lock()
                        foundSelectors[result.selectorName] = result.selectorInfo
                        keyIssues = append(keyIssues, result.keyIssues...)
                        keyStrengths = append(keyStrengths, result.keyStrengths...)
                        mu.Unlock()
                }(sel)
        }
        wg.Wait()

        foundProviders := collectFoundProviders(foundSelectors)

        prePrimary := res.Primary
        inferMailboxBehindGateway(&res, foundProviders)

        if res.Primary != prePrimary {
                reclassifyAmbiguousSelectors(foundSelectors, res.Primary)
                foundProviders = collectFoundProviders(foundSelectors)
        }

        primaryHasDKIM, primaryDKIMNote, thirdPartyOnly := attributeSelectors(foundSelectors, res.Primary, foundProviders)
        if res.DKIMInferenceNote != "" && primaryDKIMNote == "" {
                primaryDKIMNote = res.DKIMInferenceNote
        } else if res.DKIMInferenceNote != "" {
                primaryDKIMNote = res.DKIMInferenceNote + " " + primaryDKIMNote
        }

        status, message := buildDKIMVerdict(foundSelectors, keyIssues, keyStrengths, res.Primary, primaryHasDKIM, thirdPartyOnly)

        var sortedProviders []string
        for p := range foundProviders {
                sortedProviders = append(sortedProviders, p)
        }
        sort.Strings(sortedProviders)

        selectorMap := make(map[string]any, len(foundSelectors))
        for k, v := range foundSelectors {
                selectorMap[k] = v
        }

        return map[string]any{
                "status":              status,
                "message":             message,
                "selectors":           selectorMap,
                "key_issues":          keyIssues,
                "key_strengths":       uniqueStrings(keyStrengths),
                "primary_provider":    res.Primary,
                "security_gateway":    res.GatewayOrNil(),
                "primary_has_dkim":    primaryHasDKIM,
                "third_party_only":    thirdPartyOnly,
                "primary_dkim_note":   primaryDKIMNote,
                "found_providers":     sortedProviders,
                "spf_ancillary_note":  res.SPFAncillaryNote,
        }
}
