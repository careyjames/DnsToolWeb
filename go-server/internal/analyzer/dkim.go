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
	dkimKeyTypeRe = regexp.MustCompile(`(?i)\bk=(\w+)`)
	dkimPKeyRe    = regexp.MustCompile(`(?i)\bp=([^;\s]*)`)
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
	selZendesk1:  "Zendesk",
	selZendesk2:  "Zendesk",
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
	"mail.zendesk.com":  "Zendesk",
	"spf.brevo.com":     providerBrevo,
	"spf.sendinblue":    providerBrevo,
	"spf.mailjet":       providerMailjet,
	"spf.postmarkapp":   providerPostmark,
	"spf.mtasv.net":     providerPostmark,
	"spf.freshdesk":     "Freshdesk",
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

func detectPrimaryMailProvider(mxRecords []string, spfRecord string) map[string]any {
	result := map[string]any{"provider": "Unknown", "gateway": nil}

	if len(mxRecords) == 0 && spfRecord == "" {
		return result
	}

	var mxProvider string
	if len(mxRecords) > 0 {
		mxStr := strings.ToLower(strings.Join(mxRecords, " "))
		for key, provider := range mxToDKIMProvider {
			if strings.Contains(mxStr, key) {
				mxProvider = provider
				break
			}
		}
	}

	var spfProvider string
	if spfRecord != "" {
		spfLower := strings.ToLower(spfRecord)
		for key, provider := range spfMailboxProviders {
			if strings.Contains(spfLower, key) {
				spfProvider = provider
				break
			}
		}
		if spfProvider == "" {
			for key, provider := range spfAncillarySenders {
				if strings.Contains(spfLower, key) {
					spfProvider = provider
					break
				}
			}
		}
	}

	if mxProvider != "" && securityGateways[mxProvider] {
		if spfProvider != "" && spfProvider != mxProvider {
			result["provider"] = spfProvider
			result["gateway"] = mxProvider
		} else {
			result["provider"] = mxProvider
		}
	} else if mxProvider != "" {
		result["provider"] = mxProvider
	} else if spfProvider != "" {
		result["provider"] = spfProvider
	}

	return result
}

func classifySelectorProvider(selectorName, primaryProvider string) string {
	provider, ok := selectorProviderMap[selectorName]
	if !ok {
		return "Unknown"
	}

	if primaryProvider == "Unknown" && ambiguousSelectors[selectorName] {
		return "Unknown"
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

func analyzeDKIMKey(record string) map[string]any {
	keyInfo := map[string]any{
		"key_type": "rsa",
		"key_bits": nil,
		"revoked":  false,
		"issues":   []string{},
	}

	if m := dkimKeyTypeRe.FindStringSubmatch(strings.ToLower(record)); m != nil {
		keyInfo["key_type"] = m[1]
	}

	if m := dkimPKeyRe.FindStringSubmatch(record); m != nil {
		publicKey := strings.TrimSpace(m[1])
		if publicKey == "" {
			keyInfo["revoked"] = true
			keyInfo["issues"] = []string{"Key revoked (p= empty)"}
		} else {
			decoded, err := base64.StdEncoding.DecodeString(publicKey + "==")
			if err == nil {
				keyBytes := len(decoded)
				var issues []string
				if keyBytes <= 140 {
					keyInfo["key_bits"] = 1024
					issues = append(issues, "1024-bit key (weak, upgrade to 2048)")
				} else if keyBytes <= 300 {
					keyInfo["key_bits"] = 2048
				} else if keyBytes <= 600 {
					keyInfo["key_bits"] = 4096
				} else {
					keyInfo["key_bits"] = keyBytes * 8 / 10
				}
				keyInfo["issues"] = issues
			}
		}
	}

	if keyInfo["issues"] == nil {
		keyInfo["issues"] = []string{}
	}
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

func attributeSelectors(foundSelectors map[string]map[string]any, primaryProvider string, foundProviders map[string]bool) (bool, string, bool) {
	primaryHasDKIM := false
	primaryDKIMNote := ""
	thirdPartyOnly := false

	var unattributedSelectors []string
	for selName, selData := range foundSelectors {
		if selData["provider"].(string) == "Unknown" {
			unattributedSelectors = append(unattributedSelectors, selName)
		}
	}

	if primaryProvider != "Unknown" {
		expected := primaryProviderSelectors[primaryProvider]
		if len(expected) > 0 {
			for _, s := range expected {
				if _, ok := foundSelectors[s]; ok {
					primaryHasDKIM = true
					break
				}
			}
		} else {
			primaryHasDKIM = foundProviders[primaryProvider]
		}

		if !primaryHasDKIM && len(unattributedSelectors) > 0 {
			primaryHasDKIM = true
			for _, selName := range unattributedSelectors {
				foundSelectors[selName]["provider"] = primaryProvider
				foundSelectors[selName]["inferred"] = true
				foundProviders[primaryProvider] = true
			}
			var names []string
			for _, s := range unattributedSelectors {
				names = append(names, strings.TrimSuffix(s, domainkeySuffix))
			}
			primaryDKIMNote = fmt.Sprintf(
				"DKIM selector(s) %s inferred as %s (custom selector names — not the standard %s selector).",
				strings.Join(names, ", "), primaryProvider, primaryProvider,
			)
		}
	}

	if len(foundSelectors) > 0 && primaryProvider != "Unknown" && !primaryHasDKIM {
		thirdPartyOnly = true
		var providerNames []string
		for p := range foundProviders {
			providerNames = append(providerNames, p)
		}
		sort.Strings(providerNames)
		thirdPartyNames := "third-party services"
		if len(providerNames) > 0 {
			thirdPartyNames = strings.Join(providerNames, ", ")
		}
		primaryDKIMNote = fmt.Sprintf(
			"DKIM verified for %s only — no DKIM found for primary mail platform (%s). "+
				"The primary provider may use custom selectors not discoverable through standard checks.",
			thirdPartyNames, primaryProvider,
		)
	}

	return primaryHasDKIM, primaryDKIMNote, thirdPartyOnly
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

func (a *Analyzer) AnalyzeDKIM(ctx context.Context, domain string, mxRecords []string, customSelectors []string) map[string]any {
	selectors := buildSelectorList(customSelectors)

	if len(mxRecords) == 0 {
		mxRecords = a.DNS.QueryDNS(ctx, "MX", domain)
	}

	spfRecord := findSPFRecord(a.DNS.QueryDNS(ctx, "TXT", domain))

	providerInfo := detectPrimaryMailProvider(mxRecords, spfRecord)
	primaryProvider := providerInfo["provider"].(string)
	gateway := providerInfo["gateway"]

	foundSelectors := make(map[string]map[string]any)
	var keyIssues []string
	var keyStrengths []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, sel := range selectors {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			selectorName, records := checkDKIMSelector(ctx, a.DNS, s, domain)
			if selectorName == "" {
				return
			}

			provider := classifySelectorProvider(selectorName, primaryProvider)
			selectorInfo := map[string]any{
				"records":   records,
				"key_info":  []map[string]any{},
				"provider":  provider,
				"user_hint": false,
			}

			for _, cs := range customSelectors {
				csNorm := cs
				if !strings.HasSuffix(csNorm, domainkeySuffix) {
					csNorm = csNorm + domainkeySuffix
				}
				if csNorm == selectorName {
					selectorInfo["user_hint"] = true
				}
			}

			var localKeyIssues []string
			var localKeyStrengths []string
			var keyInfoList []map[string]any
			for _, rec := range records {
				ka := analyzeDKIMKey(rec)
				keyInfoList = append(keyInfoList, ka)
				for _, issue := range ka["issues"].([]string) {
					localKeyIssues = append(localKeyIssues, issue)
				}
				if bits, ok := ka["key_bits"]; ok && bits != nil {
					if b, ok := bits.(int); ok && b >= 2048 {
						localKeyStrengths = append(localKeyStrengths, fmt.Sprintf("%d-bit", b))
					}
				}
			}
			selectorInfo["key_info"] = keyInfoList

			mu.Lock()
			foundSelectors[selectorName] = selectorInfo
			keyIssues = append(keyIssues, localKeyIssues...)
			keyStrengths = append(keyStrengths, localKeyStrengths...)
			mu.Unlock()
		}(sel)
	}
	wg.Wait()

	foundProviders := make(map[string]bool)
	for _, selData := range foundSelectors {
		p := selData["provider"].(string)
		if p != "Unknown" {
			foundProviders[p] = true
		}
	}

	primaryHasDKIM, primaryDKIMNote, thirdPartyOnly := attributeSelectors(foundSelectors, primaryProvider, foundProviders)

	status, message := buildDKIMVerdict(foundSelectors, keyIssues, keyStrengths, primaryProvider, primaryHasDKIM, thirdPartyOnly)

	var sortedProviders []string
	for p := range foundProviders {
		sortedProviders = append(sortedProviders, p)
	}
	sort.Strings(sortedProviders)

	return map[string]any{
		"status":            status,
		"message":           message,
		"selectors":         foundSelectors,
		"key_issues":        keyIssues,
		"key_strengths":     uniqueStrings(keyStrengths),
		"primary_provider":  primaryProvider,
		"security_gateway":  gateway,
		"primary_has_dkim":  primaryHasDKIM,
		"third_party_only":  thirdPartyOnly,
		"primary_dkim_note": primaryDKIMNote,
		"found_providers":   sortedProviders,
	}
}
