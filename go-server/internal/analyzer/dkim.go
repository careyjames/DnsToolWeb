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

var (
	dkimKeyTypeRe = regexp.MustCompile(`(?i)\bk=(\w+)`)
	dkimPKeyRe    = regexp.MustCompile(`(?i)\bp=([^;\s]*)`)
)

var defaultDKIMSelectors = []string{
	"default._domainkey", "dkim._domainkey", "mail._domainkey",
	"email._domainkey", "k1._domainkey", "k2._domainkey",
	"s1._domainkey", "s2._domainkey", "sig1._domainkey",
	"selector1._domainkey", "selector2._domainkey",
	"google._domainkey", "google2048._domainkey",
	"mailjet._domainkey", "mandrill._domainkey", "amazonses._domainkey",
	"sendgrid._domainkey", "mailchimp._domainkey", "postmark._domainkey",
	"sparkpost._domainkey", "mailgun._domainkey", "sendinblue._domainkey",
	"mimecast._domainkey", "proofpoint._domainkey", "everlytickey1._domainkey",
	"zendesk1._domainkey", "zendesk2._domainkey", "cm._domainkey",
	"mx._domainkey", "smtp._domainkey", "mailer._domainkey",
	"protonmail._domainkey", "protonmail2._domainkey", "protonmail3._domainkey",
	"fm1._domainkey", "fm2._domainkey", "fm3._domainkey",
}

var selectorProviderMap = map[string]string{
	"selector1._domainkey":    "Microsoft 365",
	"selector2._domainkey":    "Microsoft 365",
	"google._domainkey":       "Google Workspace",
	"google2048._domainkey":   "Google Workspace",
	"k1._domainkey":           "MailChimp",
	"k2._domainkey":           "MailChimp",
	"k3._domainkey":           "MailChimp",
	"mailchimp._domainkey":    "MailChimp",
	"mandrill._domainkey":     "MailChimp (Mandrill)",
	"s1._domainkey":           "SendGrid",
	"s2._domainkey":           "SendGrid",
	"sendgrid._domainkey":     "SendGrid",
	"mailjet._domainkey":      "Mailjet",
	"amazonses._domainkey":    "Amazon SES",
	"postmark._domainkey":     "Postmark",
	"sparkpost._domainkey":    "SparkPost",
	"mailgun._domainkey":      "Mailgun",
	"sendinblue._domainkey":   "Brevo (Sendinblue)",
	"mimecast._domainkey":     "Mimecast",
	"proofpoint._domainkey":   "Proofpoint",
	"everlytickey1._domainkey": "Everlytic",
	"zendesk1._domainkey":     "Zendesk",
	"zendesk2._domainkey":     "Zendesk",
	"cm._domainkey":           "Campaign Monitor",
}

var mxToDKIMProvider = map[string]string{
	"google":              "Google Workspace",
	"googlemail":          "Google Workspace",
	"gmail":               "Google Workspace",
	"outlook":             "Microsoft 365",
	"microsoft":           "Microsoft 365",
	"protection.outlook":  "Microsoft 365",
	"o365":                "Microsoft 365",
	"exchange":            "Microsoft 365",
	"intermedia":          "Microsoft 365",
	"pphosted":            "Proofpoint",
	"gpphosted":           "Proofpoint",
	"iphmx":               "Proofpoint",
	"mimecast":            "Mimecast",
	"barracudanetworks":   "Barracuda",
	"barracuda":           "Barracuda",
	"perception-point":    "Perception Point",
	"sophos":              "Sophos",
	"fireeyecloud":        "FireEye",
	"trendmicro":          "Trend Micro",
	"forcepoint":          "Forcepoint",
	"messagelabs":         "Symantec",
	"hornetsecurity":      "Hornetsecurity",
	"antispamcloud":       "SpamExperts",
	"spamexperts":         "SpamExperts",
	"zoho":                "Zoho Mail",
	"mailgun":             "Mailgun",
	"sendgrid":            "SendGrid",
	"amazonses":           "Amazon SES",
	"fastmail":            "Fastmail",
	"protonmail":          "ProtonMail",
	"mx.cloudflare":       "Cloudflare Email",
}

var securityGateways = map[string]bool{
	"Proofpoint": true, "Mimecast": true, "Barracuda": true,
	"Perception Point": true, "Sophos": true, "FireEye": true,
	"Trend Micro": true, "Forcepoint": true, "Symantec": true,
	"Hornetsecurity": true, "SpamExperts": true,
}

var primaryProviderSelectors = map[string][]string{
	"Microsoft 365":    {"selector1._domainkey", "selector2._domainkey"},
	"Google Workspace": {"google._domainkey", "google2048._domainkey"},
	"Proofpoint":       {"proofpoint._domainkey"},
	"Mimecast":         {"mimecast._domainkey"},
	"Mailgun":          {"mailgun._domainkey"},
	"SendGrid":         {"s1._domainkey", "s2._domainkey", "sendgrid._domainkey"},
	"Amazon SES":       {"amazonses._domainkey"},
	"Zoho Mail":        {"default._domainkey"},
	"Fastmail":         {"fm1._domainkey", "fm2._domainkey", "fm3._domainkey"},
	"ProtonMail":       {"protonmail._domainkey", "protonmail2._domainkey", "protonmail3._domainkey"},
	"Cloudflare Email": {"default._domainkey"},
}

var spfMailboxProviders = map[string]string{
	"spf.protection.outlook": "Microsoft 365",
	"_spf.google":            "Google Workspace",
	"spf.intermedia":         "Microsoft 365",
	"emg.intermedia":         "Microsoft 365",
	"zoho.com":               "Zoho Mail",
	"messagingengine.com":    "Fastmail",
	"protonmail.ch":          "ProtonMail",
	"mimecast":               "Mimecast",
	"pphosted":               "Proofpoint",
}

var spfAncillarySenders = map[string]string{
	"servers.mcsv.net":  "MailChimp",
	"spf.mandrillapp":   "MailChimp",
	"sendgrid.net":      "SendGrid",
	"amazonses.com":     "Amazon SES",
	"mailgun.org":       "Mailgun",
	"spf.sparkpostmail": "SparkPost",
	"mail.zendesk.com":  "Zendesk",
	"spf.brevo.com":     "Brevo (Sendinblue)",
	"spf.sendinblue":    "Brevo (Sendinblue)",
	"spf.mailjet":       "Mailjet",
	"spf.postmarkapp":   "Postmark",
	"spf.mtasv.net":     "Postmark",
	"spf.freshdesk":     "Freshdesk",
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

	if primaryProvider == "Unknown" {
		ambiguous := map[string]bool{
			"selector1._domainkey": true,
			"selector2._domainkey": true,
			"s1._domainkey":       true,
			"s2._domainkey":       true,
			"default._domainkey":  true,
			"k1._domainkey":       true,
			"k2._domainkey":       true,
		}
		if ambiguous[selectorName] {
			return "Unknown"
		}
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

func (a *Analyzer) AnalyzeDKIM(ctx context.Context, domain string, mxRecords []string, customSelectors []string) map[string]any {
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

	if len(mxRecords) == 0 {
		mxRecords = a.DNS.QueryDNS(ctx, "MX", domain)
	}

	spfRecords := a.DNS.QueryDNS(ctx, "TXT", domain)
	var spfRecord string
	for _, r := range spfRecords {
		if strings.HasPrefix(strings.ToLower(r), "v=spf1") {
			spfRecord = r
			break
		}
	}

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

	primaryHasDKIM := false
	primaryDKIMNote := ""

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

	thirdPartyOnly := false
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

	var status, message string
	if len(foundSelectors) > 0 {
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
			status = "warning"
			message = fmt.Sprintf("Found %d DKIM selector(s) but some keys are revoked", len(foundSelectors))
		} else if hasWeakKey {
			status = "warning"
			message = fmt.Sprintf("Found %d DKIM selector(s) with weak key(s) (1024-bit)", len(foundSelectors))
		} else if thirdPartyOnly {
			status = "partial"
			if len(uniqueStrengths) > 0 {
				message = fmt.Sprintf("Found DKIM for %d selector(s) (%s) but none for primary mail platform (%s)",
					len(foundSelectors), strings.Join(uniqueStrengths, ", "), primaryProvider)
			} else {
				message = fmt.Sprintf("Found DKIM for %d selector(s) but none for primary mail platform (%s)",
					len(foundSelectors), primaryProvider)
			}
		} else {
			status = "success"
			if len(uniqueStrengths) > 0 {
				message = fmt.Sprintf("Found DKIM for %d selector(s) with strong keys (%s)",
					len(foundSelectors), strings.Join(uniqueStrengths, ", "))
			} else {
				message = fmt.Sprintf("Found DKIM records for %d selector(s)", len(foundSelectors))
			}
		}
	} else {
		status = "info"
		message = "DKIM not discoverable via common selectors (large providers use rotating selectors)"
	}

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
