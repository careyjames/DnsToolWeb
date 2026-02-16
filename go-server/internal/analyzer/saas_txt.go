// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"fmt"
	"regexp"
	"strings"
)

type saasPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

var saasPatterns = []saasPattern{
	{Name: "Google", Pattern: regexp.MustCompile(`^google-site-verification=`)},
	{Name: "Facebook", Pattern: regexp.MustCompile(`^facebook-domain-verification=`)},
	{Name: "Apple", Pattern: regexp.MustCompile(`^apple-domain-verification=`)},
	{Name: "Microsoft", Pattern: regexp.MustCompile(`^MS=`)},
	{Name: "OpenAI", Pattern: regexp.MustCompile(`^openai-domain-verification=`)},
	{Name: "Adobe", Pattern: regexp.MustCompile(`^adobe-idp-site-verification=`)},
	{Name: "Adobe Sign", Pattern: regexp.MustCompile(`^adobe-sign-verification=`)},
	{Name: "Atlassian", Pattern: regexp.MustCompile(`^atlassian-domain-verification=`)},
	{Name: "DocuSign", Pattern: regexp.MustCompile(`^docusign=`)},
	{Name: "Dropbox", Pattern: regexp.MustCompile(`^dropbox-domain-verification=`)},
	{Name: "GitHub", Pattern: regexp.MustCompile(`^_github-challenge-`)},
	{Name: "GitLab", Pattern: regexp.MustCompile(`^gitlab-pages-verification-code=`)},
	{Name: "HubSpot", Pattern: regexp.MustCompile(`^hubspot-developer-verification=`)},
	{Name: "Keybase", Pattern: regexp.MustCompile(`^keybase-site-verification=`)},
	{Name: "LinkedIn", Pattern: regexp.MustCompile(`^linkedin-code=`)},
	{Name: "Notion", Pattern: regexp.MustCompile(`^notion-domain-verification=`)},
	{Name: "Pinterest", Pattern: regexp.MustCompile(`^pinterest-site-verification=`)},
	{Name: "Postman", Pattern: regexp.MustCompile(`^postman-domain-verification=`)},
	{Name: "Salesforce", Pattern: regexp.MustCompile(`^salesforce-`)},
	{Name: "Slack", Pattern: regexp.MustCompile(`^slack-domain-verification=`)},
	{Name: "Stripe", Pattern: regexp.MustCompile(`^stripe-verification=`)},
	{Name: "Twilio", Pattern: regexp.MustCompile(`^twilio-domain-verification=`)},
	{Name: "Twitter / X", Pattern: regexp.MustCompile(`^twitter-domain-verification=`)},
	{Name: "Yandex", Pattern: regexp.MustCompile(`^yandex-verification:`)},
	{Name: "Zoom", Pattern: regexp.MustCompile(`^zoom-domain-verification=`)},
	{Name: "Webex", Pattern: regexp.MustCompile(`^webexdomainverification`)},
	{Name: "Citrix", Pattern: regexp.MustCompile(`^citrix-verification-code=`)},
	{Name: "Canva", Pattern: regexp.MustCompile(`^canva-site-verification=`)},
	{Name: "Shopify", Pattern: regexp.MustCompile(`^shopify-verification=`)},
	{Name: "Zendesk", Pattern: regexp.MustCompile(`^zendesk-domain-verification=`)},
	{Name: "1Password", Pattern: regexp.MustCompile(`^1password-site-verification=`)},
	{Name: "Amazon SES", Pattern: regexp.MustCompile(`^amazonses:`)},
	{Name: "Brevo (Sendinblue)", Pattern: regexp.MustCompile(`^brevo-code:`)},
	{Name: "Mailchimp", Pattern: regexp.MustCompile(`^mc:`)},
	{Name: "Miro", Pattern: regexp.MustCompile(`^miro-verification=`)},
	{Name: "Intercom", Pattern: regexp.MustCompile(`^intercom-domain-verification=`)},
	{Name: "Statuspage", Pattern: regexp.MustCompile(`^status-page-domain-verification=`)},
	{Name: "Smartsheet", Pattern: regexp.MustCompile(`^smartsheet-site-validation=`)},
	{Name: "Have I Been Pwned", Pattern: regexp.MustCompile(`^have-i-been-pwned-verification=`)},
	{Name: "Cisco Umbrella", Pattern: regexp.MustCompile(`^cisco-ci-domain-verification=`)},
	{Name: "Detectify", Pattern: regexp.MustCompile(`^detectify-verification=`)},
	{Name: "Dynatrace", Pattern: regexp.MustCompile(`^dynatrace-site-verification=`)},
	{Name: "MongoDB", Pattern: regexp.MustCompile(`^mongodb-site-verification=`)},
	{Name: "Fastly", Pattern: regexp.MustCompile(`^fastly-domain-delegation-`)},
	{Name: "Ahrefs", Pattern: regexp.MustCompile(`^ahrefs-site-verification_`)},
	{Name: "Brave", Pattern: regexp.MustCompile(`^brave-ledger-verification=`)},
	{Name: "Sophos", Pattern: regexp.MustCompile(`^sophos-domain-verification=`)},
}

func ExtractSaaSTXTFootprint(results map[string]any) map[string]any {
	result := map[string]any{
		"status":        "success",
		"services":      []map[string]any{},
		"service_count": 0,
		"issues":        []string{},
		"message":       "No SaaS verification records detected",
	}

	basic, ok := results["basic_records"].(map[string]any)
	if !ok {
		return result
	}

	txtRecords, _ := basic["TXT"].([]string)
	if len(txtRecords) == 0 {
		return result
	}

	seen := make(map[string]bool)
	var services []map[string]any

	for _, txt := range txtRecords {
		cleaned := strings.Trim(txt, "\"")
		matchSaaSPatterns(cleaned, seen, &services)
	}

	if len(services) > 0 {
		result["services"] = services
		result["service_count"] = len(services)
		result["message"] = fmt.Sprintf("Detected %d SaaS verification record%s", len(services), pluralSuffix(len(services)))
	}

	return result
}

func matchSaaSPatterns(txt string, seen map[string]bool, services *[]map[string]any) {
	for _, sp := range saasPatterns {
		if sp.Pattern.MatchString(txt) && !seen[sp.Name] {
			seen[sp.Name] = true
			*services = append(*services, map[string]any{
				"name":   sp.Name,
				"record": truncateRecord(txt, 120),
			})
			return
		}
	}
}

func truncateRecord(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
