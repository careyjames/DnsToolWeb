// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
// Tests for this package are maintained in the private repository.
// See github.com/careyjames/dnstool-intel for the full test suite.
package analyzer

import (
        "os"
        "path/filepath"
        "strings"
        "testing"
)

const errExpectedGot = "expected %q, got %q"

func TestEmailAnswerNoMailDomain(t *testing.T) {
        ps := protocolState{isNoMailDomain: true}
        answer := buildEmailAnswer(ps, false, false)
        if answer != "No — null MX indicates no-mail domain" {
                t.Errorf("no-mail domain should return 'No — null MX indicates no-mail domain', got: %s", answer)
        }
}

func TestEmailAnswerRejectPolicy(t *testing.T) {
        ps := protocolState{dmarcPolicy: "reject"}
        answer := buildEmailAnswer(ps, true, true)
        expected := "No — SPF and DMARC reject policy enforced"
        if answer != expected {
                t.Errorf(errExpectedGot, expected, answer)
        }
}

func TestEmailAnswerNoProtection(t *testing.T) {
        ps := protocolState{}
        answer := buildEmailAnswer(ps, false, false)
        expected := "Yes — no SPF or DMARC protection"
        if answer != expected {
                t.Errorf(errExpectedGot, expected, answer)
        }
}

func TestEmailAnswerMonitorOnly(t *testing.T) {
        ps := protocolState{dmarcPolicy: "none"}
        answer := buildEmailAnswer(ps, true, true)
        expected := "Yes — DMARC is monitor-only (p=none)"
        if answer != expected {
                t.Errorf(errExpectedGot, expected, answer)
        }
}

func TestEmailAnswerQuarantineFull(t *testing.T) {
        ps := protocolState{dmarcPolicy: "quarantine", dmarcPct: 100}
        answer := buildEmailAnswer(ps, true, true)
        expected := "Unlikely — SPF and DMARC quarantine policy enforced"
        if answer != expected {
                t.Errorf(errExpectedGot, expected, answer)
        }
}

func TestEmailAnswerSPFOnly(t *testing.T) {
        ps := protocolState{}
        answer := buildEmailAnswer(ps, true, false)
        expected := "Likely — SPF alone cannot prevent spoofing"
        if answer != expected {
                t.Errorf(errExpectedGot, expected, answer)
        }
}

func TestGoldenRuleUSAGov(t *testing.T) {
        ps := protocolState{
                dmarcPolicy: "reject",
                dmarcPct:    100,
                dmarcHasRua: true,
                spfOK:       true,
        }

        answer := buildEmailAnswer(ps, true, true)
        if answer != "No — SPF and DMARC reject policy enforced" {
                t.Errorf("usa.gov-like domain (SPF+DMARC reject, no MX) should show 'No', got: %s", answer)
        }

        verdicts := buildVerdicts(ps, DKIMProviderInferred, true, true, true)
        emailAnswer, ok := verdicts["email_answer"].(string)
        if !ok || emailAnswer == "" {
                t.Error("verdicts must contain non-empty 'email_answer' string")
        }
}

func TestDMARCRuaDetection(t *testing.T) {
        dmarcWithRua := map[string]any{
                "status": "success",
                "policy": "reject",
                "pct":    100,
                "rua":    "mailto:dc1e127b@inbox.ondmarc.com",
        }
        _, _, _, _, _, hasRua := evaluateDMARCState(dmarcWithRua)
        if !hasRua {
                t.Error("DMARC record with rua= should set dmarcHasRua=true")
        }

        dmarcNoRua := map[string]any{
                "status": "success",
                "policy": "reject",
                "pct":    100,
                "rua":    "",
        }
        _, _, _, _, _, hasRuaEmpty := evaluateDMARCState(dmarcNoRua)
        if hasRuaEmpty {
                t.Error("DMARC record with empty rua should set dmarcHasRua=false")
        }

        dmarcNilRua := map[string]any{
                "status": "success",
                "policy": "reject",
                "pct":    100,
        }
        _, _, _, _, _, hasRuaNil := evaluateDMARCState(dmarcNilRua)
        if hasRuaNil {
                t.Error("DMARC record with no rua key should set dmarcHasRua=false")
        }
}

func TestGoldenRuleNoMXDomain(t *testing.T) {
        ps := protocolState{
                dmarcPolicy:    "reject",
                dmarcPct:       100,
                isNoMailDomain: true,
        }

        answer := buildEmailAnswer(ps, true, true)
        if answer != "No — null MX indicates no-mail domain" {
                t.Errorf("no-MX domain with null MX should show no-mail answer, got: %s", answer)
        }
}

func TestGoldenRuleEnterpriseProviderDetection(t *testing.T) {
        tests := []struct {
                name         string
                nsRecords    []string
                expectTier   string
                expectName   string
        }{
                {
                        name:       "Amazon Route 53",
                        nsRecords:  []string{"ns-1234.awsdns-56.org.", "ns-789.awsdns-12.co.uk."},
                        expectTier: tierEnterprise,
                        expectName: nameAmazonRoute53,
                },
                {
                        name:       "Cloudflare",
                        nsRecords:  []string{"ns1.cloudflare.com.", "ns2.cloudflare.com."},
                        expectTier: tierEnterprise,
                        expectName: nameCloudflare,
                },
                {
                        name:       "NS1",
                        nsRecords:  []string{"dns1.p03.nsone.net.", "dns2.p03.nsone.net."},
                        expectTier: tierEnterprise,
                        expectName: "NS1",
                },
                {
                        name:       "Google Cloud DNS",
                        nsRecords:  []string{"ns-cloud-a1.googledomains.com.", "ns-cloud-a2.googledomains.com."},
                        expectTier: tierEnterprise,
                        expectName: "Google Cloud DNS",
                },
                {
                        name:       "Azure DNS",
                        nsRecords:  []string{"ns1-01.azure-dns.com.", "ns2-01.azure-dns.net."},
                        expectTier: tierEnterprise,
                        expectName: "Azure DNS",
                },
                {
                        name:       "Akamai Edge DNS",
                        nsRecords:  []string{"a1-123.akam.net.", "a2-456.akam.net."},
                        expectTier: tierEnterprise,
                        expectName: "Akamai Edge DNS",
                },
                {
                        name:       "UltraDNS",
                        nsRecords:  []string{"pdns1.ultradns.net.", "pdns2.ultradns.net."},
                        expectTier: tierEnterprise,
                        expectName: "UltraDNS",
                },
                {
                        name:       "Oracle Dyn",
                        nsRecords:  []string{"ns1.p01.dynect.net.", "ns2.p01.dynect.net."},
                        expectTier: tierEnterprise,
                        expectName: "Oracle Dyn",
                },
                {
                        name:       "CSC Global DNS",
                        nsRecords:  []string{"ns1.cscglobal.com.", "ns2.cscglobal.com."},
                        expectTier: tierEnterprise,
                        expectName: nameCSCGlobalDNS,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        im := matchEnterpriseProvider(tt.nsRecords)
                        if im == nil {
                                t.Fatalf("matchEnterpriseProvider returned nil for %s NS records %v", tt.name, tt.nsRecords)
                        }
                        if im.tier != tt.expectTier {
                                t.Errorf(errExpectedGot, tt.expectTier, im.tier)
                        }
                        if im.provider == nil {
                                t.Fatal("matched provider is nil")
                        }
                        if im.provider.Name != tt.expectName {
                                t.Errorf(errExpectedGot, tt.expectName, im.provider.Name)
                        }
                        if len(im.provider.Features) == 0 {
                                t.Error("enterprise provider must have at least one feature")
                        }
                })
        }
}

func TestGoldenRuleGoDaddyIsEnterprise(t *testing.T) {
        tests := []struct {
                name      string
                nsRecords []string
        }{
                {"domaincontrol pattern", []string{"ns51.domaincontrol.com.", "ns52.domaincontrol.com."}},
                {"godaddy pattern", []string{"ns1.godaddy.com.", "ns2.godaddy.com."}},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        im := matchEnterpriseProvider(tt.nsRecords)
                        if im == nil {
                                t.Fatalf("GoDaddy NS %v should match enterprise", tt.nsRecords)
                        }
                        if im.provider.Name != "GoDaddy" {
                                t.Errorf(errExpectedGot, "GoDaddy", im.provider.Name)
                        }
                })
        }
}

func TestGoldenRuleUnknownProviderNotEnterprise(t *testing.T) {
        standardNS := []string{"ns1.obscurehost.example.", "ns2.obscurehost.example."}
        im := matchEnterpriseProvider(standardNS)
        if im != nil {
                t.Errorf("unknown NS should not match enterprise, got: %s", im.provider.Name)
        }
}

func TestGoldenRuleLegacyProvidersNeverEnterprise(t *testing.T) {
        tests := []struct {
                name      string
                nsRecords []string
        }{
                {"Network Solutions", []string{"ns1.worldnic.com.", "ns2.worldnic.com."}},
                {"Network Solutions alt", []string{"ns53.networksolutions.com.", "ns54.networksolutions.com."}},
                {"Bluehost", []string{"ns1.bluehost.com.", "ns2.bluehost.com."}},
                {"HostGator", []string{"ns1.hostgator.com.", "ns2.hostgator.com."}},
                {"iPage", []string{"ns1.ipage.com.", "ns2.ipage.com."}},
                {"FatCow", []string{"ns1.fatcow.com.", "ns2.fatcow.com."}},
                {"JustHost", []string{"ns1.justhost.com.", "ns2.justhost.com."}},
                {"HostMonster", []string{"ns1.hostmonster.com.", "ns2.hostmonster.com."}},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        im := matchEnterpriseProvider(tt.nsRecords)
                        if im != nil {
                                t.Errorf("%s should NEVER be tagged as enterprise, got: %s", tt.name, im.provider.Name)
                        }
                })
        }
}

func TestGoldenRuleLegacyBlocklistNotEmpty(t *testing.T) {
        if len(legacyProviderBlocklist) == 0 {
                t.Fatal("legacyProviderBlocklist must not be empty — legacy providers would slip through as enterprise")
        }
        required := []string{"networksolutions", "worldnic", "bluehost", "hostgator"}
        for _, pattern := range required {
                if !legacyProviderBlocklist[pattern] {
                        t.Errorf("legacyProviderBlocklist missing required pattern %q", pattern)
                }
        }
}

func TestGoldenRuleNoOverlapBlocklistAndEnterprise(t *testing.T) {
        for pattern := range legacyProviderBlocklist {
                if _, ok := enterpriseProviders[pattern]; ok {
                        t.Errorf("pattern %q appears in BOTH enterpriseProviders and legacyProviderBlocklist — this is a conflict", pattern)
                }
        }
}

func TestGoldenRuleAnalyzeDNSInfrastructureEnterprise(t *testing.T) {
        a := &Analyzer{}
        results := map[string]any{
                "basic_records": map[string]any{
                        "NS": []string{"ns-1234.awsdns-56.org.", "ns-789.awsdns-12.co.uk."},
                },
                "dnssec": map[string]any{
                        "status": "unsigned",
                },
        }

        infra := a.AnalyzeDNSInfrastructure("example.com", results)

        tier, _ := infra["provider_tier"].(string)
        if tier != tierEnterprise {
                t.Errorf("Route 53 domain should have enterprise tier, got: %s", tier)
        }

        provider, _ := infra["provider"].(string)
        if provider != nameAmazonRoute53 {
                t.Errorf(errExpectedGot, nameAmazonRoute53, provider)
        }

        assessment, _ := infra["assessment"].(string)
        if assessment != "Enterprise-grade DNS infrastructure" {
                t.Errorf(errExpectedGot, "Enterprise-grade DNS infrastructure", assessment)
        }

        explainsDNSSEC, _ := infra["explains_no_dnssec"].(bool)
        if !explainsDNSSEC {
                t.Error("enterprise provider with unsigned DNSSEC should set explains_no_dnssec=true")
        }
}

func TestGoldenRuleAnalyzeDNSInfrastructureStandard(t *testing.T) {
        a := &Analyzer{}
        results := map[string]any{
                "basic_records": map[string]any{
                        "NS": []string{"ns1.smallhost.com.", "ns2.smallhost.com."},
                },
        }

        infra := a.AnalyzeDNSInfrastructure("smallsite.com", results)

        tier, _ := infra["provider_tier"].(string)
        if tier != "standard" {
                t.Errorf("unknown NS should have standard tier, got: %s", tier)
        }
}

func TestGoldenRuleRemediationNotStubbed(t *testing.T) {
        a := &Analyzer{}
        results := map[string]any{
                "domain": "stub-test.example.com",
                "spf_analysis": map[string]any{
                        "status": "not_found",
                },
                "dmarc_analysis": map[string]any{
                        "status": "not_found",
                },
                "dkim_analysis": map[string]any{
                        "status": "info",
                },
                "mta_sts_analysis": map[string]any{
                        "status": "not_found",
                },
                "tlsrpt_analysis": map[string]any{
                        "status": "not_found",
                },
                "bimi_analysis": map[string]any{
                        "status": "not_found",
                },
                "dane_analysis": map[string]any{
                        "status": "not_found",
                },
                "caa_analysis": map[string]any{
                        "status": "not_found",
                },
                "dnssec_analysis": map[string]any{
                        "status": "unsigned",
                },
                "basic_records": map[string]any{
                        "MX": []string{"mx.example.com."},
                },
        }

        remediation := a.GenerateRemediation(results)

        topFixes, _ := remediation["top_fixes"].([]map[string]any)
        allFixes, _ := remediation["all_fixes"].([]map[string]any)
        fixCount, _ := remediation["fix_count"].(float64)

        if len(topFixes) == 0 {
                t.Fatal("GenerateRemediation must produce non-empty top_fixes for a domain missing SPF, DMARC, DKIM — remediation engine is stubbed")
        }
        if len(allFixes) == 0 {
                t.Fatal("GenerateRemediation must produce non-empty all_fixes — remediation engine is stubbed")
        }
        if fixCount == 0 {
                t.Fatal("GenerateRemediation must produce non-zero fix_count — remediation engine is stubbed")
        }

        firstFix := topFixes[0]
        requiredKeys := []string{"title", "fix", "severity_label", "severity_color"}
        for _, key := range requiredKeys {
                val, ok := firstFix[key].(string)
                if !ok || val == "" {
                        t.Errorf("top fix must have non-empty %q field", key)
                }
        }
}

func TestGoldenRuleRemediationWellConfiguredDomain(t *testing.T) {
        a := &Analyzer{}
        results := map[string]any{
                "domain": "secure.example.com",
                "spf_analysis": map[string]any{
                        "status":    "success",
                        "qualifier": "-all",
                },
                "dmarc_analysis": map[string]any{
                        "status": "success",
                        "policy": "reject",
                        "pct":    100,
                        "rua":    "mailto:dmarc@example.com",
                },
                "dkim_analysis": map[string]any{
                        "status": "success",
                },
                "mta_sts_analysis": map[string]any{
                        "status": "success",
                },
                "tlsrpt_analysis": map[string]any{
                        "status": "success",
                },
                "bimi_analysis": map[string]any{
                        "status": "success",
                },
                "dane_analysis": map[string]any{
                        "status": "success",
                },
                "caa_analysis": map[string]any{
                        "status": "success",
                },
                "dnssec_analysis": map[string]any{
                        "status": "secure",
                },
                "basic_records": map[string]any{
                        "MX": []string{"mx.example.com."},
                },
        }

        remediation := a.GenerateRemediation(results)

        allFixes, _ := remediation["all_fixes"].([]map[string]any)
        topFixes, _ := remediation["top_fixes"].([]map[string]any)

        if len(allFixes) > 3 {
                t.Errorf("well-configured domain should have very few fixes (at most 3), got %d", len(allFixes))
        }
        if len(topFixes) > 3 {
                t.Errorf("top_fixes should never exceed 3 items, got %d", len(topFixes))
        }
}

func TestGoldenRuleRemediationProviderAware(t *testing.T) {
        daneResult := providerSupportsDANE("")
        if !daneResult {
                t.Fatal("providerSupportsDANE must return true for empty/unknown provider — benefit of the doubt")
        }
        bimiResult := providerSupportsBIMI("")
        if !bimiResult {
                t.Fatal("providerSupportsBIMI must return true for empty/unknown provider — benefit of the doubt")
        }

        a := &Analyzer{}
        results := map[string]any{
                "domain": "example.com",
                "spf_analysis": map[string]any{
                        "status":        "success",
                        "record":        "v=spf1 include:_spf.google.com ~all",
                        "all_mechanism": "~all",
                },
                "dmarc_analysis": map[string]any{
                        "status": "success",
                        "policy": "reject",
                        "pct":    100,
                        "rua":    "mailto:dmarc@example.com",
                },
                "dkim_analysis": map[string]any{
                        "status":           "success",
                        "has_dkim":         true,
                        "primary_provider": "Self-hosted",
                },
                "mta_sts_analysis": map[string]any{
                        "status": "success",
                },
                "tlsrpt_analysis": map[string]any{
                        "status": "success",
                },
                "bimi_analysis": map[string]any{
                        "status": "success",
                },
                "dane_analysis": map[string]any{
                        "status":   "info",
                        "has_dane": false,
                },
                "dnssec_analysis": map[string]any{
                        "status": "success",
                },
                "caa_analysis": map[string]any{
                        "status": "success",
                },
                "basic_records": map[string]any{
                        "MX": []string{"mail.example.com."},
                },
        }

        remediation := a.GenerateRemediation(results)
        allFixes, _ := remediation["all_fixes"].([]map[string]any)

        for _, f := range allFixes {
                title, _ := f["title"].(string)
                if strings.Contains(title, "Upgrading SPF to -all") {
                        t.Fatalf("Remediation must never suggest upgrading from ~all to -all — ~all is best practice with DMARC reject. Got: %q", title)
                }
        }
}

func TestGoldenRuleMailPostureNotStubbed(t *testing.T) {
        results := map[string]any{
                "domain": "test.example.com",
                "spf_analysis": map[string]any{
                        "status": "not_found",
                },
                "dmarc_analysis": map[string]any{
                        "status": "not_found",
                },
                "dkim_analysis": map[string]any{
                        "status": "info",
                },
                "mta_sts_analysis": map[string]any{
                        "status": "not_found",
                },
                "tlsrpt_analysis": map[string]any{
                        "status": "not_found",
                },
                "basic_records": map[string]any{
                        "MX": []string{"mx.example.com."},
                },
        }

        mp := buildMailPosture(results)

        classification, _ := mp["classification"].(string)
        label, _ := mp["label"].(string)
        color, _ := mp["color"].(string)

        if classification == "" {
                t.Fatal("buildMailPosture must return non-empty classification — mail posture engine is stubbed")
        }
        if label == "" {
                t.Fatal("buildMailPosture must return non-empty label — mail posture engine is stubbed")
        }
        if color == "" {
                t.Fatal("buildMailPosture must return non-empty color — mail posture engine is stubbed")
        }
}

func TestGoldenRuleFixToMapNotEmpty(t *testing.T) {
        f := fix{
                Title:         "Test Fix",
                Description:   "Test description",
                Severity:      severityCritical,
                SeverityColor: colorCritical,
                SeverityOrder: 1,
                RFC:           "RFC 7489",
                RFCURL:        "https://example.com",
                Section:       "SPF",
        }

        m := fixToMap(f)

        if len(m) == 0 {
                t.Fatal("fixToMap must return non-empty map — function is stubbed")
        }
        if m["title"] != "Test Fix" {
                t.Errorf("fixToMap must preserve title, got %v", m["title"])
        }
        if m["severity_label"] != severityCritical {
                t.Errorf("fixToMap must preserve severity_label, got %v", m["severity_label"])
        }
}

func TestGoldenRuleStubRegistryComplete(t *testing.T) {
        knownStubFiles := map[string]bool{
                "ai_surface/http.go":       true,
                "ai_surface/llms_txt.go":   true,
                "ai_surface/poisoning.go":  true,
                "ai_surface/robots_txt.go": true,
                "commands.go":              true,
                "confidence.go":            true,
                "dkim_state.go":            true,
                "edge_cdn.go":              true,
                "infrastructure.go":        true,
                "ip_investigation.go":      true,
                "manifest.go":              true,
                "providers.go":             true,
                "saas_txt.go":              true,
        }

        analyzerDir := "."
        stubMarker := "stub implementations"

        err := filepath.Walk(analyzerDir, func(path string, info os.FileInfo, err error) error {
                if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
                        return nil
                }
                data, readErr := os.ReadFile(path)
                if readErr != nil {
                        return nil
                }
                firstLines := string(data)
                if len(firstLines) > 500 {
                        firstLines = firstLines[:500]
                }
                if strings.Contains(strings.ToLower(firstLines), stubMarker) {
                        rel := path
                        if !knownStubFiles[rel] {
                                t.Errorf("UNREGISTERED stub file detected: %s — add to knownStubFiles or implement it", rel)
                        }
                }
                return nil
        })
        if err != nil {
                t.Fatalf("failed to walk analyzer directory: %v", err)
        }

        t.Logf("Stub registry: %d files are known stubs from dnstool-intel private repo", len(knownStubFiles))
}

func TestGoldenRuleNoProviderIntelligenceInPublicFiles(t *testing.T) {
        knownStubFiles := map[string]bool{
                "ai_surface/http.go":       true,
                "ai_surface/llms_txt.go":   true,
                "ai_surface/poisoning.go":  true,
                "ai_surface/robots_txt.go": true,
                "commands.go":              true,
                "confidence.go":            true,
                "dkim_state.go":            true,
                "edge_cdn.go":              true,
                "infrastructure.go":        true,
                "ip_investigation.go":      true,
                "manifest.go":              true,
                "providers.go":             true,
                "saas_txt.go":              true,
        }

        forbiddenPairPatterns := []string{
                `"google", "microsoft"`,
                `"google", "yahoo"`,
                `"microsoft", "yahoo"`,
                `"yahoo", "zoho"`,
                `"zoho", "fastmail"`,
                `"fastmail", "proofpoint"`,
                `"proofpoint", "mimecast"`,
                `"mimecast", "barracuda"`,
                `"barracuda", "rackspace"`,
                `"amazon ses", "sendgrid"`,
                `"sendgrid", "mailgun"`,
                `"mailgun", "postmark"`,
                `"postmark", "sparkpost"`,
                `"sparkpost", "mailchimp"`,
                `"mailchimp", "constant contact"`,
                `"google", "yahoo", "fastmail", "apple"`,
        }

        capabilityProviderNames := []string{
                "mimecast", "barracuda", "rackspace", "sparkpost",
                "constant contact", "amazon ses",
        }

        err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
                if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
                        return nil
                }
                if knownStubFiles[path] {
                        return nil
                }
                data, readErr := os.ReadFile(path)
                if readErr != nil {
                        return nil
                }
                content := string(data)
                lower := strings.ToLower(content)

                for _, pattern := range forbiddenPairPatterns {
                        if strings.Contains(lower, pattern) {
                                t.Errorf("LEAKED PROVIDER INTELLIGENCE in %s: found pattern %q — provider capability lists belong in dnstool-intel stubs only", path, pattern)
                        }
                }

                if path == "remediation.go" || path == "posture.go" || path == "scoring.go" {
                        for _, name := range capabilityProviderNames {
                                if strings.Contains(lower, `"`+name+`"`) {
                                        t.Errorf("LEAKED PROVIDER NAME in %s: found %q — provider capability data belongs in dnstool-intel stubs only", path, name)
                                }
                        }
                }

                return nil
        })
        if err != nil {
                t.Fatalf("failed to walk analyzer directory: %v", err)
        }
}

func TestGoldenRuleRemediationDelegatesProviderLogic(t *testing.T) {
        data, err := os.ReadFile("remediation.go")
        if err != nil {
                t.Fatalf("cannot read remediation.go: %v", err)
        }
        content := string(data)

        if !strings.Contains(content, "isHostedEmailProvider(") {
                t.Fatal("remediation.go must delegate DANE provider checks to isHostedEmailProvider() — do not inline provider lists")
        }
        if !strings.Contains(content, "isBIMICapableProvider(") {
                t.Fatal("remediation.go must delegate BIMI provider checks to isBIMICapableProvider() — do not inline provider lists")
        }

        forbiddenInRemediation := []string{
                `[]string{`,
                `map[string]bool{`,
                `map[string]string{`,
        }
        lines := strings.Split(content, "\n")
        inDANEFunc := false
        inBIMIFunc := false
        for _, line := range lines {
                trimmed := strings.TrimSpace(line)
                if strings.HasPrefix(trimmed, "func providerSupportsDANE") {
                        inDANEFunc = true
                }
                if strings.HasPrefix(trimmed, "func providerSupportsBIMI") {
                        inBIMIFunc = true
                }
                if (inDANEFunc || inBIMIFunc) && strings.HasPrefix(trimmed, "}") && !strings.Contains(trimmed, "{") {
                        inDANEFunc = false
                        inBIMIFunc = false
                }
                if inDANEFunc || inBIMIFunc {
                        for _, forbidden := range forbiddenInRemediation {
                                if strings.Contains(trimmed, forbidden) {
                                        t.Errorf("providerSupportsDANE/BIMI in remediation.go contains inline collection %q — delegate to providers.go stub instead", forbidden)
                                }
                        }
                }
        }
}

func TestGoldenRuleStubBoundaryFunctionsRegistered(t *testing.T) {
        knownBoundaryFunctions := []string{
                "func isHostedEmailProvider(",
                "func isBIMICapableProvider(",
                "func isKnownDKIMProvider(",
        }

        knownStubFiles := map[string]bool{
                "ai_surface/http.go":       true,
                "ai_surface/llms_txt.go":   true,
                "ai_surface/poisoning.go":  true,
                "ai_surface/robots_txt.go": true,
                "commands.go":              true,
                "confidence.go":            true,
                "dkim_state.go":            true,
                "edge_cdn.go":              true,
                "infrastructure.go":        true,
                "ip_investigation.go":      true,
                "manifest.go":              true,
                "providers.go":             true,
                "saas_txt.go":              true,
        }

        providerFuncPattern := "func is"
        providerFuncSuffix := "Provider("

        err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
                if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
                        return nil
                }
                if knownStubFiles[path] {
                        return nil
                }
                data, readErr := os.ReadFile(path)
                if readErr != nil {
                        return nil
                }
                content := string(data)

                for _, fn := range knownBoundaryFunctions {
                        if strings.Contains(content, fn) {
                                t.Errorf("BOUNDARY FUNCTION %s found in non-stub file %s — intelligence boundary functions must only be defined in stub files (providers.go)", fn, path)
                        }
                }

                for _, line := range strings.Split(content, "\n") {
                        trimmed := strings.TrimSpace(line)
                        if strings.HasPrefix(trimmed, providerFuncPattern) && strings.Contains(trimmed, providerFuncSuffix) {
                                t.Errorf("UNREGISTERED PROVIDER FUNCTION in non-stub file %s: %q — provider capability functions must be defined in stub files only", path, trimmed)
                        }
                }

                return nil
        })
        if err != nil {
                t.Fatalf("failed to walk analyzer directory: %v", err)
        }

        stubData, err := os.ReadFile("providers.go")
        if err != nil {
                t.Fatalf("cannot read providers.go: %v", err)
        }
        stubContent := string(stubData)
        for _, fn := range knownBoundaryFunctions {
                if !strings.Contains(stubContent, fn) {
                        t.Errorf("providers.go missing boundary function %s — stub must define all intelligence boundary functions", fn)
                }
        }
}

func TestGoldenRuleEnterpriseProvidersMapNotEmpty(t *testing.T) {
        if len(enterpriseProviders) == 0 {
                t.Fatal("enterpriseProviders map must not be empty — enterprise detection will silently fail")
        }
        requiredPatterns := []string{"awsdns", "cloudflare", "nsone", "azure-dns", "ultradns", "dynect", "akamai", "google", "cscglobal", "domaincontrol", "godaddy", "registrar-servers", "dns.he.net", "digitalocean", "hetzner", "vultr", "dnsimple", "netlify", "vercel"}
        for _, pattern := range requiredPatterns {
                if _, ok := enterpriseProviders[pattern]; !ok {
                        t.Errorf("enterpriseProviders missing required pattern %q", pattern)
                }
        }
}
