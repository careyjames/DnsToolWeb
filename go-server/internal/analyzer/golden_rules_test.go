// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Tests for this package are maintained in the private repository.
// See github.com/careyjames/dnstool-intel for the full test suite.
package analyzer

import (
        "context"
        "os"
        "path/filepath"
        "strings"
        "testing"
        "time"
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

        brandVerdict, ok := verdicts["brand_impersonation"].(map[string]any)
        if !ok {
                t.Fatal("verdicts must contain brand_impersonation map")
        }
        brandAnswer, _ := brandVerdict["answer"].(string)
        if brandAnswer == "No" {
                t.Errorf("usa.gov-like domain (DMARC reject, no BIMI, no CAA) brand verdict should NOT be 'No', got: %s — BIMI and CAA gaps must be reflected", brandAnswer)
        }
        if brandAnswer != "Unlikely" {
                t.Errorf("usa.gov-like domain (DMARC reject, no BIMI, no CAA) brand verdict should be 'Unlikely', got: %s", brandAnswer)
        }
}

func TestBrandVerdictFullProtection(t *testing.T) {
        ps := protocolState{
                dmarcPolicy: "reject",
                bimiOK:      true,
                caaOK:       true,
        }
        verdicts := make(map[string]any)
        buildBrandVerdict(ps, verdicts)
        brand := verdicts["brand_impersonation"].(map[string]any)
        if brand["answer"] != "No" {
                t.Errorf("DMARC reject + BIMI + CAA should be 'No', got: %s", brand["answer"])
        }
}

func TestBrandVerdictPartialGaps(t *testing.T) {
        ps := protocolState{
                dmarcPolicy: "reject",
                bimiOK:      true,
                caaOK:       false,
        }
        verdicts := make(map[string]any)
        buildBrandVerdict(ps, verdicts)
        brand := verdicts["brand_impersonation"].(map[string]any)
        if brand["answer"] != "Unlikely" {
                t.Errorf("DMARC reject + BIMI - CAA should be 'Unlikely', got: %s", brand["answer"])
        }
        if brand["label"] != "Mostly Protected" {
                t.Errorf("expected 'Mostly Protected', got: %s", brand["label"])
        }
}

func TestProbableNoMailDetection(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{},
        }
        if !detectProbableNoMail(results) {
                t.Error("domain with no MX in basic_records should be detected as probable no-mail")
        }

        resultsWithMX := map[string]any{
                "basic_records": map[string]any{
                        "MX": []string{"10 mail.example.com."},
                },
        }
        if detectProbableNoMail(resultsWithMX) {
                t.Error("domain with MX records should NOT be detected as probable no-mail")
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

func TestGoldenRuleHostedProviderNoDANE(t *testing.T) {
        a := &Analyzer{}
        hostedResults := map[string]any{
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
                        "primary_provider": "Google Workspace",
                },
                "mta_sts_analysis": map[string]any{
                        "status": "success",
                },
                "tlsrpt_analysis": map[string]any{
                        "status": "success",
                },
                "bimi_analysis": map[string]any{
                        "status":   "info",
                        "has_bimi": false,
                },
                "dane_analysis": map[string]any{
                        "status":   "info",
                        "has_dane": false,
                },
                "dnssec_analysis": map[string]any{
                        "status": "secure",
                },
                "caa_analysis": map[string]any{
                        "status": "success",
                },
                "basic_records": map[string]any{
                        "MX": []string{"aspmx.l.google.com."},
                },
        }

        remediation := a.GenerateRemediation(hostedResults)
        allFixes, _ := remediation["all_fixes"].([]map[string]any)

        for _, f := range allFixes {
                title, _ := f["title"].(string)
                if strings.Contains(title, "DANE") || strings.Contains(title, "TLSA") {
                        t.Fatalf("Remediation must NOT recommend DANE/TLSA for hosted email providers (Google Workspace) — they don't support inbound DANE. Got: %q", title)
                }
        }

        if !isHostedEmailProvider("Google Workspace") {
                t.Fatal("isHostedEmailProvider must return true for 'Google Workspace' — it is a hosted provider that cannot deploy inbound DANE")
        }

        hostedProviders := []string{"Google Workspace", "Microsoft 365", "Zoho Mail"}
        for _, p := range hostedProviders {
                if providerSupportsDANE(p) {
                        t.Fatalf("providerSupportsDANE must return false for hosted provider %q — hosted providers cannot deploy inbound DANE", p)
                }
        }
}

func TestGoldenRuleBIMIRecommendedRegardlessOfProvider(t *testing.T) {
        providers := []string{"Google Workspace", "Microsoft 365", "Zoho Mail", "Fastmail", "ProtonMail", "Self-hosted"}
        for _, provider := range providers {
                t.Run(provider, func(t *testing.T) {
                        a := &Analyzer{}
                        results := map[string]any{
                                "domain": "example.com",
                                "spf_analysis": map[string]any{
                                        "status":        "success",
                                        "record":        "v=spf1 include:example.com ~all",
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
                                        "primary_provider": provider,
                                },
                                "mta_sts_analysis": map[string]any{
                                        "status": "success",
                                },
                                "tlsrpt_analysis": map[string]any{
                                        "status": "success",
                                },
                                "bimi_analysis": map[string]any{
                                        "status":   "info",
                                        "has_bimi": false,
                                },
                                "dane_analysis": map[string]any{
                                        "status":   "info",
                                        "has_dane": false,
                                },
                                "dnssec_analysis": map[string]any{
                                        "status": "secure",
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

                        foundBIMI := false
                        for _, f := range allFixes {
                                title, _ := f["title"].(string)
                                if strings.Contains(title, "BIMI") {
                                        foundBIMI = true
                                }
                        }
                        if !foundBIMI {
                                t.Fatalf("BIMI must be recommended for any provider with DMARC reject — BIMI is receiver-side (Gmail, Apple Mail, Yahoo verify it), sending provider %q is irrelevant", provider)
                        }
                })
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
                "ai_surface/http.go":           true,
                "ai_surface/http_oss.go":       true,
                "ai_surface/llms_txt.go":       true,
                "ai_surface/llms_txt_oss.go":   true,
                "ai_surface/poisoning.go":      true,
                "ai_surface/poisoning_oss.go":  true,
                "ai_surface/robots_txt.go":     true,
                "ai_surface/robots_txt_oss.go": true,
                "confidence.go":                true,
                "dkim_state.go":                true,
                "edge_cdn_oss.go":              true,
                "infrastructure.go":            true,
                "infrastructure_oss.go":        true,
                "ip_investigation.go":          true,
                "ip_investigation_oss.go":      true,
                "manifest.go":                  true,
                "manifest_oss.go":              true,
                "providers.go":                 true,
                "providers_oss.go":             true,
                "saas_txt_oss.go":              true,
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
                "ai_surface/http.go":           true,
                "ai_surface/http_oss.go":       true,
                "ai_surface/llms_txt.go":       true,
                "ai_surface/llms_txt_oss.go":   true,
                "ai_surface/poisoning.go":      true,
                "ai_surface/poisoning_oss.go":  true,
                "ai_surface/robots_txt.go":     true,
                "ai_surface/robots_txt_oss.go": true,
                "confidence.go":                true,
                "dkim_state.go":                true,
                "edge_cdn_oss.go":              true,
                "infrastructure.go":            true,
                "infrastructure_oss.go":        true,
                "ip_investigation.go":          true,
                "ip_investigation_oss.go":      true,
                "manifest.go":                  true,
                "manifest_oss.go":              true,
                "providers.go":                 true,
                "providers_oss.go":             true,
                "saas_txt_oss.go":              true,
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
                "ai_surface/http.go":           true,
                "ai_surface/http_oss.go":       true,
                "ai_surface/llms_txt.go":       true,
                "ai_surface/llms_txt_oss.go":   true,
                "ai_surface/poisoning.go":      true,
                "ai_surface/poisoning_oss.go":  true,
                "ai_surface/robots_txt.go":     true,
                "ai_surface/robots_txt_oss.go": true,
                "confidence.go":                true,
                "dkim_state.go":                true,
                "edge_cdn_oss.go":              true,
                "infrastructure.go":            true,
                "infrastructure_oss.go":        true,
                "ip_investigation.go":          true,
                "ip_investigation_oss.go":      true,
                "manifest.go":                  true,
                "manifest_oss.go":              true,
                "providers.go":                 true,
                "providers_oss.go":             true,
                "saas_txt_oss.go":              true,
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

        stubFiles := []string{"providers.go", "providers_oss.go"}
        var combinedStub strings.Builder
        for _, sf := range stubFiles {
                data, err := os.ReadFile(sf)
                if err != nil {
                        continue
                }
                combinedStub.Write(data)
                combinedStub.WriteByte('\n')
        }
        stubContent := combinedStub.String()
        for _, fn := range knownBoundaryFunctions {
                if !strings.Contains(stubContent, fn) {
                        t.Errorf("providers boundary missing function %s — stub must define all intelligence boundary functions", fn)
                }
        }
}

func TestGoldenRuleWildcardCTDetection(t *testing.T) {
        entries := []ctEntry{
                {NameValue: "*.example.com\nexample.com", NotBefore: "2025-01-01", NotAfter: "2027-01-01", IssuerName: "C=US, O=Let's Encrypt, CN=E6"},
                {NameValue: "*.example.com\nexample.com", NotBefore: "2024-06-01", NotAfter: "2024-12-01", IssuerName: "C=US, O=Google Trust Services, CN=AE1"},
        }

        wc := detectWildcardCerts(entries, "example.com")
        if wc == nil {
                t.Fatal("wildcard certs must be detected when CT entries contain *.domain")
        }
        if !wc["present"].(bool) {
                t.Error("wildcard_certs.present must be true")
        }
        if wc["pattern"].(string) != "*.example.com" {
                t.Errorf("wildcard pattern must be *.example.com, got %s", wc["pattern"])
        }
        if !wc["current"].(bool) {
                t.Error("wildcard_certs.current must be true when at least one cert is not expired")
        }

        subdomainSet := make(map[string]map[string]any)
        processCTEntries(entries, "example.com", subdomainSet)
        if len(subdomainSet) != 0 {
                t.Errorf("wildcard-only CT entries must produce 0 explicit subdomains, got %d", len(subdomainSet))
        }
}

func TestGoldenRuleWildcardNotFalsePositive(t *testing.T) {
        entries := []ctEntry{
                {NameValue: "mail.example.com", NotBefore: "2025-01-01", NotAfter: "2026-01-01", IssuerName: "CN=E6"},
                {NameValue: "www.example.com", NotBefore: "2025-01-01", NotAfter: "2026-01-01", IssuerName: "CN=E6"},
        }

        wc := detectWildcardCerts(entries, "example.com")
        if wc != nil {
                t.Error("wildcard detection must not fire when no wildcard entries exist")
        }

        subdomainSet := make(map[string]map[string]any)
        processCTEntries(entries, "example.com", subdomainSet)
        if len(subdomainSet) != 2 {
                t.Errorf("expected 2 explicit subdomains, got %d", len(subdomainSet))
        }
        if _, ok := subdomainSet["mail.example.com"]; !ok {
                t.Error("mail.example.com must be in subdomainSet")
        }
        if _, ok := subdomainSet["www.example.com"]; !ok {
                t.Error("www.example.com must be in subdomainSet")
        }
}

func TestGoldenRuleSubdomainDiscoveryUnder60s(t *testing.T) {
        if os.Getenv("CI") != "" {
                t.Skip("skipping network-dependent test in CI")
        }

        a := New()
        ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
        defer cancel()

        start := time.Now()
        result := a.DiscoverSubdomains(ctx, "it-help.tech")
        elapsed := time.Since(start)

        if elapsed >= 60*time.Second {
                t.Fatalf("subdomain discovery took %s — must complete under 60 seconds", elapsed)
        }

        status, _ := result["status"].(string)
        if status != "success" {
                t.Errorf("subdomain discovery status must be 'success', got %q", status)
        }

        subs, _ := result["subdomains"].([]map[string]any)
        if len(subs) == 0 {
                t.Fatal("subdomain discovery must find at least one subdomain for it-help.tech")
        }

        found := make(map[string]bool)
        for _, sd := range subs {
                if name, ok := sd["name"].(string); ok {
                        found[name] = true
                }
        }

        required := []string{"dnstool.it-help.tech", "www.it-help.tech"}
        for _, req := range required {
                if !found[req] {
                        t.Errorf("subdomain discovery must find %q — not found in %d results", req, len(subs))
                }
        }

        t.Logf("subdomain discovery completed in %s — found %d subdomains", elapsed, len(subs))
}

func TestGoldenRuleSPFAncillaryCorroboration(t *testing.T) {
        tests := []struct {
                name            string
                mx              []string
                spf             string
                wantProvider    string
                wantAncillary   bool
        }{
                {
                        name:         "Google MX + Google SPF = Google Workspace",
                        mx:           []string{"aspmx.l.google.com."},
                        spf:          "v=spf1 include:_spf.google.com ~all",
                        wantProvider: providerGoogleWS,
                },
                {
                        name:          "O365 MX + Google-only SPF = Microsoft 365 with ancillary note",
                        mx:            []string{"example-com.mail.protection.outlook.com."},
                        spf:           "v=spf1 include:_spf.google.com ~all",
                        wantProvider:  providerMicrosoft365,
                        wantAncillary: true,
                },
                {
                        name:          "Self-hosted MX + Google SPF = self-hosted with ancillary note",
                        mx:            []string{"mail.example.com."},
                        spf:           "v=spf1 include:_spf.google.com ~all",
                        wantProvider:  "Self-hosted",
                        wantAncillary: true,
                },
                {
                        name:         "No MX + Google SPF = Google Workspace (no MX to contradict)",
                        mx:           []string{},
                        spf:          "v=spf1 include:_spf.google.com ~all",
                        wantProvider: providerGoogleWS,
                },
                {
                        name:         "Google MX + no SPF = Google Workspace from MX only",
                        mx:           []string{"aspmx.l.google.com."},
                        spf:          "",
                        wantProvider: providerGoogleWS,
                },
                {
                        name:         "Proofpoint gateway + Google SPF = Google behind gateway",
                        mx:           []string{"mx01.example.pphosted.com."},
                        spf:          "v=spf1 include:_spf.google.com ~all",
                        wantProvider: providerGoogleWS,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        result := detectPrimaryMailProvider(tt.mx, tt.spf)
                        provider := result.Primary
                        note := result.SPFAncillaryNote

                        if provider != tt.wantProvider {
                                t.Errorf("provider = %q, want %q", provider, tt.wantProvider)
                        }
                        if tt.wantAncillary && note == "" {
                                t.Error("expected ancillary note but got empty string")
                        }
                        if !tt.wantAncillary && note != "" {
                                t.Errorf("unexpected ancillary note: %q", note)
                        }
                })
        }
}
