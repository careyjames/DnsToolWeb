// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
// Tests for this package are maintained in the private repository.
// See github.com/careyjames/dnstool-intel for the full test suite.
package analyzer

import (
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
