package analyzer

import (
        "strings"
        "testing"
)

func newTestAnalyzer() *Analyzer {
        return &Analyzer{
                maxConcurrent: 6,
                semaphore:     make(chan struct{}, 6),
                ctCache:       make(map[string]ctCacheEntry),
        }
}

func TestNonExistentDomainStructure(t *testing.T) {
        a := newTestAnalyzer()
        msg := "Domain is not delegated"
        result := a.buildNonExistentResult("fake.example", "undelegated", &msg)

        if result["domain_exists"] != false {
                t.Errorf("expected domain_exists=false, got %v", result["domain_exists"])
        }
        if result["domain_status"] != "undelegated" {
                t.Errorf("expected domain_status=undelegated, got %v", result["domain_status"])
        }

        basic, ok := result["basic_records"].(map[string]any)
        if !ok {
                t.Fatal("basic_records is not map[string]any")
        }
        expectedTypes := []string{"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"}
        for _, rtype := range expectedTypes {
                arr, ok := basic[rtype].([]string)
                if !ok {
                        t.Errorf("basic_records[%s] is not []string", rtype)
                        continue
                }
                if len(arr) != 0 {
                        t.Errorf("basic_records[%s] should be empty, got %v", rtype, arr)
                }
        }

        dane, ok := result["dane_analysis"].(map[string]any)
        if !ok {
                t.Fatal("dane_analysis is not map[string]any")
        }
        if dane["has_dane"] != false {
                t.Errorf("expected dane has_dane=false, got %v", dane["has_dane"])
        }
        tlsa, ok := dane["tlsa_records"].([]any)
        if !ok {
                t.Fatal("dane tlsa_records is not []any")
        }
        if len(tlsa) != 0 {
                t.Error("expected empty tlsa_records")
        }
        issues, ok := dane["issues"].([]string)
        if !ok {
                t.Fatal("dane issues is not []string")
        }
        if len(issues) != 0 {
                t.Error("expected empty dane issues")
        }
}

func TestNonExistentDomainAllSectionsNA(t *testing.T) {
        a := newTestAnalyzer()
        result := a.buildNonExistentResult("fake.example", "undelegated", nil)

        naSections := []string{
                "spf_analysis", "dmarc_analysis", "dkim_analysis",
                "mta_sts_analysis", "tlsrpt_analysis", "bimi_analysis",
                "dane_analysis", "caa_analysis", "dnssec_analysis",
        }

        for _, section := range naSections {
                m, ok := result[section].(map[string]any)
                if !ok {
                        t.Errorf("%s is not map[string]any", section)
                        continue
                }
                if m["status"] != "n/a" {
                        t.Errorf("%s status expected n/a, got %v", section, m["status"])
                }
        }
}

func TestNonExistentDomainPosture(t *testing.T) {
        a := newTestAnalyzer()
        result := a.buildNonExistentResult("fake.example", "undelegated", nil)

        posture, ok := result["posture"].(map[string]any)
        if !ok {
                t.Fatal("posture is not map[string]any")
        }
        if posture["score"] != 0 {
                t.Errorf("expected score=0, got %v", posture["score"])
        }
        if posture["grade"] != "N/A" {
                t.Errorf("expected grade=N/A, got %v", posture["grade"])
        }
        if posture["color"] != "secondary" {
                t.Errorf("expected color=secondary, got %v", posture["color"])
        }
}

func TestPostureFullProtection(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":   map[string]any{"status": "success"},
                "dmarc_analysis": map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":  map[string]any{"status": "success"},
                "mta_sts_analysis": map[string]any{"status": "success"},
                "tlsrpt_analysis":  map[string]any{"status": "success"},
                "bimi_analysis":    map[string]any{"status": "success"},
                "dane_analysis":    map[string]any{"has_dane": true},
                "caa_analysis":     map[string]any{"status": "success"},
                "dnssec_analysis":  map[string]any{"status": "success"},
        }

        posture := a.CalculatePosture(results)
        score, _ := posture["score"].(int)
        if score < 90 {
                t.Errorf("expected score >= 90 for full protection, got %d", score)
        }
        if posture["state"] != "STRONG" {
                t.Errorf("expected state STRONG, got %v", posture["state"])
        }
        if posture["color"] != "success" {
                t.Errorf("expected color success, got %v", posture["color"])
        }
}

func TestPostureMinimalSPFOnly(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success"},
                "dmarc_analysis":   map[string]any{},
                "dkim_analysis":    map[string]any{},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
        }

        posture := a.CalculatePosture(results)
        if posture["state"] != "WEAK" {
                t.Errorf("expected state WEAK (SPF only, no DMARC), got %v", posture["state"])
        }
}

func TestPostureScoreCapping(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success"},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{"status": "success"},
                "mta_sts_analysis": map[string]any{"status": "success"},
                "tlsrpt_analysis":  map[string]any{"status": "success"},
                "bimi_analysis":    map[string]any{"status": "success"},
                "dane_analysis":    map[string]any{"has_dane": true},
                "caa_analysis":     map[string]any{"status": "success"},
                "dnssec_analysis":  map[string]any{"status": "success"},
        }

        posture := a.CalculatePosture(results)
        score, _ := posture["score"].(int)
        if score > 100 {
                t.Errorf("score should be capped at 100, got %d", score)
        }
        if score != 100 {
                t.Errorf("expected score=100, got %d", score)
        }
}

func TestPostureIssuesTracking(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{},
                "dmarc_analysis":   map[string]any{},
                "dkim_analysis":    map[string]any{},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
        }

        posture := a.CalculatePosture(results)
        issues, ok := posture["issues"].([]string)
        if !ok {
                t.Fatal("issues is not []string")
        }

        expectedIssues := []string{
                "No SPF record",
                "No DMARC record",
                "No DKIM found",
                "No CAA records",
        }

        if len(issues) != len(expectedIssues) {
                t.Errorf("expected %d issues, got %d: %v", len(expectedIssues), len(issues), issues)
        }
        for i, expected := range expectedIssues {
                if i < len(issues) && issues[i] != expected {
                        t.Errorf("issue[%d] expected %q, got %q", i, expected, issues[i])
                }
        }
}

func TestPostureProviderAwareDKIM(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success"},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{"status": "info", "primary_provider": "Google Workspace"},
                "mta_sts_analysis": map[string]any{"status": "success"},
                "tlsrpt_analysis":  map[string]any{"status": "success"},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{"status": "success"},
                "dnssec_analysis":  map[string]any{},
        }

        posture := a.CalculatePosture(results)
        state, _ := posture["state"].(string)
        if !strings.HasPrefix(state, "STRONG") {
                t.Errorf("expected STRONG for provider-aware DKIM, got %v", state)
        }

        configured, _ := posture["configured"].([]string)
        found := false
        for _, c := range configured {
                if strings.Contains(c, "provider-verified") {
                        found = true
                        break
                }
        }
        if !found {
                t.Error("expected 'provider-verified' in configured list")
        }

        monitoring, _ := posture["monitoring"].([]string)
        if len(monitoring) > 0 {
                t.Errorf("known provider DKIM should not be in monitoring, got %v", monitoring)
        }
}

func TestPostureUnknownProviderDKIM(t *testing.T) {
        a := newTestAnalyzer()
        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success"},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{"status": "info", "primary_provider": "Unknown"},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
        }

        posture := a.CalculatePosture(results)
        monitoring, _ := posture["monitoring"].([]string)
        if len(monitoring) == 0 {
                t.Error("unknown provider DKIM should be in monitoring")
        }
        state, _ := posture["state"].(string)
        if !strings.Contains(state, "Monitoring") {
                t.Errorf("expected state containing Monitoring, got %v", state)
        }
}

func TestPostureTruthBasedGrades(t *testing.T) {
        tests := []struct {
                name          string
                results       map[string]any
                expectedGrade string
                expectedColor string
                messageContains string
        }{
                {
                        name: "STRONG — full protection with reject + CAA",
                        results: map[string]any{
                                "spf_analysis":     map[string]any{"status": "success"},
                                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                                "dkim_analysis":    map[string]any{"status": "success"},
                                "mta_sts_analysis": map[string]any{"status": "success"},
                                "tlsrpt_analysis":  map[string]any{"status": "success"},
                                "bimi_analysis":    map[string]any{"status": "success"},
                                "dane_analysis":    map[string]any{"has_dane": true},
                                "caa_analysis":     map[string]any{"status": "success"},
                                "dnssec_analysis":  map[string]any{"status": "success"},
                        },
                        expectedGrade: "STRONG",
                        expectedColor: "success",
                        messageContains: "DMARC enforcement",
                },
                {
                        name: "STRONG — core with reject + CAA, optional missing",
                        results: map[string]any{
                                "spf_analysis":     map[string]any{"status": "success"},
                                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                                "dkim_analysis":    map[string]any{"status": "success"},
                                "mta_sts_analysis": map[string]any{},
                                "tlsrpt_analysis":  map[string]any{},
                                "bimi_analysis":    map[string]any{},
                                "dane_analysis":    map[string]any{},
                                "caa_analysis":     map[string]any{"status": "success"},
                                "dnssec_analysis":  map[string]any{},
                        },
                        expectedGrade: "STRONG",
                        expectedColor: "success",
                        messageContains: "not configured",
                },
                {
                        name: "STRONG — quarantine with core configured",
                        results: map[string]any{
                                "spf_analysis":     map[string]any{"status": "success"},
                                "dmarc_analysis":   map[string]any{"status": "success", "policy": "quarantine"},
                                "dkim_analysis":    map[string]any{"status": "success"},
                                "mta_sts_analysis": map[string]any{},
                                "tlsrpt_analysis":  map[string]any{},
                                "bimi_analysis":    map[string]any{},
                                "dane_analysis":    map[string]any{},
                                "caa_analysis":     map[string]any{},
                                "dnssec_analysis":  map[string]any{},
                        },
                        expectedGrade: "STRONG",
                        expectedColor: "success",
                        messageContains: "quarantine",
                },
                {
                        name: "GOOD — core present but DMARC p=none",
                        results: map[string]any{
                                "spf_analysis":     map[string]any{"status": "success"},
                                "dmarc_analysis":   map[string]any{"status": "warning", "policy": "none"},
                                "dkim_analysis":    map[string]any{"status": "success"},
                                "mta_sts_analysis": map[string]any{},
                                "tlsrpt_analysis":  map[string]any{},
                                "bimi_analysis":    map[string]any{},
                                "dane_analysis":    map[string]any{},
                                "caa_analysis":     map[string]any{},
                                "dnssec_analysis":  map[string]any{},
                        },
                        expectedGrade: "GOOD",
                        expectedColor: "info",
                        messageContains: "monitoring mode",
                },
                {
                        name: "FAIR — SPF + DMARC but no DKIM",
                        results: map[string]any{
                                "spf_analysis":     map[string]any{"status": "success"},
                                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                                "dkim_analysis":    map[string]any{},
                                "mta_sts_analysis": map[string]any{},
                                "tlsrpt_analysis":  map[string]any{},
                                "bimi_analysis":    map[string]any{},
                                "dane_analysis":    map[string]any{},
                                "caa_analysis":     map[string]any{},
                                "dnssec_analysis":  map[string]any{},
                        },
                        expectedGrade: "FAIR",
                        expectedColor: "warning",
                        messageContains: "DKIM not verified",
                },
                {
                        name: "WEAK — SPF only, no DMARC",
                        results: map[string]any{
                                "spf_analysis":     map[string]any{"status": "success"},
                                "dmarc_analysis":   map[string]any{},
                                "dkim_analysis":    map[string]any{},
                                "mta_sts_analysis": map[string]any{},
                                "tlsrpt_analysis":  map[string]any{},
                                "bimi_analysis":    map[string]any{},
                                "dane_analysis":    map[string]any{},
                                "caa_analysis":     map[string]any{},
                                "dnssec_analysis":  map[string]any{},
                        },
                        expectedGrade: "WEAK",
                        expectedColor: "warning",
                        messageContains: "DMARC",
                },
                {
                        name: "CRITICAL — nothing configured",
                        results: map[string]any{
                                "spf_analysis":     map[string]any{},
                                "dmarc_analysis":   map[string]any{},
                                "dkim_analysis":    map[string]any{},
                                "mta_sts_analysis": map[string]any{},
                                "tlsrpt_analysis":  map[string]any{},
                                "bimi_analysis":    map[string]any{},
                                "dane_analysis":    map[string]any{},
                                "caa_analysis":     map[string]any{},
                                "dnssec_analysis":  map[string]any{},
                        },
                        expectedGrade: "CRITICAL",
                        expectedColor: "danger",
                        messageContains: "fully vulnerable",
                },
        }

        a := newTestAnalyzer()
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        posture := a.CalculatePosture(tt.results)
                        state, _ := posture["state"].(string)
                        if !strings.HasPrefix(state, tt.expectedGrade) {
                                t.Errorf("expected state starting with %s, got %v", tt.expectedGrade, state)
                        }
                        if posture["color"] != tt.expectedColor {
                                t.Errorf("expected color %s, got %v", tt.expectedColor, posture["color"])
                        }
                        label, _ := posture["message"].(string)
                        if !strings.Contains(strings.ToLower(label), strings.ToLower(tt.messageContains)) {
                                t.Errorf("expected message containing %q, got %q", tt.messageContains, label)
                        }
                })
        }
}

func TestRemediationTopFixes(t *testing.T) {
        a := newTestAnalyzer()

        results := map[string]any{
                "spf_analysis":     map[string]any{},
                "dmarc_analysis":   map[string]any{},
                "dkim_analysis":    map[string]any{},
                "mta_sts_analysis": map[string]any{},
                "tlsrpt_analysis":  map[string]any{},
                "bimi_analysis":    map[string]any{},
                "dane_analysis":    map[string]any{},
                "caa_analysis":     map[string]any{},
                "dnssec_analysis":  map[string]any{},
        }

        remediation := a.GenerateRemediation(results)
        topFixes, ok := remediation["top_fixes"].([]map[string]any)
        if !ok {
                t.Fatal("top_fixes is not []map[string]any")
        }
        if len(topFixes) != 3 {
                t.Errorf("expected 3 top fixes, got %d", len(topFixes))
        }

        for _, fix := range topFixes {
                severity, _ := fix["severity_label"].(string)
                if severity != "Critical" && severity != "High" && severity != "Medium" && severity != "Low" {
                        t.Errorf("unexpected severity: %s", severity)
                }
                rfcURL, _ := fix["rfc_url"].(string)
                if rfcURL == "" {
                        t.Error("expected non-empty rfc_url")
                }
                if !strings.Contains(rfcURL, "#section") {
                        t.Errorf("RFC URL should link to specific section: %s", rfcURL)
                }
        }

        if topFixes[0]["severity_label"] != "Critical" {
                t.Errorf("first fix should be Critical severity, got %v", topFixes[0]["severity_label"])
        }
}

func TestRemediationFullySecure(t *testing.T) {
        a := newTestAnalyzer()

        results := map[string]any{
                "spf_analysis":     map[string]any{"status": "success"},
                "dmarc_analysis":   map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":    map[string]any{"status": "success"},
                "mta_sts_analysis": map[string]any{"status": "success"},
                "tlsrpt_analysis":  map[string]any{"status": "success"},
                "bimi_analysis":    map[string]any{"status": "success"},
                "dane_analysis":    map[string]any{"has_dane": true},
                "caa_analysis":     map[string]any{"status": "success"},
                "dnssec_analysis":  map[string]any{"status": "success"},
        }

        remediation := a.GenerateRemediation(results)
        topFixes, ok := remediation["top_fixes"].([]map[string]any)
        if !ok {
                t.Fatal("top_fixes is not []map[string]any")
        }
        if len(topFixes) != 0 {
                t.Errorf("fully secure domain should have 0 fixes, got %d", len(topFixes))
        }
        if remediation["posture_achievable"] != "SECURE" {
                t.Errorf("expected achievable SECURE, got %v", remediation["posture_achievable"])
        }
}

func TestGovernmentDomainDetection(t *testing.T) {
        a := newTestAnalyzer()

        tests := []struct {
                domain string
        }{
                {"whitehouse.gov"},
                {"army.mil"},
                {"service.gov.uk"},
                {"defence.gov.au"},
                {"canada.gc.ca"},
        }

        for _, tt := range tests {
                t.Run(tt.domain, func(t *testing.T) {
                        results := map[string]any{
                                "basic_records": map[string]any{
                                        "A":  []string{},
                                        "NS": []string{},
                                        "MX": []string{},
                                },
                                "caa_analysis":   map[string]any{},
                                "dnssec_analysis": map[string]any{},
                        }
                        infra := a.AnalyzeDNSInfrastructure(tt.domain, results)
                        if infra["is_government"] != true {
                                t.Errorf("%s should be detected as government domain", tt.domain)
                        }
                })
        }
}

func TestEnterpriseProviderDetection(t *testing.T) {
        a := newTestAnalyzer()

        tests := []struct {
                name     string
                ns       []string
                expected string
        }{
                {"Cloudflare", []string{"ns1.cloudflare.com", "ns2.cloudflare.com"}, "enterprise"},
                {"Route53", []string{"ns-123.awsdns-01.net", "ns-456.awsdns-02.org"}, "enterprise"},
                {"Azure", []string{"ns1-01.azure-dns.com", "ns2-01.azure-dns.net"}, "enterprise"},
                {"UltraDNS", []string{"udns1.ultradns.net", "udns2.ultradns.net"}, "enterprise"},
                {"GoDaddy", []string{"ns1.domaincontrol.com", "ns2.domaincontrol.com"}, "managed"},
                {"Namecheap", []string{"ns1.registrar-servers.com", "ns2.registrar-servers.com"}, "managed"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        results := map[string]any{
                                "basic_records": map[string]any{
                                        "A":  []string{},
                                        "NS": tt.ns,
                                        "MX": []string{},
                                },
                                "caa_analysis":    map[string]any{},
                                "dnssec_analysis": map[string]any{},
                        }
                        infra := a.AnalyzeDNSInfrastructure("example.com", results)
                        if infra["provider_tier"] != tt.expected {
                                t.Errorf("expected tier %s for %s, got %v", tt.expected, tt.name, infra["provider_tier"])
                        }
                })
        }
}

func TestNonGovernmentDomainNotDetected(t *testing.T) {
        a := newTestAnalyzer()

        domains := []string{"google.com", "amazon.com", "github.io", "example.org"}

        for _, domain := range domains {
                t.Run(domain, func(t *testing.T) {
                        results := map[string]any{
                                "basic_records": map[string]any{
                                        "A":  []string{},
                                        "NS": []string{"ns1.example.com"},
                                        "MX": []string{},
                                },
                                "caa_analysis":    map[string]any{},
                                "dnssec_analysis": map[string]any{},
                        }
                        infra := a.AnalyzeDNSInfrastructure(domain, results)
                        if infra["is_government"] == true {
                                t.Errorf("%s should not be detected as government domain", domain)
                        }
                })
        }
}

func TestStrContainsAny(t *testing.T) {
        tests := []struct {
                s        string
                substrs  []string
                expected bool
        }{
                {"Hello World", []string{"hello"}, true},
                {"Hello World", []string{"WORLD"}, true},
                {"Hello World", []string{"foo", "bar"}, false},
                {"cloudflare.com", []string{"cloud", "azure"}, true},
                {"", []string{"anything"}, false},
                {"something", []string{}, false},
        }

        for _, tt := range tests {
                result := strContainsAny(tt.s, tt.substrs...)
                if result != tt.expected {
                        t.Errorf("strContainsAny(%q, %v) = %v, want %v", tt.s, tt.substrs, result, tt.expected)
                }
        }
}

func TestStrHasSuffix(t *testing.T) {
        tests := []struct {
                s        string
                suffixes []string
                expected bool
        }{
                {"whitehouse.gov", []string{".gov", ".mil"}, true},
                {"army.mil", []string{".gov", ".mil"}, true},
                {"google.com", []string{".gov", ".mil"}, false},
                {"service.gov.uk", []string{".gov.uk"}, true},
                {"", []string{".gov"}, false},
        }

        for _, tt := range tests {
                result := strHasSuffix(tt.s, tt.suffixes...)
                if result != tt.expected {
                        t.Errorf("strHasSuffix(%q, %v) = %v, want %v", tt.s, tt.suffixes, result, tt.expected)
                }
        }
}

func TestUniqueStrings(t *testing.T) {
        tests := []struct {
                input    []string
                expected int
        }{
                {[]string{"a", "b", "c"}, 3},
                {[]string{"a", "a", "b"}, 2},
                {[]string{"x", "x", "x"}, 1},
                {[]string{}, 0},
                {nil, 0},
        }

        for _, tt := range tests {
                result := uniqueStrings(tt.input)
                if len(result) != tt.expected {
                        t.Errorf("uniqueStrings(%v) returned %d items, want %d", tt.input, len(result), tt.expected)
                }
        }
}

func TestGetStr(t *testing.T) {
        m := map[string]any{"key": "value", "num": 42}

        if got := getStr(m, "key"); got != "value" {
                t.Errorf("getStr(m, 'key') = %q, want 'value'", got)
        }
        if got := getStr(m, "num"); got != "" {
                t.Errorf("getStr(m, 'num') = %q, want ''", got)
        }
        if got := getStr(m, "missing"); got != "" {
                t.Errorf("getStr(m, 'missing') = %q, want ''", got)
        }
}

func TestGetSlice(t *testing.T) {
        m := map[string]any{
                "strings": []string{"a", "b"},
                "anys":    []any{"c", "d"},
                "mixed":   []any{"e", 42},
                "notslice": "hello",
        }

        if got := getSlice(m, "strings"); len(got) != 2 || got[0] != "a" {
                t.Errorf("getSlice strings unexpected: %v", got)
        }
        if got := getSlice(m, "anys"); len(got) != 2 || got[0] != "c" {
                t.Errorf("getSlice anys unexpected: %v", got)
        }
        if got := getSlice(m, "mixed"); len(got) != 1 || got[0] != "e" {
                t.Errorf("getSlice mixed unexpected: %v", got)
        }
        if got := getSlice(m, "notslice"); got != nil {
                t.Errorf("getSlice notslice expected nil, got %v", got)
        }
        if got := getSlice(m, "missing"); got != nil {
                t.Errorf("getSlice missing expected nil, got %v", got)
        }
}

func TestGetBool(t *testing.T) {
        m := map[string]any{"flag": true, "off": false, "str": "true"}

        if got := getBool(m, "flag"); got != true {
                t.Error("getBool flag expected true")
        }
        if got := getBool(m, "off"); got != false {
                t.Error("getBool off expected false")
        }
        if got := getBool(m, "str"); got != false {
                t.Error("getBool str expected false")
        }
        if got := getBool(m, "missing"); got != false {
                t.Error("getBool missing expected false")
        }
}

func TestGetMap(t *testing.T) {
        sub := map[string]any{"nested": true}
        m := map[string]any{"sub": sub, "str": "hello"}

        if got := getMap(m, "sub"); got == nil || got["nested"] != true {
                t.Error("getMap sub unexpected")
        }
        if got := getMap(m, "str"); got != nil {
                t.Error("getMap str expected nil")
        }
        if got := getMap(m, "missing"); got != nil {
                t.Error("getMap missing expected nil")
        }
}
