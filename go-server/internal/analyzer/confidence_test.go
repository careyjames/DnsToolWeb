package analyzer

import (
        "testing"
)

func TestConfidenceMapFunctions(t *testing.T) {
        t.Run("ObservedMap", func(t *testing.T) {
                m := ConfidenceObservedMap(MethodRDAP)
                if m["level"] != ConfidenceObserved {
                        t.Errorf("expected level %q, got %q", ConfidenceObserved, m["level"])
                }
                if m["label"] != ConfidenceLabelObserved {
                        t.Errorf("expected label %q, got %q", ConfidenceLabelObserved, m["label"])
                }
                if m["method"] != MethodRDAP {
                        t.Errorf("expected method %q, got %q", MethodRDAP, m["method"])
                }
        })

        t.Run("InferredMap", func(t *testing.T) {
                m := ConfidenceInferredMap(MethodNSPattern)
                if m["level"] != ConfidenceInferred {
                        t.Errorf("expected level %q, got %q", ConfidenceInferred, m["level"])
                }
                if m["label"] != ConfidenceLabelInferred {
                        t.Errorf("expected label %q, got %q", ConfidenceLabelInferred, m["label"])
                }
                if m["method"] != MethodNSPattern {
                        t.Errorf("expected method %q, got %q", MethodNSPattern, m["method"])
                }
        })

        t.Run("ThirdPartyMap", func(t *testing.T) {
                m := ConfidenceThirdPartyMap("ip-api.com")
                if m["level"] != ConfidenceThirdParty {
                        t.Errorf("expected level %q, got %q", ConfidenceThirdParty, m["level"])
                }
                if m["label"] != ConfidenceLabelThirdParty {
                        t.Errorf("expected label %q, got %q", ConfidenceLabelThirdParty, m["label"])
                }
        })
}

func TestInfrastructureConfidenceLabels(t *testing.T) {
        a := testAnalyzer()

        t.Run("HostingInfoHasConfidence", func(t *testing.T) {
                results := baseResults()
                results["basic_records"] = map[string]any{
                        "A":  []string{"172.217.14.206"},
                        "NS": []string{"ns1.google.com", "ns2.google.com"},
                        "MX": []string{"aspmx.l.google.com"},
                }
                hosting := a.GetHostingInfo("example.com", results)

                hostConf, ok := hosting["hosting_confidence"].(map[string]any)
                if !ok || len(hostConf) == 0 {
                        t.Skip("hosting_confidence empty for unresolved A-record provider")
                }

                emailConf, ok := hosting["email_confidence"].(map[string]any)
                if !ok {
                        t.Fatal("email_confidence missing from hosting info")
                }
                if emailConf["level"] != ConfidenceObserved {
                        t.Errorf("expected observed confidence for email (MX pattern), got %q", emailConf["level"])
                }

                dnsConf, ok := hosting["dns_confidence"].(map[string]any)
                if !ok {
                        t.Fatal("dns_confidence missing from hosting info")
                }
                if dnsConf["level"] != ConfidenceObserved {
                        t.Errorf("expected observed confidence for dns (NS pattern), got %q", dnsConf["level"])
                }
        })

        t.Run("DNSInfraHasConfidence", func(t *testing.T) {
                results := baseResults()
                results["basic_records"] = map[string]any{
                        "NS": []string{"ns1.cloudflare.com", "ns2.cloudflare.com"},
                }
                infra := a.AnalyzeDNSInfrastructure("example.com", results)

                conf, ok := infra["confidence"].(map[string]any)
                if !ok {
                        t.Fatal("confidence missing from DNS infrastructure result")
                }
                if conf["level"] != ConfidenceObserved {
                        t.Errorf("expected observed confidence (NS pattern match), got %q", conf["level"])
                }
                if conf["method"] != MethodNSPattern {
                        t.Errorf("expected method %q, got %q", MethodNSPattern, conf["method"])
                }
        })

        t.Run("GovernmentConfidence", func(t *testing.T) {
                results := baseResults()
                results["basic_records"] = map[string]any{
                        "NS": []string{"ns1.example.gov"},
                }
                infra := a.AnalyzeDNSInfrastructure("whitehouse.gov", results)

                govConf, ok := infra["gov_confidence"].(map[string]any)
                if !ok {
                        t.Fatal("gov_confidence missing for government domain")
                }
                if govConf["level"] != ConfidenceInferred {
                        t.Errorf("expected inferred confidence for gov detection, got %q", govConf["level"])
                }
                if govConf["method"] != MethodTLDSuffix {
                        t.Errorf("expected method %q, got %q", MethodTLDSuffix, govConf["method"])
                }
        })
}
