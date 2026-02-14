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
