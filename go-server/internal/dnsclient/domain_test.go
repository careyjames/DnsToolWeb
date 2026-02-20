// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package dnsclient

import "testing"

func TestValidateDomain_Basic(t *testing.T) {
	valid := []string{
		"example.com",
		"sub.example.com",
		"deep.sub.example.com",
		"ietf.org",
		"apple.com",
		"whitehouse.gov",
		"münchen.de",
		"nlnetlabs.nl",
		"a.b.c.d.e.f.g.example.com",
	}
	for _, d := range valid {
		if !ValidateDomain(d) {
			t.Errorf("expected valid: %s", d)
		}
	}

	invalid := []string{
		"",
		"localhost",
		".example.com",
		"-example.com",
		"example..com",
	}
	for _, d := range invalid {
		if ValidateDomain(d) {
			t.Errorf("expected invalid: %s", d)
		}
	}
}

func TestValidateDomain_LabelDepth(t *testing.T) {
	if ValidateDomain("a.b.c.d.e.f.g.h.i.j.k.example.com") {
		t.Error("expected >10 labels to be rejected")
	}
	if !ValidateDomain("a.b.c.d.e.f.g.h.example.com") {
		t.Error("expected 10 labels to be accepted")
	}
}

func TestValidateDomain_ScannerDomainsAccepted(t *testing.T) {
	scannerDomains := []string{
		"3bb082.2351459410758711703.103661431.ssrf02.ssrf.us3.qualysperiscope.com",
		"test.oastify.com",
		"abc123.burpcollaborator.net",
	}
	for _, d := range scannerDomains {
		if !ValidateDomain(d) {
			t.Errorf("scanner domain should be accepted for analysis: %s", d)
		}
	}
}

func TestValidateDomain_LegitDomains(t *testing.T) {
	legit := []string{
		"apple.com",
		"westcappowerequipment.com",
		"sportcommunities.group",
		"imobr-bucuresti.ro",
		"nsfnow.com",
		"red.com",
		"xn--mnchen-3ya.de",
		"cdn-123456.example.com",
		"mail01.example.com",
	}
	for _, d := range legit {
		if !ValidateDomain(d) {
			t.Errorf("false positive — should be valid: %s", d)
		}
	}
}
