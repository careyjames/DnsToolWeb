// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
package analyzer

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func (a *Analyzer) AnalyzeSMIMEA(ctx context.Context, domain string) map[string]any {
	result := map[string]any{
		"status":         "success",
		"has_smimea":     false,
		"has_openpgpkey": false,
		"smimea_records": []map[string]any{},
		"openpgpkey_records": []map[string]any{},
		"issues":         []string{},
	}

	smimeaRecords := a.querySMIMEA(ctx, domain)
	openpgpRecords := a.queryOPENPGPKEY(ctx, domain)

	if len(smimeaRecords) > 0 {
		result["has_smimea"] = true
		result["smimea_records"] = parseSMIMEARecords(smimeaRecords)
	}

	if len(openpgpRecords) > 0 {
		result["has_openpgpkey"] = true
		result["openpgpkey_records"] = parseOPENPGPKEYRecords(openpgpRecords)
	}

	if !result["has_smimea"].(bool) && !result["has_openpgpkey"].(bool) {
		result["status"] = "info"
		result["message"] = "No SMIMEA or OPENPGPKEY records found — email encryption keys not published via DNS"
	} else {
		result["message"] = buildEmailEncryptionMessage(result)
	}

	return result
}

func (a *Analyzer) querySMIMEA(ctx context.Context, domain string) []*dns.SMIMEA {
	queryName := fmt.Sprintf("*._smimecert.%s", domain)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(queryName), dns.TypeSMIMEA)
	msg.RecursionDesired = true

	resp, err := a.DNS.ExchangeContext(ctx, msg)
	if err != nil || resp == nil {
		return nil
	}

	var records []*dns.SMIMEA
	for _, rr := range resp.Answer {
		if s, ok := rr.(*dns.SMIMEA); ok {
			records = append(records, s)
		}
	}
	return records
}

func (a *Analyzer) queryOPENPGPKEY(ctx context.Context, domain string) []*dns.OPENPGPKEY {
	queryName := fmt.Sprintf("*._openpgpkey.%s", domain)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(queryName), dns.TypeOPENPGPKEY)
	msg.RecursionDesired = true

	resp, err := a.DNS.ExchangeContext(ctx, msg)
	if err != nil || resp == nil {
		return nil
	}

	var records []*dns.OPENPGPKEY
	for _, rr := range resp.Answer {
		if o, ok := rr.(*dns.OPENPGPKEY); ok {
			records = append(records, o)
		}
	}
	return records
}

func parseSMIMEARecords(records []*dns.SMIMEA) []map[string]any {
	var parsed []map[string]any
	for _, r := range records {
		parsed = append(parsed, map[string]any{
			"usage":        r.Usage,
			"selector":     r.Selector,
			"matching_type": r.MatchingType,
			"raw":          r.String(),
			"confidence":   ConfidenceObservedMap(MethodDNSRecord),
		})
	}
	return parsed
}

func parseOPENPGPKEYRecords(records []*dns.OPENPGPKEY) []map[string]any {
	var parsed []map[string]any
	for _, r := range records {
		parsed = append(parsed, map[string]any{
			"key_length": len(r.PublicKey),
			"raw":        truncateRecord(r.String(), 120),
			"confidence": ConfidenceObservedMap(MethodDNSRecord),
		})
	}
	return parsed
}

func buildEmailEncryptionMessage(result map[string]any) string {
	var parts []string
	if result["has_smimea"].(bool) {
		parts = append(parts, "S/MIME certificates published via SMIMEA (RFC 8162)")
	}
	if result["has_openpgpkey"].(bool) {
		parts = append(parts, "OpenPGP keys published via OPENPGPKEY (RFC 7929)")
	}
	return fmt.Sprintf("%s", strings.Join(parts, "; "))
}
