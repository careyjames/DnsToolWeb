// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var (
	bimiLogoRe = regexp.MustCompile(`(?i)l=([^;\s]+)`)
	bimiVMCRe  = regexp.MustCompile(`(?i)a=([^;\s]+)`)
)

func buildBIMIMessage(logoURL, vmcURL *string, logoData, vmcData map[string]any) (string, string) {
	status := "success"
	var messageParts []string

	status, messageParts = buildBIMICoreMessage(logoURL, vmcURL, logoData, vmcData)
	messageParts = appendBIMILogoIssue(logoURL, logoData, &status, messageParts)

	return status, strings.Join(messageParts, " ")
}

func buildBIMICoreMessage(logoURL, vmcURL *string, logoData, vmcData map[string]any) (string, []string) {
	status := "success"
	var parts []string

	if vmcURL != nil && vmcData["valid"] == true {
		parts = append(parts, "BIMI with VMC certificate")
		if issuer, ok := vmcData["issuer"].(string); ok && issuer != "" {
			parts = append(parts, fmt.Sprintf("(from %s)", issuer))
		}
	} else if vmcURL != nil {
		parts = append(parts, "BIMI with VMC")
		if errStr, ok := vmcData["error"].(string); ok && errStr != "" {
			status = "warning"
			parts = append(parts, fmt.Sprintf("- VMC issue: %s", errStr))
		}
	} else if logoURL != nil {
		parts = append(parts, "BIMI configured")
		if logoData["valid"] == true {
			parts = append(parts, "- logo validated")
		}
		parts = append(parts, "(VMC recommended for Gmail)")
	} else {
		status = "warning"
		parts = append(parts, "BIMI record found but missing logo URL")
	}

	return status, parts
}

func appendBIMILogoIssue(logoURL *string, logoData map[string]any, status *string, parts []string) []string {
	if logoURL != nil && logoData["valid"] != true {
		if errStr, ok := logoData["error"].(string); ok && errStr != "" {
			*status = "warning"
			parts = append(parts, fmt.Sprintf("Logo issue: %s", errStr))
		}
	}
	return parts
}

func filterBIMIRecords(records []string) []string {
	var valid []string
	for _, r := range records {
		if strings.HasPrefix(strings.ToLower(r), "v=bimi1") {
			valid = append(valid, r)
		}
	}
	return valid
}

func extractBIMIURLs(record string) (logoURL, vmcURL *string) {
	if m := bimiLogoRe.FindStringSubmatch(record); m != nil {
		logoURL = &m[1]
	}
	if m := bimiVMCRe.FindStringSubmatch(record); m != nil {
		vmcURL = &m[1]
	}
	return
}

func (a *Analyzer) fetchBIMIValidations(ctx context.Context, logoURL, vmcURL *string) (map[string]any, map[string]any) {
	var logoData, vmcData map[string]any
	if logoURL != nil {
		logoData = a.validateBIMILogo(ctx, *logoURL)
	} else {
		logoData = map[string]any{}
	}
	if vmcURL != nil {
		vmcData = a.validateBIMIVMC(ctx, *vmcURL)
	} else {
		vmcData = map[string]any{}
	}
	return logoData, vmcData
}

func (a *Analyzer) AnalyzeBIMI(ctx context.Context, domain string) map[string]any {
	bimiDomain := fmt.Sprintf("default._bimi.%s", domain)
	records := a.DNS.QueryDNS(ctx, "TXT", bimiDomain)

	baseResult := map[string]any{
		"status":      "warning",
		"message":     "No BIMI record found",
		"record":      nil,
		"logo_url":    nil,
		"vmc_url":     nil,
		"logo_valid":  nil,
		"logo_format": nil,
		"logo_error":  nil,
		"vmc_valid":   nil,
		"vmc_issuer":  nil,
		"vmc_subject": nil,
		"vmc_error":   nil,
	}

	if len(records) == 0 {
		return baseResult
	}

	validRecords := filterBIMIRecords(records)
	if len(validRecords) == 0 {
		baseResult["message"] = "No valid BIMI record found"
		return baseResult
	}

	record := validRecords[0]
	logoURL, vmcURL := extractBIMIURLs(record)
	logoData, vmcData := a.fetchBIMIValidations(ctx, logoURL, vmcURL)
	status, message := buildBIMIMessage(logoURL, vmcURL, logoData, vmcData)

	return map[string]any{
		"status":      status,
		"message":     message,
		"record":      record,
		"logo_url":    derefStr(logoURL),
		"vmc_url":     derefStr(vmcURL),
		"logo_valid":  logoData["valid"],
		"logo_format": logoData["format"],
		"logo_error":  logoData["error"],
		"vmc_valid":   vmcData["valid"],
		"vmc_issuer":  vmcData["issuer"],
		"vmc_subject": vmcData["subject"],
		"vmc_error":   vmcData["error"],
	}
}

func (a *Analyzer) validateBIMILogo(ctx context.Context, url string) map[string]any {
	result := map[string]any{"valid": false, "format": nil, "error": nil}

	if url == "" {
		result["error"] = "No URL"
		return result
	}

	resp, err := a.HTTP.Get(ctx, url)
	if err != nil {
		result["error"] = classifyHTTPError(err, 30)
		return result
	}

	body, err := a.HTTP.ReadBody(resp, 1<<20)
	if err != nil {
		result["error"] = "Failed to read response"
		return result
	}

	if resp.StatusCode != 200 {
		result["error"] = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result
	}

	classifyBIMILogoFormat(resp.Header.Get("Content-Type"), body, result)
	return result
}

func classifyBIMILogoFormat(contentType string, body []byte, result map[string]any) {
	lowerCT := strings.ToLower(contentType)
	switch {
	case strings.Contains(lowerCT, "svg"):
		result["valid"] = true
		result["format"] = "SVG"
	case strings.Contains(lowerCT, "image"):
		result["valid"] = true
		parts := strings.Split(contentType, "/")
		if len(parts) >= 2 {
			result["format"] = strings.ToUpper(parts[1])
		}
	default:
		content := strings.ToLower(string(body[:minInt(500, len(body))]))
		if strings.Contains(content, "<svg") {
			result["valid"] = true
			result["format"] = "SVG"
		} else {
			result["error"] = "Not SVG format"
		}
	}
}

func (a *Analyzer) validateBIMIVMC(ctx context.Context, url string) map[string]any {
	result := map[string]any{"valid": false, "issuer": nil, "subject": nil, "error": nil}

	if url == "" {
		result["error"] = "No URL"
		return result
	}

	resp, err := a.HTTP.Get(ctx, url)
	if err != nil {
		result["error"] = classifyHTTPError(err, 30)
		return result
	}

	body, err := a.HTTP.ReadBody(resp, 1<<20)
	if err != nil {
		result["error"] = "Failed to read response"
		return result
	}

	if resp.StatusCode != 200 {
		result["error"] = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result
	}

	classifyVMCCertificate(string(body), result)
	return result
}

func classifyVMCCertificate(content string, result map[string]any) {
	if !strings.Contains(content, "-----BEGIN CERTIFICATE-----") {
		result["error"] = "Invalid certificate format"
		return
	}
	result["valid"] = true
	switch {
	case strings.Contains(content, "DigiCert"):
		result["issuer"] = "DigiCert"
	case strings.Contains(content, "Entrust"):
		result["issuer"] = "Entrust"
	case strings.Contains(content, "GlobalSign"):
		result["issuer"] = "GlobalSign"
	default:
		result["issuer"] = "Verified CA"
	}
}
