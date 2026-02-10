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

	var validRecords []string
	for _, r := range records {
		if strings.HasPrefix(strings.ToLower(r), "v=bimi1") {
			validRecords = append(validRecords, r)
		}
	}

	if len(validRecords) == 0 {
		baseResult["message"] = "No valid BIMI record found"
		return baseResult
	}

	record := validRecords[0]
	var logoURL, vmcURL *string

	if m := bimiLogoRe.FindStringSubmatch(record); m != nil {
		logoURL = &m[1]
	}
	if m := bimiVMCRe.FindStringSubmatch(record); m != nil {
		vmcURL = &m[1]
	}

	var logoData map[string]any
	if logoURL != nil {
		logoData = a.validateBIMILogo(ctx, *logoURL)
	} else {
		logoData = map[string]any{}
	}

	var vmcData map[string]any
	if vmcURL != nil {
		vmcData = a.validateBIMIVMC(ctx, *vmcURL)
	} else {
		vmcData = map[string]any{}
	}

	status := "success"
	var messageParts []string

	if vmcURL != nil && vmcData["valid"] == true {
		messageParts = append(messageParts, "BIMI with VMC certificate")
		if issuer, ok := vmcData["issuer"].(string); ok && issuer != "" {
			messageParts = append(messageParts, fmt.Sprintf("(from %s)", issuer))
		}
	} else if vmcURL != nil {
		messageParts = append(messageParts, "BIMI with VMC")
		if errStr, ok := vmcData["error"].(string); ok && errStr != "" {
			status = "warning"
			messageParts = append(messageParts, fmt.Sprintf("- VMC issue: %s", errStr))
		}
	} else if logoURL != nil {
		messageParts = append(messageParts, "BIMI configured")
		if logoData["valid"] == true {
			messageParts = append(messageParts, "- logo validated")
		}
		messageParts = append(messageParts, "(VMC recommended for Gmail)")
	} else {
		status = "warning"
		messageParts = append(messageParts, "BIMI record found but missing logo URL")
	}

	if logoURL != nil && logoData["valid"] != true {
		if errStr, ok := logoData["error"].(string); ok && errStr != "" {
			status = "warning"
			messageParts = append(messageParts, fmt.Sprintf("Logo issue: %s", errStr))
		}
	}

	return map[string]any{
		"status":      status,
		"message":     strings.Join(messageParts, " "),
		"record":      record,
		"logo_url":    logoURL,
		"vmc_url":     vmcURL,
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
		errStr := err.Error()
		if strings.Contains(errStr, "tls") || strings.Contains(errStr, "certificate") {
			result["error"] = "SSL error"
		} else if strings.Contains(errStr, "connection") || strings.Contains(errStr, "dial") {
			result["error"] = "Connection failed"
		} else if strings.Contains(errStr, "timeout") {
			result["error"] = "Timeout"
		} else {
			if len(errStr) > 30 {
				errStr = errStr[:30]
			}
			result["error"] = errStr
		}
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

	contentType := resp.Header.Get("Content-Type")
	lowerCT := strings.ToLower(contentType)
	if strings.Contains(lowerCT, "svg") {
		result["valid"] = true
		result["format"] = "SVG"
	} else if strings.Contains(lowerCT, "image") {
		result["valid"] = true
		parts := strings.Split(contentType, "/")
		if len(parts) >= 2 {
			result["format"] = strings.ToUpper(parts[1])
		}
	} else {
		content := strings.ToLower(string(body[:minInt(500, len(body))]))
		if strings.Contains(content, "<svg") {
			result["valid"] = true
			result["format"] = "SVG"
		} else {
			result["error"] = "Not SVG format"
		}
	}

	return result
}

func (a *Analyzer) validateBIMIVMC(ctx context.Context, url string) map[string]any {
	result := map[string]any{"valid": false, "issuer": nil, "subject": nil, "error": nil}

	if url == "" {
		result["error"] = "No URL"
		return result
	}

	resp, err := a.HTTP.Get(ctx, url)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "tls") || strings.Contains(errStr, "certificate") {
			result["error"] = "SSL error"
		} else if strings.Contains(errStr, "connection") || strings.Contains(errStr, "dial") {
			result["error"] = "Connection failed"
		} else if strings.Contains(errStr, "timeout") {
			result["error"] = "Timeout"
		} else {
			if len(errStr) > 30 {
				errStr = errStr[:30]
			}
			result["error"] = errStr
		}
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

	content := string(body)
	if strings.Contains(content, "-----BEGIN CERTIFICATE-----") {
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
	} else {
		result["error"] = "Invalid certificate format"
	}

	return result
}
