// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"encoding/json"
	"strings"
)

type DetectedFormat struct {
	Format  string
	Headers string
	Error   string
}

func DetectAndExtractHeaders(raw string, filename string) *DetectedFormat {
	trimmed := strings.TrimSpace(raw)

	if isBinaryContent(trimmed) {
		return handleBinaryFile(filename)
	}

	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return tryExtractFromJSON(trimmed)
	}

	if strings.HasPrefix(trimmed, "From ") && isMboxFormat(trimmed) {
		return extractFromMbox(trimmed)
	}

	return &DetectedFormat{
		Format:  "raw",
		Headers: raw,
	}
}

func isBinaryContent(data string) bool {
	if len(data) < 8 {
		return false
	}
	checkLen := 512
	if len(data) < checkLen {
		checkLen = len(data)
	}
	nullCount := 0
	for i := 0; i < checkLen; i++ {
		if data[i] == 0 {
			nullCount++
		}
	}
	return nullCount > 4
}

func handleBinaryFile(filename string) *DetectedFormat {
	lower := strings.ToLower(filename)
	if strings.HasSuffix(lower, ".msg") {
		return &DetectedFormat{
			Format: "msg",
			Error:  "Outlook .msg files use a proprietary binary format we can't read directly. In Outlook, open the message → File → Save As → choose \".eml\" format, then upload that instead.",
		}
	}
	return &DetectedFormat{
		Format: "binary",
		Error:  "This appears to be a binary file. Please paste the headers as text, or save the email as .eml format and upload that.",
	}
}

func tryExtractFromJSON(raw string) *DetectedFormat {
	raw = strings.TrimSpace(raw)

	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		var arr []interface{}
		if err2 := json.Unmarshal([]byte(raw), &arr); err2 != nil {
			return &DetectedFormat{
				Format:  "raw",
				Headers: raw,
			}
		}
		if len(arr) > 0 {
			if first, ok := arr[0].(map[string]interface{}); ok {
				obj = first
			}
		}
	}

	if obj == nil {
		return &DetectedFormat{
			Format:  "raw",
			Headers: raw,
		}
	}

	if headers := extractMicrosoftGraphHeaders(obj); headers != "" {
		return &DetectedFormat{Format: "json-microsoft-graph", Headers: headers}
	}
	if headers := extractGmailAPIHeaders(obj); headers != "" {
		return &DetectedFormat{Format: "json-gmail-api", Headers: headers}
	}
	if headers := extractPostmarkHeaders(obj); headers != "" {
		return &DetectedFormat{Format: "json-postmark", Headers: headers}
	}
	if headers := extractSendGridHeaders(obj); headers != "" {
		return &DetectedFormat{Format: "json-sendgrid", Headers: headers}
	}
	if headers := extractMailgunHeaders(obj); headers != "" {
		return &DetectedFormat{Format: "json-mailgun", Headers: headers}
	}
	if headers := extractGenericJSONHeaders(obj); headers != "" {
		return &DetectedFormat{Format: "json-generic", Headers: headers}
	}

	return &DetectedFormat{
		Format: "json",
		Error:  "We found valid JSON but couldn't locate email headers in it. Supported formats: Gmail API, Microsoft Graph API, Postmark, SendGrid, Mailgun, or any JSON with a \"headers\" key containing RFC 5322 header fields.",
	}
}

func extractMicrosoftGraphHeaders(obj map[string]interface{}) string {
	imh, ok := obj["internetMessageHeaders"]
	if !ok {
		return ""
	}
	arr, ok := imh.([]interface{})
	if !ok {
		return ""
	}
	var lines []string
	for _, item := range arr {
		header, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := header["name"].(string)
		value, _ := header["value"].(string)
		if name != "" {
			lines = append(lines, name+": "+value)
		}
	}

	if subject, ok := obj["subject"].(string); ok && subject != "" {
		hasSubject := false
		for _, l := range lines {
			if strings.HasPrefix(strings.ToLower(l), "subject:") {
				hasSubject = true
				break
			}
		}
		if !hasSubject {
			lines = append([]string{"Subject: " + subject}, lines...)
		}
	}
	if from, ok := obj["from"].(map[string]interface{}); ok {
		if ea, ok := from["emailAddress"].(map[string]interface{}); ok {
			addr, _ := ea["address"].(string)
			name, _ := ea["name"].(string)
			if addr != "" {
				hasFrom := false
				for _, l := range lines {
					if strings.HasPrefix(strings.ToLower(l), "from:") {
						hasFrom = true
						break
					}
				}
				if !hasFrom {
					if name != "" {
						lines = append([]string{"From: " + name + " <" + addr + ">"}, lines...)
					} else {
						lines = append([]string{"From: " + addr}, lines...)
					}
				}
			}
		}
	}

	if len(lines) >= 2 {
		return strings.Join(lines, "\r\n")
	}
	return ""
}

func extractGmailAPIHeaders(obj map[string]interface{}) string {
	payload, ok := obj["payload"].(map[string]interface{})
	if !ok {
		return ""
	}
	headersRaw, ok := payload["headers"].([]interface{})
	if !ok {
		return ""
	}
	var lines []string
	for _, item := range headersRaw {
		header, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := header["name"].(string)
		value, _ := header["value"].(string)
		if name != "" {
			lines = append(lines, name+": "+value)
		}
	}
	if len(lines) >= 2 {
		return strings.Join(lines, "\r\n")
	}
	return ""
}

func extractPostmarkHeaders(obj map[string]interface{}) string {
	_, hasMessageID := obj["MessageID"]
	headersRaw, hasHeaders := obj["Headers"]
	if !hasMessageID || !hasHeaders {
		return ""
	}
	arr, ok := headersRaw.([]interface{})
	if !ok {
		return ""
	}
	var lines []string
	for _, item := range arr {
		header, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := header["Name"].(string)
		value, _ := header["Value"].(string)
		if name != "" {
			lines = append(lines, name+": "+value)
		}
	}

	if from, ok := obj["From"].(string); ok && from != "" {
		lines = append([]string{"From: " + from}, lines...)
	}
	if to, ok := obj["To"].(string); ok && to != "" {
		lines = append(lines, "To: "+to)
	}
	if subject, ok := obj["Subject"].(string); ok && subject != "" {
		lines = append(lines, "Subject: "+subject)
	}
	if msgID, ok := obj["MessageID"].(string); ok && msgID != "" {
		lines = append(lines, "Message-ID: "+msgID)
	}

	if len(lines) >= 2 {
		return strings.Join(lines, "\r\n")
	}
	return ""
}

func extractSendGridHeaders(obj map[string]interface{}) string {
	headersRaw, ok := obj["headers"]
	if !ok {
		return ""
	}
	headersMap, ok := headersRaw.(map[string]interface{})
	if !ok {
		return ""
	}
	var lines []string
	for name, val := range headersMap {
		value, _ := val.(string)
		lines = append(lines, name+": "+value)
	}

	if from, ok := obj["from"].(map[string]interface{}); ok {
		email, _ := from["email"].(string)
		name, _ := from["name"].(string)
		if email != "" {
			if name != "" {
				lines = append([]string{"From: " + name + " <" + email + ">"}, lines...)
			} else {
				lines = append([]string{"From: " + email}, lines...)
			}
		}
	}
	if subject, ok := obj["subject"].(string); ok && subject != "" {
		lines = append(lines, "Subject: "+subject)
	}

	if len(lines) >= 2 {
		return strings.Join(lines, "\r\n")
	}
	return ""
}

func extractMailgunHeaders(obj map[string]interface{}) string {
	msgHeaders, ok := obj["message-headers"]
	if !ok {
		return ""
	}
	arr, ok := msgHeaders.([]interface{})
	if !ok {
		return ""
	}
	var lines []string
	for _, item := range arr {
		pair, ok := item.([]interface{})
		if !ok || len(pair) < 2 {
			continue
		}
		name, _ := pair[0].(string)
		value, _ := pair[1].(string)
		if name != "" {
			lines = append(lines, name+": "+value)
		}
	}
	if len(lines) >= 2 {
		return strings.Join(lines, "\r\n")
	}
	return ""
}

func extractGenericJSONHeaders(obj map[string]interface{}) string {
	for _, key := range []string{"headers", "Headers", "email_headers", "emailHeaders", "message_headers", "raw_headers", "rawHeaders"} {
		val, ok := obj[key]
		if !ok {
			continue
		}

		if str, ok := val.(string); ok && hasHeaderFields(str) {
			return str
		}

		if arr, ok := val.([]interface{}); ok {
			var lines []string
			for _, item := range arr {
				if header, ok := item.(map[string]interface{}); ok {
					name := firstString(header, "name", "Name", "key", "Key", "header")
					value := firstString(header, "value", "Value", "val")
					if name != "" {
						lines = append(lines, name+": "+value)
					}
				}
			}
			if len(lines) >= 2 {
				return strings.Join(lines, "\r\n")
			}
		}

		if headerMap, ok := val.(map[string]interface{}); ok {
			var lines []string
			for name, v := range headerMap {
				value, _ := v.(string)
				lines = append(lines, name+": "+value)
			}
			if len(lines) >= 2 {
				return strings.Join(lines, "\r\n")
			}
		}
	}

	if raw, ok := obj["raw"].(string); ok && hasHeaderFields(raw) {
		return raw
	}
	if raw, ok := obj["Raw"].(string); ok && hasHeaderFields(raw) {
		return raw
	}

	return ""
}

func firstString(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok {
			return v
		}
	}
	return ""
}

func isMboxFormat(data string) bool {
	lines := strings.SplitN(data, "\n", 5)
	if len(lines) < 2 {
		return false
	}
	firstLine := lines[0]
	if !strings.HasPrefix(firstLine, "From ") {
		return false
	}
	for _, line := range lines[1:] {
		if hasHeaderFields(line) {
			return true
		}
	}
	return false
}

func extractFromMbox(data string) *DetectedFormat {
	lines := strings.SplitN(data, "\n", 2)
	if len(lines) < 2 {
		return &DetectedFormat{Format: "mbox", Error: "MBOX file appears empty."}
	}
	remainder := lines[1]

	nextMsg := strings.Index(remainder, "\nFrom ")
	if nextMsg > 0 {
		remainder = remainder[:nextMsg]
	}

	return &DetectedFormat{
		Format:  "mbox",
		Headers: strings.TrimSpace(remainder),
	}
}
