// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import "strings"

const (
	featDDoSProtection       = "DDoS protection"
	featAnycast              = "Anycast"
	featBrandProtection      = "Brand protection"
	featEnterpriseManagement = "Enterprise management"
	featEnterpriseSecurity   = "Enterprise security"
	featGlobalAnycast        = "Global Anycast"
	featGlobalInfra          = "Global infrastructure"
	featSelfManagedInfra     = "Self-managed infrastructure"
	featProtectedInfra       = "Protected infrastructure"
	featGovSecurityStandards = "Government security standards"
	detMTASTS                = "MTA-STS"

	tierEnterprise = "enterprise"
	tierManaged    = "managed"
)

type providerInfo struct {
	Name     string
	Tier     string
	Features []string
}

type infraMatch struct {
	provider *providerInfo
	tier     string
}

type dsDetection struct {
	info         dynamicServiceInfo
	capabilities []string
}

func parentZone(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return ""
	}
	return strings.Join(parts[1:], ".")
}

func applyHostingDefaults(hosting, dnsHosting, emailHosting string, isNoMail bool) (string, string, string) {
	if hosting == "" {
		hosting = "Unknown"
	}
	if dnsHosting == "" {
		dnsHosting = "Unknown"
	}
	if isNoMail && emailHosting == "" {
		emailHosting = "No Mail Domain"
	} else if emailHosting == "" {
		emailHosting = "Unknown"
	}
	return hosting, dnsHosting, emailHosting
}

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func zoneCapability(zoneKey string) string {
	return zoneKey + " management"
}

func addOrMergeProvider(providers map[string]map[string]any, info *managementProviderInfo, detectedFrom, source string) {
}

func extractMailtoDomains(ruaStr string) []string {
	return nil
}
