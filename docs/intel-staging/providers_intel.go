//go:build intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Full intelligence implementation.
package analyzer

const (
	nameOnDMARC       = "OnDMARC"
	nameDMARCReport   = "DMARC Report"
	nameDMARCLY       = "DMARCLY"
	nameDmarcian      = "Dmarcian"
	nameSendmarc      = "Sendmarc"
	nameProofpoint    = "Proofpoint"
	nameValimailEnf   = "Valimail Enforce"
	nameProofpointEFD = "Proofpoint EFD"
	namePowerDMARC    = "PowerDMARC"
	nameMailhardener  = "Mailhardener"
	nameFraudmarc     = "Fraudmarc"
	nameEasyDMARC     = "EasyDMARC"
	nameDMARCAdvisor  = "DMARC Advisor"
	nameRedSift       = "Red Sift"

	vendorRedSift    = "Red Sift"
	vendorValimail   = "Valimail"
	vendorDmarcian   = "Dmarcian"
	vendorSendmarc   = "Sendmarc"
	vendorProofpoint = "Proofpoint"
	vendorDMARCLY    = "DMARCLY"
	vendorPowerDMARC = "PowerDMARC"
	vendorFraudmarc  = "Fraudmarc"
	vendorEasyDMARC  = "EasyDMARC"
	vendorDMARCAdv   = "DMARC Advisor"
	vendorMailharden = "Mailhardener"
	vendorDMARCRpt   = "DMARC Report"
	vendorFortra     = "Fortra"
	vendorMimecast   = "Mimecast"
	vendorActiveCamp = "ActiveCampaign"

	nameAkamai     = "Akamai"
	nameSalesforce = "Salesforce"
	nameHubSpot    = "HubSpot"
	nameHeroku     = "Heroku"

	domainOndmarc  = "ondmarc.com"
	domainRedsift  = "redsift.cloud"
	domainDmarcian = "dmarcian.com"
	domainSendmarc = "sendmarc.com"
)

// TODO: Populate with full provider intelligence from private repo.
var dmarcMonitoringProviders = map[string]managementProviderInfo{}

// TODO: Populate with full provider intelligence from private repo.
var spfFlatteningProviders = map[string]spfFlatteningInfo{}

// TODO: Populate with full provider intelligence from private repo.
var hostedDKIMProviders = map[string]hostedDKIMInfo{}

// TODO: Populate with full provider intelligence from private repo.
var dynamicServicesProviders = map[string]dynamicServiceInfo{}

// TODO: Populate with full provider intelligence from private repo.
var dynamicServicesZones = map[string]string{}

// TODO: Populate with full provider intelligence from private repo.
var cnameProviderMap = map[string]cnameProviderInfo{}

// TODO: Replace with full intelligence implementation from private repo.
func isHostedEmailProvider(_ string) bool {
	return true
}

// TODO: Replace with full intelligence implementation from private repo.
func isBIMICapableProvider(_ string) bool {
	return false
}

// TODO: Replace with full intelligence implementation from private repo.
func isKnownDKIMProvider(_ interface{}) bool {
	return false
}
