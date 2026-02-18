// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

func ExportClassifyAllQualifier(spfRecord string) *string {
	p, _, _ := classifyAllQualifier(spfRecord)
	return p
}

func ExportCountSPFLookups(spfRecord string) int {
	count, _, _, _, _, _, _ := parseSPFMechanisms(spfRecord)
	return count
}

func ExportBuildSPFVerdict(lookupCount int, permissiveness *string, noMailIntent bool, validSPF, spfLike []string) (string, string) {
	return buildSPFVerdict(lookupCount, permissiveness, noMailIntent, validSPF, spfLike)
}

func ExportParseSPFMechanisms(spfRecord string) (int, []string, []string, *string, *string, []string, bool) {
	return parseSPFMechanisms(spfRecord)
}

func ExportClassifySPFRecords(records []string) ([]string, []string) {
	return classifySPFRecords(records)
}

func ExportBuildEmailAnswer(isNoMailDomain bool, dmarcPolicy string, dmarcPct int, nullMX bool, hasSPF, hasDMARC bool) string {
	ps := protocolState{
		isNoMailDomain: isNoMailDomain || nullMX,
		dmarcPolicy:    dmarcPolicy,
		dmarcPct:       dmarcPct,
	}
	return buildEmailAnswer(ps, hasSPF, hasDMARC)
}

func ExportBuildEmailAnswerStructured(isNoMailDomain bool, dmarcPolicy string, dmarcPct int, nullMX bool, hasSPF, hasDMARC bool) map[string]string {
	ps := protocolState{
		isNoMailDomain: isNoMailDomain || nullMX,
		dmarcPolicy:    dmarcPolicy,
		dmarcPct:       dmarcPct,
	}
	return buildEmailAnswerStructured(ps, hasSPF, hasDMARC)
}
