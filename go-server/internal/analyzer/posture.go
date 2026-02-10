package analyzer

func (a *Analyzer) CalculatePosture(results map[string]any) map[string]any {
	score := 0
	var issues []string

	spf := getMapResult(results, "spf_analysis")
	dmarc := getMapResult(results, "dmarc_analysis")
	dkim := getMapResult(results, "dkim_analysis")
	mtaSts := getMapResult(results, "mta_sts_analysis")
	tlsrpt := getMapResult(results, "tlsrpt_analysis")
	bimi := getMapResult(results, "bimi_analysis")
	dane := getMapResult(results, "dane_analysis")
	caa := getMapResult(results, "caa_analysis")
	dnssec := getMapResult(results, "dnssec_analysis")

	switch spf["status"] {
	case "success":
		score += 15
	case "warning":
		score += 8
		issues = append(issues, "SPF needs attention")
	default:
		issues = append(issues, "No SPF record")
	}

	switch dmarc["status"] {
	case "success":
		score += 20
		if dmarc["policy"] == "reject" {
			score += 5
		}
	case "warning":
		score += 10
		issues = append(issues, "DMARC needs strengthening")
	default:
		issues = append(issues, "No DMARC record")
	}

	switch dkim["status"] {
	case "success":
		score += 15
	case "warning", "partial":
		score += 8
		issues = append(issues, "DKIM issues detected")
	case "info":
		score += 3
	default:
		issues = append(issues, "No DKIM found")
	}

	if mtaSts["status"] == "success" {
		score += 10
	} else {
		issues = append(issues, "No MTA-STS")
	}

	if tlsrpt["status"] == "success" {
		score += 5
	}

	if bimi["status"] == "success" {
		score += 5
	}

	if dane["has_dane"] == true {
		score += 10
	}

	if caa["status"] == "success" {
		score += 10
	} else {
		issues = append(issues, "No CAA records")
	}

	if dnssec["status"] == "success" {
		score += 10
	} else {
		issues = append(issues, "No DNSSEC")
	}

	if score > 100 {
		score = 100
	}

	var grade, label, color string
	switch {
	case score >= 90:
		grade = "A+"
		label = "Excellent"
		color = "success"
	case score >= 80:
		grade = "A"
		label = "Very Good"
		color = "success"
	case score >= 70:
		grade = "B"
		label = "Good"
		color = "info"
	case score >= 55:
		grade = "C"
		label = "Fair"
		color = "warning"
	case score >= 40:
		grade = "D"
		label = "Needs Improvement"
		color = "warning"
	default:
		grade = "F"
		label = "Critical"
		color = "danger"
	}

	return map[string]any{
		"score":  score,
		"grade":  grade,
		"label":  label,
		"issues": issues,
		"color":  color,
	}
}
