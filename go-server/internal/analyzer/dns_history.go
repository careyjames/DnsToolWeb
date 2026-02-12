package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"
)

type stHistoryResponse struct {
	Records []stHistoryRecord `json:"records"`
	Pages   int               `json:"pages"`
	Type    string            `json:"type"`
}

type stHistoryRecord struct {
	FirstSeen     string           `json:"first_seen"`
	LastSeen      *string          `json:"last_seen"`
	Organizations []string         `json:"organizations"`
	Values        []stHistoryValue `json:"values"`
}

type stHistoryValue struct {
	IP      string `json:"ip"`
	IPCount int    `json:"ip_count"`
	Host    string `json:"host,omitempty"`
}

type dnsChangeEvent struct {
	RecordType  string
	Value       string
	Action      string
	Date        string
	Org         string
	Description string
	DaysAgo     int
}

func FetchDNSHistory(ctx context.Context, domain string) map[string]any {
	initSecurityTrails()
	if !securityTrailsEnabled {
		return map[string]any{
			"available":    false,
			"changes":      []map[string]any{},
			"total_events": float64(0),
			"source":       "",
		}
	}

	recordTypes := []string{"a", "mx", "ns"}
	var allChanges []dnsChangeEvent

	for _, rtype := range recordTypes {
		changes := fetchHistoryForType(ctx, domain, rtype)
		allChanges = append(allChanges, changes...)
	}

	sort.Slice(allChanges, func(i, j int) bool {
		return allChanges[i].Date > allChanges[j].Date
	})

	maxChanges := 15
	if len(allChanges) > maxChanges {
		allChanges = allChanges[:maxChanges]
	}

	changesMaps := make([]map[string]any, len(allChanges))
	for i, ch := range allChanges {
		changesMaps[i] = map[string]any{
			"record_type": ch.RecordType,
			"value":       ch.Value,
			"action":      ch.Action,
			"date":        ch.Date,
			"org":         ch.Org,
			"description": ch.Description,
			"days_ago":    float64(ch.DaysAgo),
		}
	}

	return map[string]any{
		"available":    len(allChanges) > 0,
		"changes":      changesMaps,
		"total_events": float64(len(allChanges)),
		"source":       "SecurityTrails",
	}
}

func fetchHistoryForType(ctx context.Context, domain, rtype string) []dnsChangeEvent {
	url := fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/%s", domain, rtype)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		slog.Warn("SecurityTrails history: failed to create request", "domain", domain, "type", rtype, "error", err)
		return nil
	}
	req.Header.Set("APIKEY", securityTrailsAPIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := securityTrailsHTTPClient.Do(req)
	if err != nil {
		slog.Warn("SecurityTrails history: request failed", "domain", domain, "type", rtype, "error", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		slog.Warn("SecurityTrails history: rate limited", "domain", domain, "type", rtype)
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		slog.Warn("SecurityTrails history: unexpected status", "domain", domain, "type", rtype, "status", resp.StatusCode)
		return nil
	}

	var histResp stHistoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&histResp); err != nil {
		slog.Warn("SecurityTrails history: parse failed", "domain", domain, "type", rtype, "error", err)
		return nil
	}

	now := time.Now()
	upperType := strings.ToUpper(rtype)
	var changes []dnsChangeEvent

	for _, rec := range histResp.Records {
		value := extractHistoryValue(rec, rtype)
		if value == "" {
			continue
		}

		firstSeen, _ := time.Parse("2006-01-02", rec.FirstSeen)

		var daysActive int
		var daysSinceGone int

		if rec.LastSeen != nil {
			lastSeen, _ := time.Parse("2006-01-02", *rec.LastSeen)
			daysActive = int(lastSeen.Sub(firstSeen).Hours() / 24)
			daysSinceGone = int(now.Sub(lastSeen).Hours() / 24)
		} else {
			daysActive = int(now.Sub(firstSeen).Hours() / 24)
		}

		orgLabel := ""
		if len(rec.Organizations) > 0 {
			orgLabel = rec.Organizations[0]
		}

		changes = append(changes, dnsChangeEvent{
			RecordType:  upperType,
			Value:       value,
			Action:      "added",
			Date:        rec.FirstSeen,
			Org:         orgLabel,
			Description: buildChangeDescription(upperType, value, "added", orgLabel, daysActive),
			DaysAgo:     int(now.Sub(firstSeen).Hours() / 24),
		})

		if rec.LastSeen != nil {
			lastSeen, _ := time.Parse("2006-01-02", *rec.LastSeen)
			changes = append(changes, dnsChangeEvent{
				RecordType:  upperType,
				Value:       value,
				Action:      "removed",
				Date:        *rec.LastSeen,
				Org:         orgLabel,
				Description: buildChangeDescription(upperType, value, "removed", orgLabel, daysSinceGone),
				DaysAgo:     int(now.Sub(lastSeen).Hours() / 24),
			})
		}
	}

	slog.Info("SecurityTrails history: fetched", "domain", domain, "type", rtype, "events", len(changes))
	return changes
}

func extractHistoryValue(rec stHistoryRecord, rtype string) string {
	if len(rec.Values) == 0 {
		return ""
	}
	v := rec.Values[0]
	switch rtype {
	case "a", "aaaa":
		return v.IP
	case "mx", "ns":
		if v.Host != "" {
			return v.Host
		}
		return v.IP
	default:
		if v.IP != "" {
			return v.IP
		}
		return v.Host
	}
}

func buildChangeDescription(rtype, value, action, org string, daysMetric int) string {
	timeLabel := formatDaysAgo(daysMetric)

	switch action {
	case "added":
		if org != "" {
			return fmt.Sprintf("%s record %s (%s) appeared %s", rtype, value, org, timeLabel)
		}
		return fmt.Sprintf("%s record %s appeared %s", rtype, value, timeLabel)
	case "removed":
		if org != "" {
			return fmt.Sprintf("%s record %s (%s) was removed %s", rtype, value, org, timeLabel)
		}
		return fmt.Sprintf("%s record %s was removed %s", rtype, value, timeLabel)
	default:
		return fmt.Sprintf("%s record %s changed %s", rtype, value, timeLabel)
	}
}

func formatDaysAgo(days int) string {
	if days == 0 {
		return "today"
	}
	if days == 1 {
		return "yesterday"
	}
	if days < 7 {
		return fmt.Sprintf("%d days ago", days)
	}
	if days < 30 {
		weeks := days / 7
		if weeks == 1 {
			return "1 week ago"
		}
		return fmt.Sprintf("%d weeks ago", weeks)
	}
	if days < 365 {
		months := days / 30
		if months == 1 {
			return "1 month ago"
		}
		return fmt.Sprintf("%d months ago", months)
	}
	years := days / 365
	if years == 1 {
		return "1 year ago"
	}
	return fmt.Sprintf("%d years ago", years)
}
