package enrich

import (
	"encoding/json"
	"fmt"
	"strings"
)

// AbuseIPDB v2 /check response shape (only the fields we render).
// Full schema: https://docs.abuseipdb.com/#check-endpoint
type abuseIPDBResp struct {
	Data struct {
		IPAddress            string   `json:"ipAddress"`
		AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
		CountryCode          string   `json:"countryCode"`
		ISP                  string   `json:"isp"`
		Domain               string   `json:"domain"`
		UsageType            string   `json:"usageType"`
		TotalReports         int      `json:"totalReports"`
		LastReportedAt       string   `json:"lastReportedAt"`
		Hostnames            []string `json:"hostnames"`
	} `json:"data"`
}

var abuseIPDBSpec = providerSpec{
	envVar: "SHARDLURE_ABUSEIPDB_KEY",
	buildReq: func(ip, key string) (string, map[string]string) {
		return "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip + "&maxAgeInDays=90",
			map[string]string{
				"Accept": "application/json",
				"Key":    key,
			}
	},
	parse: parseAbuseIPDB,
}

// parseAbuseIPDB maps the /check payload onto a Result. Split out from the
// HTTP wrapper so it can be unit-tested without a network round-trip.
func parseAbuseIPDB(raw []byte, ip string) Result {
	var parsed abuseIPDBResp
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return Result{Configured: true, Error: err.Error()}
	}

	d := parsed.Data
	score := d.AbuseConfidenceScore
	verdict := "benign"
	switch {
	case score >= 75:
		verdict = "malicious"
	case score >= 25:
		verdict = "suspicious"
	}

	tags := []string{}
	if d.UsageType != "" {
		tags = append(tags, strings.ToLower(strings.ReplaceAll(d.UsageType, " ", "-")))
	}
	for _, h := range d.Hostnames {
		if h != "" {
			tags = append(tags, h)
		}
	}

	summary := fmt.Sprintf("%d reports in 90d, score=%d/100", d.TotalReports, score)
	if n := len(d.LastReportedAt); n >= 10 {
		summary += ", last " + d.LastReportedAt[:10]
	} else if n > 0 {
		summary += ", last " + d.LastReportedAt
	}

	return Result{
		Configured: true,
		Score:      intPtr(score),
		Verdict:    verdict,
		Country:    d.CountryCode,
		ASOwner:    d.ISP,
		Tags:       tags,
		Summary:    summary,
		URL:        "https://www.abuseipdb.com/check/" + ip,
		Raw:        json.RawMessage(raw),
	}
}
