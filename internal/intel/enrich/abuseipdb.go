package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

func fetchAbuseIPDB(ctx context.Context, hc *http.Client, ip string) (Result, error) {
	key := envKey("SHARDLURE_ABUSEIPDB_KEY")
	if key == "" {
		return Result{Configured: false, Verdict: "unknown"}, nil
	}

	url := "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip + "&maxAgeInDays=90"
	var parsed abuseIPDBResp
	raw, err := httpJSON(ctx, hc, url, map[string]string{
		"Accept": "application/json",
		"Key":    key,
	}, &parsed)
	if err != nil {
		return Result{Configured: true}, err
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
	if d.LastReportedAt != "" {
		summary += ", last " + d.LastReportedAt[:10]
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
	}, nil
}
