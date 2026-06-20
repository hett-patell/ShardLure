package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// VirusTotal v3 /ip_addresses/{ip} response (subset).
// Full docs: https://docs.virustotal.com/reference/ip-info
type vtResp struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
			AsOwner    string `json:"as_owner"`
			ASN        int    `json:"asn"`
			Country    string `json:"country"`
			Network    string `json:"network"`
			Reputation int    `json:"reputation"`
		} `json:"attributes"`
	} `json:"data"`
}

func fetchVirusTotal(ctx context.Context, hc *http.Client, ip string) (Result, error) {
	key := envKey("SHARDLURE_VT_KEY")
	if key == "" {
		return Result{Configured: false, Verdict: "unknown"}, nil
	}

	url := "https://www.virustotal.com/api/v3/ip_addresses/" + ip
	var parsed vtResp
	raw, err := httpJSON(ctx, hc, url, map[string]string{
		"Accept":   "application/json",
		"x-apikey": key,
	}, &parsed)
	if err != nil {
		return Result{Configured: true}, err
	}

	a := parsed.Data.Attributes
	stats := a.LastAnalysisStats
	totalEng := stats.Harmless + stats.Malicious + stats.Suspicious + stats.Undetected
	verdict := "benign"
	switch {
	case stats.Malicious >= 3:
		verdict = "malicious"
	case stats.Malicious > 0 || stats.Suspicious >= 2:
		verdict = "suspicious"
	case totalEng == 0:
		verdict = "unknown"
	}

	tags := []string{}
	if a.Network != "" {
		tags = append(tags, a.Network)
	}

	summary := fmt.Sprintf("%d/%d engines flagged malicious", stats.Malicious, totalEng)
	if a.Reputation != 0 {
		summary += ", reputation=" + strconv.Itoa(a.Reputation)
	}

	asn := ""
	if a.ASN != 0 {
		asn = "AS" + strconv.Itoa(a.ASN)
	}

	return Result{
		Configured: true,
		Score:      intPtr(stats.Malicious),
		Verdict:    verdict,
		ASN:        asn,
		ASOwner:    a.AsOwner,
		Country:    a.Country,
		Tags:       tags,
		Summary:    summary,
		URL:        "https://www.virustotal.com/gui/ip-address/" + ip,
		Raw:        json.RawMessage(raw),
	}, nil
}
