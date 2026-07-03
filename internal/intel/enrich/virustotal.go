package enrich

import (
	"encoding/json"
	"fmt"
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

var virusTotalSpec = providerSpec{
	envVar: "SHARDLURE_VT_KEY",
	buildReq: func(ip, key string) (string, map[string]string) {
		return "https://www.virustotal.com/api/v3/ip_addresses/" + ip,
			map[string]string{
				"Accept":   "application/json",
				"x-apikey": key,
			}
	},
	parse: parseVirusTotal,
}

// parseVirusTotal maps the v3 IP payload onto a Result. Split out from the
// HTTP wrapper so it can be unit-tested without a network round-trip.
func parseVirusTotal(raw []byte, ip string) Result {
	var parsed vtResp
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return Result{Configured: true, Error: err.Error()}
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
	}
}
