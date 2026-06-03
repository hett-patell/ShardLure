package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// AlienVault OTX (Open Threat Exchange) general reputation endpoint. The
// "pulse" count is the headline signal: pulses are community-curated threat
// reports referencing the indicator, so a high count strongly implies the IP
// is part of known malicious infrastructure.
//
// Requires a free API key in SHARDLURE_OTX_KEY (sent as the X-OTX-API-KEY
// header). Docs: https://otx.alienvault.com/api
type otxResp struct {
	PulseInfo struct {
		Count  int `json:"count"`
		Pulses []struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		} `json:"pulses"`
	} `json:"pulse_info"`
	ASN     string `json:"asn"`
	Country string `json:"country_name"`
	City    string `json:"city"`
}

func fetchOTX(ctx context.Context, hc *http.Client, ip string) (Result, error) {
	key := envKey("SHARDLURE_OTX_KEY")
	if key == "" {
		return Result{Configured: false, Verdict: "unknown"}, nil
	}
	url := "https://otx.alienvault.com/api/v1/indicators/IPv4/" + ip + "/general"
	var parsed otxResp
	raw, err := httpJSON(ctx, hc, url, map[string]string{
		"Accept":        "application/json",
		"X-OTX-API-KEY": key,
	}, &parsed)
	if err != nil {
		return Result{Configured: true}, err
	}
	return parseOTX(raw, ip), nil
}

// parseOTX maps the OTX general response onto a Result. Split out for testing.
func parseOTX(raw []byte, ip string) Result {
	var p otxResp
	if err := json.Unmarshal(raw, &p); err != nil {
		return Result{Configured: true, Error: err.Error()}
	}

	count := p.PulseInfo.Count
	verdict := "unknown"
	switch {
	case count >= 5:
		verdict = "malicious"
	case count >= 1:
		verdict = "suspicious"
	default:
		verdict = "benign"
	}

	// Surface up to a few pulse names + their tags so the operator sees what
	// the IP is associated with without opening the OTX UI.
	tags := map[string]struct{}{}
	var names []string
	for i, pulse := range p.PulseInfo.Pulses {
		if i < 3 && pulse.Name != "" {
			names = append(names, pulse.Name)
		}
		for _, t := range pulse.Tags {
			if t != "" {
				tags[strings.ToLower(t)] = struct{}{}
			}
		}
	}
	tagList := make([]string, 0, len(tags))
	for t := range tags {
		tagList = append(tagList, t)
	}

	summary := fmt.Sprintf("%d OTX pulse(s)", count)
	if len(names) > 0 {
		summary += ": " + strings.Join(names, "; ")
	}

	// ASN in OTX comes as e.g. "AS12345 Some ISP"; split the number off.
	asn, asOwner := splitASN(p.ASN)

	return Result{
		Configured: true,
		Score:      intPtr(min100(count * 20)),
		Verdict:    verdict,
		ASN:        asn,
		ASOwner:    asOwner,
		Country:    p.Country,
		Tags:       tagList,
		Summary:    summary,
		URL:        "https://otx.alienvault.com/indicator/ip/" + ip,
		Raw:        json.RawMessage(raw),
	}
}

// splitASN turns "AS12345 Some ISP" into ("AS12345", "Some ISP").
func splitASN(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	if i := strings.IndexByte(s, ' '); i > 0 {
		return s[:i], strings.TrimSpace(s[i+1:])
	}
	return s, ""
}

func min100(v int) int {
	if v > 100 {
		return 100
	}
	if v < 0 {
		return 0
	}
	return v
}
