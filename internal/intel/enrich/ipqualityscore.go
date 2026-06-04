package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// IPQualityScore proxy/fraud detection. Its fraud_score (0-100) plus the
// proxy/VPN/TOR/bot flags are good at unmasking anonymized attacker infra —
// the kind that a pure abuse-report provider (AbuseIPDB) can miss because the
// exit node is fresh. Requires a free-tier key in SHARDLURE_IPQS_KEY; the key
// is part of the URL path per IPQS's API.
//
// Docs: https://www.ipqualityscore.com/documentation/proxy-detection-api/overview
type ipqsResp struct {
	Success     bool    `json:"success"`
	Message     string  `json:"message"`
	FraudScore  int     `json:"fraud_score"`
	CountryCode string  `json:"country_code"`
	ISP         string  `json:"ISP"`
	ASN         int     `json:"ASN"`
	Proxy       bool    `json:"proxy"`
	VPN         bool    `json:"vpn"`
	Tor         bool    `json:"tor"`
	IsCrawler   bool    `json:"is_crawler"`
	BotStatus   bool    `json:"bot_status"`
	RecentAbuse bool    `json:"recent_abuse"`
}

func fetchIPQualityScore(ctx context.Context, hc *http.Client, ip string) (Result, error) {
	key := envKey("SHARDLURE_IPQS_KEY")
	if key == "" {
		return Result{Configured: false, Verdict: "unknown"}, nil
	}
	// strictness=1 balances false positives; key is a path segment.
	url := "https://ipqualityscore.com/api/json/ip/" + key + "/" + ip + "?strictness=1"
	// out=nil: parseIPQS owns the decode (avoids a redundant double-decode).
	raw, err := httpJSON(ctx, hc, url, map[string]string{"Accept": "application/json"}, nil)
	if err != nil {
		return Result{Configured: true}, err
	}
	return parseIPQS(raw, ip), nil
}

// parseIPQS maps the IPQS response onto a Result. Split out for testing.
func parseIPQS(raw []byte, ip string) Result {
	var p ipqsResp
	if err := json.Unmarshal(raw, &p); err != nil {
		return Result{Configured: true, Error: err.Error()}
	}
	if !p.Success {
		msg := p.Message
		if msg == "" {
			msg = "IPQualityScore request unsuccessful"
		}
		return Result{Configured: true, Error: msg}
	}

	score := p.FraudScore
	verdict := "benign"
	switch {
	case score >= 85:
		verdict = "malicious"
	case score >= 50:
		verdict = "suspicious"
	}

	tags := []string{}
	if p.Proxy {
		tags = append(tags, "proxy")
	}
	if p.VPN {
		tags = append(tags, "vpn")
	}
	if p.Tor {
		tags = append(tags, "tor")
	}
	if p.IsCrawler {
		tags = append(tags, "crawler")
	}
	if p.BotStatus {
		tags = append(tags, "bot")
	}
	if p.RecentAbuse {
		tags = append(tags, "recent-abuse")
	}

	asn := ""
	if p.ASN > 0 {
		asn = fmt.Sprintf("AS%d", p.ASN)
	}

	summary := fmt.Sprintf("fraud score=%d/100", score)
	if len(tags) > 0 {
		summary += " [" + strings.Join(tags, ",") + "]"
	}

	return Result{
		Configured: true,
		Score:      intPtr(score),
		Verdict:    verdict,
		ASN:        asn,
		ASOwner:    p.ISP,
		Country:    p.CountryCode,
		Tags:       tags,
		Summary:    summary,
		URL:        "https://www.ipqualityscore.com/ip-reputation-check/lookup/" + ip,
		Raw:        json.RawMessage(raw),
	}
}
