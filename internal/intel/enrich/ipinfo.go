package enrich

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// IPinfo provides ASN/org/geo plus privacy flags (hosting/proxy/vpn/tor) on
// the paid tiers. It populates the ASN/ASOwner/Country fields the Result
// struct already carries but few other providers fill, and the privacy block
// flags anonymized infra. Requires a token in SHARDLURE_IPINFO_KEY.
//
// Docs: https://ipinfo.io/developers
type ipinfoResp struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
	Org     string `json:"org"` // e.g. "AS15169 Google LLC"
	ASN     struct {
		ASN    string `json:"asn"`
		Name   string `json:"name"`
		Domain string `json:"domain"`
	} `json:"asn"`
	Privacy struct {
		VPN     bool `json:"vpn"`
		Proxy   bool `json:"proxy"`
		Tor     bool `json:"tor"`
		Relay   bool `json:"relay"`
		Hosting bool `json:"hosting"`
	} `json:"privacy"`
}

func fetchIPinfo(ctx context.Context, hc *http.Client, ip string) (Result, error) {
	key := envKey("SHARDLURE_IPINFO_KEY")
	if key == "" {
		return Result{Configured: false, Verdict: "unknown"}, nil
	}
	url := "https://ipinfo.io/" + ip + "/json?token=" + key
	// out=nil: parseIPinfo owns the decode (avoids a redundant double-decode).
	raw, err := httpJSON(ctx, hc, url, map[string]string{"Accept": "application/json"}, nil)
	if err != nil {
		return Result{Configured: true}, err
	}
	return parseIPinfo(raw, ip), nil
}

// parseIPinfo maps the IPinfo response onto a Result. Split out for testing.
func parseIPinfo(raw []byte, ip string) Result {
	var p ipinfoResp
	if err := json.Unmarshal(raw, &p); err != nil {
		return Result{Configured: true, Error: err.Error()}
	}

	// ASN can arrive in the structured asn{} block (paid) or embedded in org
	// (e.g. "AS15169 Google LLC"). Prefer the structured form.
	asn, asOwner := p.ASN.ASN, p.ASN.Name
	if asn == "" && p.Org != "" {
		asn, asOwner = splitASN(p.Org)
	}

	tags := []string{}
	if p.Privacy.Hosting {
		tags = append(tags, "hosting")
	}
	if p.Privacy.Proxy {
		tags = append(tags, "proxy")
	}
	if p.Privacy.VPN {
		tags = append(tags, "vpn")
	}
	if p.Privacy.Tor {
		tags = append(tags, "tor")
	}
	if p.Privacy.Relay {
		tags = append(tags, "relay")
	}

	// IPinfo is primarily a context/geo source, not a reputation scorer.
	// Anonymized infra (proxy/vpn/tor) is mildly suspicious in a honeypot
	// context; hosting alone is neutral (lots of legit scanners run on VPS).
	verdict := "unknown"
	if p.Privacy.Proxy || p.Privacy.VPN || p.Privacy.Tor || p.Privacy.Relay {
		verdict = "suspicious"
	}

	var loc []string
	for _, s := range []string{p.City, p.Region, p.Country} {
		if s != "" {
			loc = append(loc, s)
		}
	}
	summary := asOwner
	if len(loc) > 0 {
		if summary != "" {
			summary += " · "
		}
		summary += strings.Join(loc, ", ")
	}
	if len(tags) > 0 {
		summary += " [" + strings.Join(tags, ",") + "]"
	}

	return Result{
		Configured: true,
		Verdict:    verdict,
		ASN:        asn,
		ASOwner:    asOwner,
		Country:    p.Country,
		Tags:       tags,
		Summary:    summary,
		URL:        "https://ipinfo.io/" + ip,
		Raw:        json.RawMessage(raw),
	}
}
