package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Shodan InternetDB is a free, keyless endpoint that returns the open
// ports, detected products (CPEs), known vulnerabilities and tags Shodan
// has observed for an IP. It is rate-limited but requires no account, so
// like GreyNoise community we always mark it Configured=true.
//
// Docs: https://internetdb.shodan.io/  (GET https://internetdb.shodan.io/<ip>)
//
// A 404 means "Shodan has no data for this IP", which for a freshly-seen
// attacker is common and benign — we surface it as an empty-but-clean
// result rather than an error.
type shodanResp struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	CPEs      []string `json:"cpes"`
	Hostnames []string `json:"hostnames"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
}

func fetchShodan(ctx context.Context, hc *http.Client, ip string) (Result, error) {
	url := "https://internetdb.shodan.io/" + ip
	var parsed shodanResp
	raw, err := httpJSON(ctx, hc, url, map[string]string{"Accept": "application/json"}, &parsed)
	if err != nil {
		if err.Error() == "404 Not Found" {
			return Result{
				Configured: true,
				Verdict:    "unknown",
				Summary:    "no Shodan observations",
				URL:        "https://www.shodan.io/host/" + ip,
			}, nil
		}
		return Result{Configured: true}, err
	}
	return parseShodan(raw, ip), nil
}

// parseShodan maps the InternetDB payload onto a Result. Split out from the
// HTTP wrapper so it can be unit-tested without a network round-trip.
func parseShodan(raw []byte, ip string) Result {
	var p shodanResp
	if err := json.Unmarshal(raw, &p); err != nil {
		return Result{Configured: true, Error: err.Error()}
	}

	tags := []string{}
	for _, t := range p.Tags {
		if t != "" {
			tags = append(tags, t)
		}
	}
	for _, port := range p.Ports {
		tags = append(tags, fmt.Sprintf("port:%d", port))
	}

	// Verdict: a host with known CVEs or a Shodan malicious/compromised tag is
	// a stronger signal than a bare port list. InternetDB doesn't score, so we
	// derive a coarse verdict from the presence of vulns / suspicious tags.
	verdict := "unknown"
	if len(p.Vulns) > 0 || hasSuspiciousTag(p.Tags) {
		verdict = "suspicious"
	} else if len(p.Ports) > 0 {
		verdict = "benign"
	}

	var sb strings.Builder
	if len(p.Ports) > 0 {
		fmt.Fprintf(&sb, "%d open port(s)", len(p.Ports))
	}
	if len(p.Vulns) > 0 {
		if sb.Len() > 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "%d known vuln(s): %s", len(p.Vulns), strings.Join(truncate(p.Vulns, 5), ", "))
	}
	if sb.Len() == 0 {
		sb.WriteString("host known to Shodan, no ports/vulns reported")
	}

	return Result{
		Configured: true,
		Verdict:    verdict,
		Tags:       tags,
		Summary:    sb.String(),
		URL:        "https://www.shodan.io/host/" + ip,
		Raw:        json.RawMessage(raw),
	}
}

func hasSuspiciousTag(tags []string) bool {
	for _, t := range tags {
		switch strings.ToLower(t) {
		case "malware", "compromised", "honeypot", "c2", "botnet", "scanner", "self-signed", "tor", "vpn", "proxy":
			return true
		}
	}
	return false
}

// truncate returns at most n elements of s (for compact summaries).
func truncate(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
