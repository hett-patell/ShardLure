package enrich

import (
	"context"
	"encoding/json"
	"net/http"
)

// GreyNoise community endpoint shape. The community API is free and
// doesn't require an API key, but if SHARDLURE_GREYNOISE_KEY is set
// we'll send it as a courtesy / higher rate limit.
//
// Docs: https://docs.greynoise.io/reference/get_v3-community-ip
type greyNoiseResp struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`
	Classification string `json:"classification"`
	Name           string `json:"name"`
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message"`
}

func fetchGreyNoise(ctx context.Context, hc *http.Client, ip string) (Result, error) {
	// GreyNoise is always 'configured' since the community endpoint
	// is keyless. We mark Configured=true to signal "we can query
	// this provider" rather than "you've supplied a key".
	url := "https://api.greynoise.io/v3/community/" + ip

	headers := map[string]string{"Accept": "application/json"}
	if key := envKey("SHARDLURE_GREYNOISE_KEY"); key != "" {
		headers["key"] = key
	}

	var parsed greyNoiseResp
	raw, err := httpJSON(ctx, hc, url, headers, &parsed)
	if err != nil {
		// 404 from GreyNoise just means "we have no data" - treat as
		// a clean benign-unknown rather than an error.
		if err.Error() == "404 Not Found" {
			return Result{
				Configured: true,
				Verdict:    "unknown",
				Summary:    "no GreyNoise observations",
				URL:        "https://viz.greynoise.io/ip/" + ip,
			}, nil
		}
		return Result{Configured: true}, err
	}

	verdict := "unknown"
	switch parsed.Classification {
	case "malicious":
		verdict = "malicious"
	case "benign":
		verdict = "benign"
	case "unknown":
		verdict = "unknown"
	}

	tags := []string{}
	if parsed.Noise {
		tags = append(tags, "internet-noise")
	}
	if parsed.Riot {
		tags = append(tags, "riot")
	}
	if parsed.Name != "" {
		tags = append(tags, parsed.Name)
	}

	summary := parsed.Message
	if summary == "" {
		summary = "classification=" + parsed.Classification
		if parsed.LastSeen != "" {
			summary += ", last seen " + parsed.LastSeen
		}
	}

	link := parsed.Link
	if link == "" {
		link = "https://viz.greynoise.io/ip/" + ip
	}

	return Result{
		Configured: true,
		Verdict:    verdict,
		Tags:       tags,
		Summary:    summary,
		URL:        link,
		Raw:        json.RawMessage(raw),
	}, nil
}
