package enrich

import (
	"encoding/json"
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

var greyNoiseSpec = providerSpec{
	// keyOptional: the community endpoint is keyless, so GreyNoise is always
	// 'configured'; a key is sent when present for the higher rate limit.
	envVar:      "SHARDLURE_GREYNOISE_KEY",
	keyOptional: true,
	buildReq: func(ip, key string) (string, map[string]string) {
		headers := map[string]string{"Accept": "application/json"}
		if key != "" {
			headers["key"] = key
		}
		return "https://api.greynoise.io/v3/community/" + ip, headers
	},
	parse: parseGreyNoise,
	// 404 from GreyNoise just means "we have no data" - treat as a clean
	// benign-unknown rather than an error.
	notFound: func(ip string) Result {
		return Result{
			Configured: true,
			Verdict:    "unknown",
			Summary:    "no GreyNoise observations",
			URL:        "https://viz.greynoise.io/ip/" + ip,
		}
	},
}

// parseGreyNoise maps the community payload onto a Result. Split out from the
// HTTP wrapper so it can be unit-tested without a network round-trip.
func parseGreyNoise(raw []byte, ip string) Result {
	var parsed greyNoiseResp
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return Result{Configured: true, Error: err.Error()}
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
	}
}
