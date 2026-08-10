// Package vt looks up captured payloads by hash on VirusTotal.
//
// This is the FILE side of VirusTotal, distinct from internal/intel/enrich,
// which queries the IP side. Endpoint:
//
//	GET https://www.virustotal.com/api/v3/files/{sha256}   header: x-apikey
//
// Design constraints that shape this package:
//
//   - The free tier permits ~4 requests/minute and 500/day. So lookups are
//     ON DEMAND (an analyst opening a payload), never a background sweep, and
//     results are cached with a long TTL. A file hash is immutable and its
//     verdict is stable, unlike an IP reputation, so a long TTL costs nothing
//     in accuracy.
//   - HTTP 404 means "VirusTotal has never seen this hash". For a honeypot
//     that is a genuinely interesting finding (a novel sample), not an error,
//     so it is modelled as a first-class Verdict, not a failure.
//   - Only the hash is ever transmitted. We never upload the file, so nothing
//     about the honeypot or the session leaves the host.
package vt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Source is the cache key used in the payload_intel table.
const Source = "virustotal"

// DefaultEndpoint is the VirusTotal v3 file-report base URL.
const DefaultEndpoint = "https://www.virustotal.com/api/v3/files/"

// CacheTTL bounds how long a cached verdict is reused. Long by design: a
// hash's verdict barely moves, and the free tier's 4 req/min ceiling makes
// re-asking expensive. A "not found" result uses NotFoundTTL instead, because
// that answer genuinely does change once someone else submits the sample.
const (
	CacheTTL    = 30 * 24 * time.Hour
	NotFoundTTL = 7 * 24 * time.Hour
)

// Verdict is the parsed, UI-shaped result of one hash lookup. It is what gets
// JSON-encoded into the payload_intel cache, so field names are part of the
// on-disk format — add fields, don't rename them.
type Verdict struct {
	SHA256 string `json:"sha256"`
	// Found is false when VirusTotal has never seen this hash (HTTP 404).
	Found bool `json:"found"`
	// Verdict is a coarse bucket: malicious / suspicious / benign / unknown.
	// Derived with the same thresholds the IP-side provider uses so the two
	// surfaces agree.
	Verdict string `json:"verdict"`
	// Malicious/Suspicious/Harmless/Undetected are engine counts.
	Malicious   int `json:"malicious"`
	Suspicious  int `json:"suspicious"`
	Harmless    int `json:"harmless"`
	Undetected  int `json:"undetected"`
	TotalEngine int `json:"total_engines"`
	// ThreatLabel is VT's popular_threat_classification suggestion, e.g.
	// "trojan.mirai/gafgyt". Empty when VT has no consensus.
	ThreatLabel string `json:"threat_label,omitempty"`
	// TypeDescription is VT's file-type string, e.g. "ELF" or "Bash script".
	TypeDescription string `json:"type_description,omitempty"`
	// MeaningfulName is the most common filename VT has seen for this hash.
	MeaningfulName string `json:"meaningful_name,omitempty"`
	// Reputation is VT's community score (can be negative).
	Reputation int `json:"reputation,omitempty"`
	// TimesSubmitted counts how often the sample has been submitted to VT.
	TimesSubmitted int `json:"times_submitted,omitempty"`
	// FirstSeen / LastAnalysis are VT-side timestamps (zero when absent).
	FirstSeen    time.Time `json:"first_seen,omitempty"`
	LastAnalysis time.Time `json:"last_analysis,omitempty"`
	// Permalink is the human-facing VT page for this hash. Constructed
	// locally; VT does not return it on this endpoint.
	Permalink string `json:"permalink,omitempty"`
	// FetchedAt is when we obtained this verdict.
	FetchedAt time.Time `json:"fetched_at"`
	// Cached reports that the value came from the local cache rather than a
	// live call. Not persisted (it's derived per response).
	Cached bool `json:"cached,omitempty"`
}

// Errors surfaced to callers.
var (
	ErrMissingAPIKey = errors.New("vt: missing API key")
	ErrUnauthorized  = errors.New("vt: API key rejected")
	ErrRateLimited   = errors.New("vt: rate limited (free tier allows ~4 requests/minute)")
	ErrBadHash       = errors.New("vt: not a sha256 hash")
)

// Client queries the VirusTotal file endpoint. The API key is passed per-call
// rather than stored, so logging a Client cannot leak it.
type Client struct {
	endpoint string
	hc       *http.Client
}

// NewClient returns a client targeting endpoint (DefaultEndpoint when empty).
func NewClient(endpoint string) *Client {
	if strings.TrimSpace(endpoint) == "" {
		endpoint = DefaultEndpoint
	}
	if !strings.HasSuffix(endpoint, "/") {
		endpoint += "/"
	}
	return &Client{
		endpoint: endpoint,
		hc:       &http.Client{Timeout: 15 * time.Second},
	}
}

// vtFileResp is the subset of the v3 file object we consume.
type vtFileResp struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			MeaningfulName  string `json:"meaningful_name"`
			TypeDescription string `json:"type_description"`
			Reputation      int    `json:"reputation"`
			TimesSubmitted  int    `json:"times_submitted"`
			FirstSubmission int64  `json:"first_submission_date"`
			LastAnalysis    int64  `json:"last_analysis_date"`
			PopularThreat   struct {
				SuggestedLabel string `json:"suggested_threat_label"`
			} `json:"popular_threat_classification"`
		} `json:"attributes"`
	} `json:"data"`
}

// isSHA256 keeps a malformed identifier from being interpolated into the URL
// path (and from wasting one of the 4 requests/minute).
func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// Lookup fetches the verdict for one sha256. A 404 returns a Verdict with
// Found=false and no error — "VT has never seen this" is a real answer.
func (c *Client) Lookup(ctx context.Context, apiKey, sha string) (*Verdict, error) {
	sha = strings.ToLower(strings.TrimSpace(sha))
	if !isSHA256(sha) {
		return nil, ErrBadHash
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, ErrMissingAPIKey
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+sha, nil)
	if err != nil {
		return nil, fmt.Errorf("vt: build request: %w", err)
	}
	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vt: get: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		// Genuinely useful signal for a honeypot: a sample nobody has seen.
		return &Verdict{
			SHA256:    sha,
			Found:     false,
			Verdict:   "unknown",
			Permalink: permalink(sha),
			FetchedAt: time.Now().UTC(),
		}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, ErrUnauthorized
	case http.StatusTooManyRequests:
		return nil, ErrRateLimited
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("vt: HTTP %d", resp.StatusCode)
	}

	// Cap the body: the v3 file object can be large (every engine's result),
	// and an unbounded decode is a memory-exhaustion vector.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("vt: read body: %w", err)
	}
	return ParseFileReport(raw, sha)
}

// ParseFileReport maps a raw v3 file object onto a Verdict. Split from the HTTP
// call so it can be unit-tested without a network round-trip.
func ParseFileReport(raw []byte, sha string) (*Verdict, error) {
	var parsed vtFileResp
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("vt: decode: %w", err)
	}
	a := parsed.Data.Attributes
	st := a.LastAnalysisStats
	total := st.Harmless + st.Malicious + st.Suspicious + st.Undetected

	v := &Verdict{
		SHA256:          sha,
		Found:           true,
		Malicious:       st.Malicious,
		Suspicious:      st.Suspicious,
		Harmless:        st.Harmless,
		Undetected:      st.Undetected,
		TotalEngine:     total,
		ThreatLabel:     a.PopularThreat.SuggestedLabel,
		TypeDescription: a.TypeDescription,
		MeaningfulName:  a.MeaningfulName,
		Reputation:      a.Reputation,
		TimesSubmitted:  a.TimesSubmitted,
		Permalink:       permalink(sha),
		FetchedAt:       time.Now().UTC(),
	}
	if a.FirstSubmission > 0 {
		v.FirstSeen = time.Unix(a.FirstSubmission, 0).UTC()
	}
	if a.LastAnalysis > 0 {
		v.LastAnalysis = time.Unix(a.LastAnalysis, 0).UTC()
	}
	// Same thresholds as the IP-side provider so the two surfaces never
	// disagree about what "suspicious" means.
	switch {
	case st.Malicious >= 3:
		v.Verdict = "malicious"
	case st.Malicious > 0 || st.Suspicious >= 2:
		v.Verdict = "suspicious"
	case total == 0:
		v.Verdict = "unknown"
	default:
		v.Verdict = "benign"
	}
	return v, nil
}

func permalink(sha string) string {
	return "https://www.virustotal.com/gui/file/" + sha
}

// Expired reports whether a cached verdict should be refreshed. "Not found"
// entries expire sooner because that answer changes as soon as anyone else
// submits the sample.
func Expired(v Verdict, now time.Time) bool {
	ttl := CacheTTL
	if !v.Found {
		ttl = NotFoundTTL
	}
	return now.Sub(v.FetchedAt) > ttl
}
