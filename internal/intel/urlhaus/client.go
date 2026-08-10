// Package urlhaus wraps the abuse.ch URLhaus bulk submission API.
//
// Endpoint: POST https://urlhaus.abuse.ch/api/ with a JSON body:
//
//	{"anonymous":"0","submission":[{"url":"...","threat":"malware_download","tags":["..."]}]}
//
// Authentication is the `Auth-Key` HTTP header from https://auth.abuse.ch/ —
// the same abuse.ch account used for MalwareBazaar. Anonymous submissions are
// NOT accepted by URLhaus (the `anonymous` flag only hides your handle from
// the public record; abuse.ch still knows the source), so a key is mandatory.
//
// Like the bazaar client, the API key is passed per-call rather than stored on
// the struct, so accidentally logging a Client can never leak it.
package urlhaus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultEndpoint is the production URLhaus bulk submission URL.
const DefaultEndpoint = "https://urlhaus.abuse.ch/api/"

// ThreatMalwareDownload is the only threat type URLhaus accepts for URL
// submissions ("must be malware_download" per the submission docs).
const ThreatMalwareDownload = "malware_download"

// Client posts URL submissions to URLhaus.
type Client struct {
	endpoint string
	hc       *http.Client
}

// NewClient returns a client targeting endpoint (DefaultEndpoint when empty).
// 30 s is ample: unlike a MalwareBazaar file upload this is a small JSON POST.
func NewClient(endpoint string) *Client {
	if strings.TrimSpace(endpoint) == "" {
		endpoint = DefaultEndpoint
	}
	return &Client{
		endpoint: endpoint,
		hc:       &http.Client{Timeout: 30 * time.Second},
	}
}

// Entry is one URL in a submission batch.
type Entry struct {
	URL    string   `json:"url"`
	Threat string   `json:"threat"`
	Tags   []string `json:"tags,omitempty"`
}

// submitBody is the wire format. `anonymous` is a STRING ("0"/"1") in the
// documented sample script, not a JSON bool — keep it that way.
type submitBody struct {
	Anonymous  string  `json:"anonymous"`
	Submission []Entry `json:"submission"`
}

// Result is the parsed URLhaus response for one batch.
type Result struct {
	// Status is the upstream query_status. Documented values include
	// "ok" and "invalid_auth_key"; unknown values are surfaced verbatim
	// rather than guessed at.
	Status string
	// Rejected counts entries URLhaus refused, when reported.
	Rejected int
	// Raw is the trimmed response body, kept for the CLI's -v output and
	// for recording an unexpected status without losing information.
	Raw string
}

// Errors surfaced to callers, kept as sentinels so the CLI can map them to
// distinct exit codes.
var (
	ErrMissingAPIKey = errors.New("urlhaus: missing API key")
	ErrUnauthorized  = errors.New("urlhaus: auth key rejected")
	ErrNoEntries     = errors.New("urlhaus: no entries to submit")
)

// Submit posts one batch. anonymous hides the operator's abuse.ch handle from
// the public record (abuse.ch still attributes it internally).
//
// A non-2xx response or an auth-failure status is returned as an error so
// callers never record a failed submission as if it had landed.
func (c *Client) Submit(ctx context.Context, apiKey string, entries []Entry, anonymous bool) (*Result, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, ErrMissingAPIKey
	}
	if len(entries) == 0 {
		return nil, ErrNoEntries
	}
	anon := "0"
	if anonymous {
		anon = "1"
	}
	payload, err := json.Marshal(submitBody{Anonymous: anon, Submission: entries})
	if err != nil {
		return nil, fmt.Errorf("urlhaus: encode body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("urlhaus: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Auth-Key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("urlhaus: post: %w", err)
	}
	defer resp.Body.Close()

	// Cap the body: a misbehaving endpoint must not stream unbounded data
	// into the decoder. URLhaus replies with a small JSON object.
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	trimmed := strings.TrimSpace(string(raw))

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("urlhaus: HTTP %d: %s", resp.StatusCode, truncate(trimmed, 200))
	}

	var parsed struct {
		QueryStatus string `json:"query_status"`
		// URLhaus reports per-entry outcomes under varying keys across
		// versions; decode the counts we know about and keep Raw for the rest.
		Rejected []json.RawMessage `json:"rejected"`
	}
	// A body that isn't JSON is not fatal on a 2xx: record it verbatim.
	_ = json.Unmarshal(raw, &parsed)

	if parsed.QueryStatus == "invalid_auth_key" || parsed.QueryStatus == "unauthorized" {
		return nil, ErrUnauthorized
	}
	return &Result{
		Status:   parsed.QueryStatus,
		Rejected: len(parsed.Rejected),
		Raw:      truncate(trimmed, 2000),
	}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
