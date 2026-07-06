// Package abuseipdb wraps the AbuseIPDB v2 /report API — the WRITE side of
// AbuseIPDB (the enrichment package already handles the READ side, /check).
//
// Endpoint: POST https://api.abuseipdb.com/api/v2/report as form-encoded
// body (ip, categories, comment, timestamp). Authentication is the `Key`
// HTTP header, obtained from https://www.abuseipdb.com/account/api. The v2
// /check endpoint is GET and lives in internal/intel/enrich; reporting needs
// a POST client with different semantics, so it does NOT reuse enrich's
// GET-only httpJSON helper.
//
// Like the bazaar client, the API key is passed per-call (never cached on the
// struct) so a misuse — logging the Client — cannot leak it. The endpoint URL
// is configurable purely so tests can point at an httptest.Server.
package abuseipdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultEndpoint is the production AbuseIPDB v2 report URL.
const DefaultEndpoint = "https://api.abuseipdb.com/api/v2/report"

// Client posts reports to AbuseIPDB. Zero value is not usable; construct with
// NewClient.
type Client struct {
	endpoint string
	hc       *http.Client
}

// NewClient returns a client targeting endpoint (DefaultEndpoint if empty)
// with a 15 s timeout per call — /report is a small form POST, not an upload.
func NewClient(endpoint string) *Client {
	if strings.TrimSpace(endpoint) == "" {
		endpoint = DefaultEndpoint
	}
	return &Client{
		endpoint: endpoint,
		hc:       &http.Client{Timeout: 15 * time.Second},
	}
}

// Submission is one report's payload. IP is the offender; Categories are the
// AbuseIPDB category IDs (e.g. 18 Brute-Force, 22 SSH); Comment is the public
// note — it must carry NOTHING that identifies the honeypot host or session.
type Submission struct {
	IP         string
	Categories []int
	Comment    string
	// Timestamp is the observation time (RFC3339). Zero means "now" and is
	// omitted so AbuseIPDB stamps receipt time.
	Timestamp time.Time
}

// Result is the parsed /report response. Score is the offender's updated
// abuseConfidenceScore (0-100) AbuseIPDB returns on a successful report.
// RateLimited is set when the API returned 429 (daily report cap hit) so the
// caller can stop cleanly instead of hammering the endpoint.
type Result struct {
	Score       int
	RateLimited bool
}

// Submit posts one report. authKey is the AbuseIPDB API key; an empty string
// is a caller bug (returns an error before any network IO). A 429 is returned
// as (Result{RateLimited:true}, nil) — an expected operational state, not an
// error; any other non-2xx is an error.
func (c *Client) Submit(ctx context.Context, authKey string, rep Submission) (*Result, error) {
	if strings.TrimSpace(authKey) == "" {
		return nil, errors.New("abuseipdb: missing API key")
	}
	if strings.TrimSpace(rep.IP) == "" {
		return nil, errors.New("abuseipdb: missing ip")
	}
	if len(rep.Categories) == 0 {
		return nil, errors.New("abuseipdb: at least one category is required")
	}

	form := url.Values{}
	form.Set("ip", rep.IP)
	form.Set("categories", joinInts(rep.Categories))
	if rep.Comment != "" {
		form.Set("comment", rep.Comment)
	}
	if !rep.Timestamp.IsZero() {
		form.Set("timestamp", rep.Timestamp.UTC().Format(time.RFC3339))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", authKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// 429 = daily report limit reached. Surface as a clean signal so the
	// orchestrator can halt the batch rather than keep POSTing into a wall.
	if resp.StatusCode == http.StatusTooManyRequests {
		return &Result{RateLimited: true}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("report: http %d: %s", resp.StatusCode, truncateForError(raw))
	}

	// Success shape: {"data": {"ipAddress": "...", "abuseConfidenceScore": N}}
	var parsed struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("parse response: %w; body=%q", err, truncateForError(raw))
	}
	return &Result{Score: parsed.Data.AbuseConfidenceScore}, nil
}

func joinInts(in []int) string {
	parts := make([]string, 0, len(in))
	for _, n := range in {
		parts = append(parts, strconv.Itoa(n))
	}
	return strings.Join(parts, ",")
}

func truncateForError(b []byte) string {
	const max = 400
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "...(truncated)"
}
