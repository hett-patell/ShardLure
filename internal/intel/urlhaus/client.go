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
	"github.com/networkshard/shardlure/internal/observability"
	"net/http"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/intel/intelutil"
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
	// Status is "ok" for an accepted response or "unknown" for an
	// unrecognised provider status. Arbitrary provider text is never retained.
	Status string
	// Rejected counts entries URLhaus refused, when reported.
	Rejected int
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
func (c *Client) Submit(ctx context.Context, apiKey string, entries []Entry, anonymous bool) (result *Result, resultErr error) {
	ctx, trace := observability.TraceRequest(ctx, observability.URLhaus, observability.Submit)
	defer func() {
		if errors.Is(resultErr, ErrUnauthorized) {
			trace.Finish(resultErr, observability.Unauthorized)
			return
		}
		trace.Finish(resultErr)
	}()
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
		return nil, errors.New("urlhaus: invalid submission endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Auth-Key", apiKey)
	req.Header.Set("Accept", "application/json")

	observability.StartHTTP(ctx)
	resp, err := c.hc.Do(req)
	observability.HTTPResult(ctx, resp, err)
	if err != nil {
		return nil, intelutil.SafeRequestError("urlhaus", "post", err)
	}
	defer resp.Body.Close()

	// Cap the body: a misbehaving endpoint must not stream unbounded data
	// into the decoder. URLhaus replies with a small JSON object.
	raw, err := intelutil.ReadBoundedResponse("urlhaus", resp.Body, 256<<10)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("urlhaus: submission returned HTTP %d", resp.StatusCode)
	}

	var parsed struct {
		QueryStatus string `json:"query_status"`
		// URLhaus reports per-entry outcomes under varying keys across
		// versions; decode the counts we know about and keep Raw for the rest.
		Rejected []json.RawMessage `json:"rejected"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		// URLhaus's legacy submission endpoint returns a bare plaintext ok
		// for accepted batches and already_queued: URL when it has accepted a
		// single URL for processing. Other plaintext tokens such as no_data are
		// errors. Keep multi-entry already_queued responses fail-closed because a
		// single echoed URL cannot prove the whole batch was accepted.
		text := strings.TrimSpace(string(raw))
		if strings.EqualFold(text, "ok") {
			return &Result{Status: "ok"}, nil
		}
		const queuedPrefix = "already_queued:"
		if len(entries) == 1 && strings.HasPrefix(strings.ToLower(text), queuedPrefix) &&
			strings.TrimSpace(text[len(queuedPrefix):]) == entries[0].URL {
			return &Result{Status: "already_queued"}, nil
		}
		return nil, errors.New("urlhaus: invalid submission response")
	}

	status := strings.ToLower(strings.TrimSpace(parsed.QueryStatus))
	if status == "invalid_auth_key" || status == "unauthorized" || status == "illegal_auth_key" || status == "no_auth_key" {
		return nil, ErrUnauthorized
	}
	if status != "ok" {
		return &Result{Status: "unknown"}, errors.New("urlhaus: submission rejected")
	}
	if len(parsed.Rejected) > 0 {
		return &Result{Status: "rejected", Rejected: len(parsed.Rejected)}, errors.New("urlhaus: submission contained rejected entries")
	}
	return &Result{Status: "ok"}, nil
}
