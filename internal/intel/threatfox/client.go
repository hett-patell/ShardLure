// Package threatfox wraps the abuse.ch ThreatFox IOC submission API.
//
// Endpoint: POST https://threatfox-api.abuse.ch/api/v1/ with a JSON body:
//
//	{"query":"submit_ioc","threat_type":"payload_delivery","ioc_type":"url",
//	 "malware":"elf.mirai","confidence_level":75,"reference":"...",
//	 "anonymous":0,"tags":["..."],"iocs":["http://host/x"]}
//
// Authentication is the `Auth-Key` HTTP header from https://auth.abuse.ch/ —
// the SAME abuse.ch account used for MalwareBazaar and URLhaus. ThreatFox is
// the IOC-level give-back channel: MalwareBazaar receives the files, URLhaus
// the URLs, ThreatFox the indicators (URL / ip:port / domain / hash) tied to a
// malware family.
//
// Like the bazaar and urlhaus clients, the API key is passed per-call rather
// than stored on the struct, so accidentally logging a Client can never leak it.
package threatfox

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

	"github.com/networkshard/shardlure/internal/intel/intelutil"
)

// DefaultEndpoint is the production ThreatFox API v1 URL.
const DefaultEndpoint = "https://threatfox-api.abuse.ch/api/v1/"

// Threat types (abuse.ch `types` endpoint, verified 2026-08-14). We only ever
// submit payload-delivery indicators and the payload hash — never botnet_cc,
// which would require first-hand C2 proof the honeypot does not have.
const (
	ThreatPayloadDelivery = "payload_delivery" // url / domain / ip:port that served a payload
	ThreatPayload         = "payload"          // a malware sample hash
)

// IOC types (abuse.ch `types` endpoint, verified 2026-08-14).
const (
	IOCTypeURL    = "url"
	IOCTypeDomain = "domain"
	IOCTypeIPPort = "ip:port"
	IOCTypeSHA256 = "sha256_hash"
)

// Client posts IOC submissions to ThreatFox.
type Client struct {
	endpoint string
	hc       *http.Client
}

// NewClient returns a client targeting endpoint (DefaultEndpoint when empty).
// 30s is ample: this is a small JSON POST, not a file upload.
func NewClient(endpoint string) *Client {
	if strings.TrimSpace(endpoint) == "" {
		endpoint = DefaultEndpoint
	}
	return &Client{
		endpoint: endpoint,
		hc:       &http.Client{Timeout: 30 * time.Second},
	}
}

// Submission is one ThreatFox IOC. One submit call carries exactly one IOC
// with its own threat_type/ioc_type/malware, because those fields are per-IOC
// and mixing them in a batch would mislabel indicators.
type Submission struct {
	ThreatType      string
	IOCType         string
	Malware         string // Malpedia label, e.g. "elf.mirai"
	IOC             string // the indicator value
	ConfidenceLevel int    // 0-100
	Reference       string // a URL, e.g. a MalwareBazaar sample link; may be ""
	Tags            []string
	Comment         string
}

// submitBody is the wire format for query=submit_ioc. `anonymous` is an int
// (0/1) per the documented sample; `iocs` is a list even for a single IOC.
type submitBody struct {
	Query           string   `json:"query"`
	ThreatType      string   `json:"threat_type"`
	IOCType         string   `json:"ioc_type"`
	Malware         string   `json:"malware"`
	ConfidenceLevel int      `json:"confidence_level"`
	Reference       string   `json:"reference,omitempty"`
	Comment         string   `json:"comment,omitempty"`
	Anonymous       int      `json:"anonymous"`
	Tags            []string `json:"tags,omitempty"`
	IOCs            []string `json:"iocs"`
}

// Result is the parsed ThreatFox response for one submission.
type Result struct {
	// Status is the upstream query_status verbatim (e.g. "ok",
	// "illegal_malware"); unknown values are surfaced, not guessed.
	Status string
	// Accepted is true when the IOC landed in the `ok` array (newly added).
	Accepted bool
	// Duplicate is true when ThreatFox reported the IOC in the `duplicated`
	// array — already in the dataset. A duplicate is a SUCCESS for our purposes
	// (the IOC is published), so it is recorded in the dedup ledger, not retried.
	Duplicate bool
	// Ignored is true when the IOC landed in the `ignored` array — REJECTED by
	// ThreatFox (failed validation). This is a FAILURE: it is NOT recorded, so a
	// corrected future run can retry, and it is surfaced to the operator.
	Ignored bool
	// Reward is the abuse.ch contribution credit reported for the submission,
	// when present; purely informational.
	Reward int
	// Raw is the trimmed response body, kept for the CLI's -v output and to
	// record an unexpected status without losing information.
	Raw string
}

// Errors surfaced to callers, kept as sentinels so the CLI can map them to
// distinct exit codes.
var (
	ErrMissingAPIKey = errors.New("threatfox: missing API key")
	ErrUnauthorized  = errors.New("threatfox: auth key rejected")
	ErrEmptyIOC      = errors.New("threatfox: empty IOC")
)

// Submit posts one IOC. anonymous hides the operator's abuse.ch handle from the
// public record (abuse.ch still attributes it internally).
//
// A non-2xx response or an auth-failure status is returned as an error so a
// failed submission is never recorded as if it had landed. A "duplicate"
// outcome is NOT an error — it means the IOC is already in the dataset, which
// is a successful contribution, so it returns a Result with Duplicate=true.
func (c *Client) Submit(ctx context.Context, apiKey string, s Submission) (*Result, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, ErrMissingAPIKey
	}
	if strings.TrimSpace(s.IOC) == "" {
		return nil, ErrEmptyIOC
	}
	anon := 0
	body := submitBody{
		Query:           "submit_ioc",
		ThreatType:      s.ThreatType,
		IOCType:         s.IOCType,
		Malware:         s.Malware,
		ConfidenceLevel: s.ConfidenceLevel,
		Reference:       s.Reference,
		Comment:         s.Comment,
		Anonymous:       anon,
		Tags:            s.Tags,
		IOCs:            []string{s.IOC},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("threatfox: encode body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("threatfox: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Auth-Key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("threatfox: post: %w", err)
	}
	defer resp.Body.Close()

	// Cap the body: a misbehaving endpoint must not stream unbounded data into
	// the decoder. ThreatFox replies with a small JSON object.
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	trimmed := strings.TrimSpace(string(raw))

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("threatfox: HTTP %d: %s", resp.StatusCode, intelutil.Truncate(trimmed, 200))
	}

	// ThreatFox wraps everything in {"query_status": "...", "data": ...}. The
	// data shape varies (object with reward/ok/ignored, or a message string),
	// so decode defensively: pull the status and any duplicate/reward signal we
	// recognise, keep Raw for everything else.
	var parsed struct {
		QueryStatus string          `json:"query_status"`
		Data        json.RawMessage `json:"data"`
	}
	_ = json.Unmarshal(raw, &parsed)

	status := strings.ToLower(strings.TrimSpace(parsed.QueryStatus))
	// Auth failures reported in-band (documented abuse.ch pattern: a 200 with
	// an illegal-key status) must still be a hard error, not a recorded submit.
	switch status {
	case "illegal_auth_key", "unauthorized", "invalid_auth_key", "no_auth_key":
		return nil, ErrUnauthorized
	}

	res := &Result{Status: parsed.QueryStatus, Raw: intelutil.Truncate(trimmed, 2000)}
	// Any non-"ok" top-level status is a failure. abuse.ch does not publish the
	// submit error vocabulary, so we do NOT switch on a fixed enum — the
	// non-"ok" status is surfaced verbatim (via res.Status) and the caller
	// treats it as a failed submission. Only "ok" carries the data accounting.
	if status == "ok" {
		res.Accepted, res.Duplicate, res.Ignored, res.Reward = parseSubmitData(parsed.Data)
	}
	return res, nil
}

// parseSubmitData reads the CONFIRMED submit_ioc success shape:
//
//	"data": {"ok": [...], "ignored": [...], "duplicated": [...], "reward": N}
//
// (verified against a real captured fixture — seanmcfeely/ThreatFox
// tests/submission_result.json — and an independent parser). Because Submit
// posts exactly ONE ioc per call, at most one of the three arrays is non-empty:
//   - ok        -> accepted (newly added)
//   - duplicated -> already in the dataset (a success for dedup)
//   - ignored   -> rejected by ThreatFox (a failure — do not record)
func parseSubmitData(data json.RawMessage) (accepted, duplicate, ignored bool, reward int) {
	if len(data) == 0 {
		return false, false, false, 0
	}
	var obj struct {
		OK         []json.RawMessage `json:"ok"`
		Ignored    []json.RawMessage `json:"ignored"`
		Duplicated []json.RawMessage `json:"duplicated"`
		Reward     int               `json:"reward"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return false, false, false, 0
	}
	return len(obj.OK) > 0, len(obj.Duplicated) > 0, len(obj.Ignored) > 0, obj.Reward
}
