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
	"github.com/networkshard/shardlure/internal/observability"
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
	// Status is "ok" for a structurally valid response. Arbitrary provider
	// query_status text is never retained or returned.
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
func (c *Client) Submit(ctx context.Context, apiKey string, s Submission) (result *Result, resultErr error) {
	ctx, trace := observability.TraceRequest(ctx, observability.ThreatFox, observability.Submit)
	defer func() {
		if errors.Is(resultErr, ErrUnauthorized) {
			trace.Finish(resultErr, observability.Unauthorized)
			return
		}
		if result != nil && result.Ignored {
			trace.Finish(resultErr, observability.Rejected)
			return
		}
		trace.Finish(resultErr)
	}()
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
		return nil, errors.New("threatfox: invalid submission endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Auth-Key", apiKey)
	req.Header.Set("Accept", "application/json")

	observability.StartHTTP(ctx)
	resp, err := c.hc.Do(req)
	observability.HTTPResult(ctx, resp, err)
	if err != nil {
		return nil, intelutil.SafeRequestError("threatfox", "post", err)
	}
	defer resp.Body.Close()

	// Cap the body: a misbehaving endpoint must not stream unbounded data into
	// the decoder. ThreatFox replies with a small JSON object.
	raw, err := intelutil.ReadBoundedResponse("threatfox", resp.Body, 256<<10)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("threatfox: submission returned HTTP %d", resp.StatusCode)
	}

	// ThreatFox wraps everything in {"query_status": "...", "data": ...}.
	var parsed struct {
		QueryStatus string          `json:"query_status"`
		Data        json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, errors.New("threatfox: invalid submission response")
	}

	status := strings.ToLower(strings.TrimSpace(parsed.QueryStatus))
	// Auth failures reported in-band (documented abuse.ch pattern: a 200 with
	// an illegal-key status) must still be a hard error, not a recorded submit.
	switch status {
	case "illegal_auth_key", "unauthorized", "invalid_auth_key", "no_auth_key":
		return nil, ErrUnauthorized
	}

	if status != "ok" {
		return nil, errors.New("threatfox: submission rejected")
	}
	accepted, duplicate, ignored, reward, err := parseSubmitData(parsed.Data, s.IOC)
	if err != nil {
		return nil, errors.New("threatfox: invalid submission response")
	}
	res := &Result{Status: "ok", Accepted: accepted, Duplicate: duplicate, Ignored: ignored, Reward: reward}
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
func parseSubmitData(data json.RawMessage, expectedIOC string) (accepted, duplicate, ignored bool, reward int, err error) {
	if len(data) == 0 {
		return false, false, false, 0, errors.New("missing data")
	}
	var obj struct {
		OK         []json.RawMessage `json:"ok"`
		Ignored    []json.RawMessage `json:"ignored"`
		Duplicated []json.RawMessage `json:"duplicated"`
		Reward     int               `json:"reward"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return false, false, false, 0, err
	}
	if outcomes := len(obj.OK) + len(obj.Duplicated) + len(obj.Ignored); outcomes != 1 {
		return false, false, false, 0, errors.New("ambiguous outcome")
	}
	var outcome json.RawMessage
	switch {
	case len(obj.OK) == 1:
		accepted, outcome = true, obj.OK[0]
	case len(obj.Duplicated) == 1:
		duplicate, outcome = true, obj.Duplicated[0]
	case len(obj.Ignored) == 1:
		ignored, outcome = true, obj.Ignored[0]
	}
	var reportedIOC string
	if err := json.Unmarshal(outcome, &reportedIOC); err != nil || reportedIOC == "" || reportedIOC != expectedIOC {
		return false, false, false, 0, errors.New("invalid outcome IOC")
	}
	return accepted, duplicate, ignored, obj.Reward, nil
}
