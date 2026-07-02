// Package bazaar wraps the abuse.ch MalwareBazaar v1 submission API.
//
// Endpoint: POST https://mb-api.abuse.ch/api/v1/ as multipart/form-data
// with two parts: `file` (the binary) and `json_data` (UTF-8 JSON
// metadata). Authentication is the `Auth-Key` HTTP header, obtained
// from https://auth.abuse.ch/.
//
// The client deliberately does NOT cache the API key in memory longer
// than the single Upload call: it is passed in per-request so a misuse
// (e.g. logging the Client struct) cannot leak it. The endpoint URL is
// configurable purely so tests can point at an httptest.Server.
package bazaar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

// DefaultEndpoint is the production MalwareBazaar v1 submission URL.
const DefaultEndpoint = "https://mb-api.abuse.ch/api/v1/"

// Client posts samples to MalwareBazaar. Zero value is not usable;
// construct with NewClient.
type Client struct {
	endpoint string
	hc       *http.Client
}

// NewClient returns a client targeting endpoint (DefaultEndpoint if
// empty) with a 90 s timeout per call. 90 s is generous: the abuse.ch
// upload step ingests, hashes and disassembles the sample server-side
// before responding, and a 30 MiB ELF can take 20 s+ on a slow link.
func NewClient(endpoint string) *Client {
	if strings.TrimSpace(endpoint) == "" {
		endpoint = DefaultEndpoint
	}
	return &Client{
		endpoint: endpoint,
		hc:       &http.Client{Timeout: 90 * time.Second},
	}
}

// Submission is the metadata side of a single Upload. The Filename
// becomes `file_name` in the upstream record and is shown on the
// public sample page, so we use the cowrie-assigned sha-prefix instead
// of leaking the absolute on-disk path.
type Submission struct {
	Filename  string
	Anonymous bool
	Tags      []string
	Comment   string
	// DeliveryMethod is one of: email_attachment, email_link,
	// web_download, web_drive-by, multiple, other. Honeypot captures
	// fit "other" best — the attacker pushed the file via SSH/SFTP,
	// not via any of the listed delivery channels.
	DeliveryMethod string
	// References is an opaque map of typed source links. abuse.ch
	// understands urlhaus, any_run, joe_sandbox, malpedia, twitter,
	// links. Use "links" for any free-form URL (e.g. the attacker's
	// wget URL recovered from the cowrie session).
	References map[string][]string
}

// Result is the parsed abuse.ch response for an upload call. Status
// strings are one of the documented `query_status` values:
//
//	inserted              — newly added to MalwareBazaar
//	file_already_known    — duplicate; sample is already on MB
//	no_api_key            — missing/wrong Auth-Key
//	user_blacklisted      — your account is banned
//	http_post_expected    — wrong HTTP method (we never hit this)
//	file_expected         — multipart `file` part missing
//
// SampleURL is convenience: if Status=="inserted", we synthesise the
// public sample page URL from the sha256 the caller already knows.
type Result struct {
	Status    string
	SampleURL string
}

// IsAccepted reports whether MalwareBazaar took the sample (either
// freshly inserted or already known). Callers should record the row
// when this is true and refuse to do so when it is false (so the next
// run retries transient failures).
func (r Result) IsAccepted() bool {
	return r.Status == "inserted" || r.Status == "file_already_known"
}

// Upload submits one sample. file is read into memory in full — we
// could stream the multipart body to avoid the buffer, but abuse.ch's
// 30 MiB-ish cap means it's never enough to matter, and the simpler
// code path keeps the failure modes (Content-Length mismatches,
// partial writes) tightly contained.
//
// authKey is the abuse.ch Auth-Key. Passing an empty string is a
// caller bug: returns an error before any network IO.
func (c *Client) Upload(ctx context.Context, authKey string, file io.Reader, sha256 string, sub Submission) (*Result, error) {
	if strings.TrimSpace(authKey) == "" {
		return nil, errors.New("bazaar: missing Auth-Key")
	}
	if sub.Filename == "" {
		sub.Filename = sha256
	}

	// Build the json_data part. Mirroring the field order in the
	// abuse.ch sample script so the response is easier to diff
	// against their example output during debugging.
	jsonBlob := map[string]interface{}{}
	if sub.Anonymous {
		jsonBlob["anonymous"] = 1
	}
	if sub.DeliveryMethod != "" {
		jsonBlob["delivery_method"] = sub.DeliveryMethod
	}
	if len(sub.Tags) > 0 {
		// Tags are constrained to [A-Za-z0-9.- ] per the API docs;
		// the caller (classify.go) already normalises, but we
		// still strip again here so a future caller can't poison
		// the request.
		jsonBlob["tags"] = sanitiseTags(sub.Tags)
	}
	if len(sub.References) > 0 {
		jsonBlob["references"] = sub.References
	}
	if sub.Comment != "" {
		jsonBlob["context"] = map[string]string{"comment": sub.Comment}
	}
	jb, err := json.Marshal(jsonBlob)
	if err != nil {
		return nil, fmt.Errorf("marshal json_data: %w", err)
	}

	// Compose the multipart body.
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	// json_data as a named part with explicit Content-Type so abuse.ch
	// doesn't try to autodetect text/plain.
	jph := make(map[string][]string)
	jph["Content-Disposition"] = []string{`form-data; name="json_data"`}
	jph["Content-Type"] = []string{"application/json"}
	jpw, err := w.CreatePart(jph)
	if err != nil {
		return nil, err
	}
	if _, err := jpw.Write(jb); err != nil {
		return nil, err
	}
	// File part.
	fpw, err := w.CreateFormFile("file", sub.Filename)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(fpw, file); err != nil {
		return nil, fmt.Errorf("copy file part: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Auth-Key", authKey)
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	// abuse.ch returns 200 for both success AND most semantic errors
	// (no_api_key, file_expected); the actual outcome lives in the
	// JSON body's query_status. A non-2xx is always a transport-level
	// failure worth surfacing.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upload: http %d: %s", resp.StatusCode, truncateForError(raw))
	}

	// Response shape: {"query_status": "...", "data": {...}}
	var parsed struct {
		QueryStatus string `json:"query_status"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("parse response: %w; body=%q", err, truncateForError(raw))
	}
	r := &Result{Status: parsed.QueryStatus}
	if r.IsAccepted() && sha256 != "" {
		r.SampleURL = "https://bazaar.abuse.ch/sample/" + sha256 + "/"
	}
	return r, nil
}

// sanitiseTags strips characters disallowed by the abuse.ch tag
// validator ([A-Za-z0-9.- ]) so the upload doesn't reject the whole
// submission over a stray slash in an attacker-supplied filename.
func sanitiseTags(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, t := range in {
		var b strings.Builder
		for _, r := range t {
			switch {
			case r >= 'A' && r <= 'Z',
				r >= 'a' && r <= 'z',
				r >= '0' && r <= '9',
				r == '.', r == '-', r == ' ':
				b.WriteRune(r)
			}
		}
		s := strings.TrimSpace(b.String())
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func truncateForError(b []byte) string {
	const max = 400
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "...(truncated)"
}
