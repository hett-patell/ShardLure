package urlhaus

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRecorder is an in-memory SubmitRecorder.
type fakeRecorder struct {
	mu        sync.Mutex
	submitted map[string]string
	failOn    string // URL whose URLhausSubmitted call should error
}

func newFakeRecorder() *fakeRecorder {
	return &fakeRecorder{submitted: map[string]string{}}
}

func (f *fakeRecorder) URLhausSubmitted(url string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if url == f.failOn {
		return false, errors.New("boom")
	}
	_, ok := f.submitted[url]
	return ok, nil
}

func (f *fakeRecorder) RecordURLhausSubmission(url, status string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.submitted[url] = status
	return nil
}

// captureServer records every submission body it receives.
type captureServer struct {
	*httptest.Server
	mu      sync.Mutex
	bodies  []submitBody
	authKey string
	status  int
	reply   string
}

func newCaptureServer(t *testing.T) *captureServer {
	t.Helper()
	cs := &captureServer{status: http.StatusOK, reply: `{"query_status":"ok"}`}
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		defer cs.mu.Unlock()
		cs.authKey = r.Header.Get("Auth-Key")
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var b submitBody
		_ = json.Unmarshal(raw, &b)
		cs.bodies = append(cs.bodies, b)
		w.WriteHeader(cs.status)
		_, _ = w.Write([]byte(cs.reply))
	}))
	t.Cleanup(cs.Close)
	return cs
}

func (cs *captureServer) allEntries() []Entry {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	var out []Entry
	for _, b := range cs.bodies {
		out = append(out, b.Submission...)
	}
	return out
}

func TestShareSubmitsOnlyVettedURLs(t *testing.T) {
	cs := newCaptureServer(t)
	rec := newFakeRecorder()

	good := goodCandidate()
	privateIP := goodCandidate()
	privateIP.URL = "http://10.1.2.3/bins/x86"
	pseudoKey := goodCandidate()
	pseudoKey.URL = "cowrie-download:abc123"
	failedFetch := goodCandidate()
	failedFetch.URL = "http://evil.tld/gone"
	failedFetch.Status = "failed"

	submitted, skipped, err := Share(context.Background(), rec,
		[]Candidate{good, privateIP, pseudoKey, failedFetch},
		Options{APIKey: "k", Endpoint: cs.URL, ExtraTags: []string{"shardlure"}, RateLimit: time.Millisecond})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 1 {
		t.Errorf("submitted = %d, want 1", submitted)
	}
	if skipped != 3 {
		t.Errorf("skipped = %d, want 3", skipped)
	}

	entries := cs.allEntries()
	if len(entries) != 1 {
		t.Fatalf("server saw %d entries, want 1: %+v", len(entries), entries)
	}
	if entries[0].URL != good.URL {
		t.Errorf("submitted URL = %q, want %q", entries[0].URL, good.URL)
	}
	if entries[0].Threat != ThreatMalwareDownload {
		t.Errorf("threat = %q, want %q", entries[0].Threat, ThreatMalwareDownload)
	}
	if cs.authKey != "k" {
		t.Errorf("Auth-Key header = %q, want k", cs.authKey)
	}
	if got := rec.submitted[good.URL]; got != "ok" {
		t.Errorf("recorded status = %q, want ok", got)
	}
}

// The candidate carries no honeypot identifiers, so the wire payload can't
// contain them. This is the leak-prevention regression guard.
func TestShareBodyLeaksNoHoneypotIdentifiers(t *testing.T) {
	cs := newCaptureServer(t)
	rec := newFakeRecorder()
	_, _, err := Share(context.Background(), rec, []Candidate{goodCandidate()},
		Options{APIKey: "k", Endpoint: cs.URL, RateLimit: time.Millisecond})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	cs.mu.Lock()
	raw, _ := json.Marshal(cs.bodies)
	cs.mu.Unlock()
	body := string(raw)
	for _, forbidden := range []string{"session", "src_ip", "local_path", "/var/lib/shardlure", "evidence"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("submission body leaked %q: %s", forbidden, body)
		}
	}
}

func TestShareSkipsAlreadySubmitted(t *testing.T) {
	cs := newCaptureServer(t)
	rec := newFakeRecorder()
	c := goodCandidate()
	rec.submitted[c.URL] = "ok" // pretend a previous run shipped it

	submitted, skipped, err := Share(context.Background(), rec, []Candidate{c},
		Options{APIKey: "k", Endpoint: cs.URL, RateLimit: time.Millisecond})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 0 || skipped != 1 {
		t.Errorf("submitted=%d skipped=%d, want 0/1", submitted, skipped)
	}
	if n := len(cs.allEntries()); n != 0 {
		t.Errorf("server should see nothing, saw %d", n)
	}
}

func TestShareDryRunNeverPosts(t *testing.T) {
	cs := newCaptureServer(t)
	rec := newFakeRecorder()
	submitted, _, err := Share(context.Background(), rec, []Candidate{goodCandidate()},
		Options{Endpoint: cs.URL, DryRun: true, RateLimit: time.Millisecond})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 1 {
		t.Errorf("dry-run should report 1 would-submit, got %d", submitted)
	}
	if n := len(cs.allEntries()); n != 0 {
		t.Errorf("dry-run must not POST, server saw %d entries", n)
	}
	if len(rec.submitted) != 0 {
		t.Errorf("dry-run must not record, got %v", rec.submitted)
	}
}

func TestShareRequiresAPIKeyUnlessDryRun(t *testing.T) {
	rec := newFakeRecorder()
	if _, _, err := Share(context.Background(), rec, []Candidate{goodCandidate()}, Options{}); !errors.Is(err, ErrMissingAPIKey) {
		t.Errorf("err = %v, want ErrMissingAPIKey", err)
	}
	if _, _, err := Share(context.Background(), rec, nil, Options{APIKey: "k"}); !errors.Is(err, ErrEmptyBatch) {
		t.Errorf("err = %v, want ErrEmptyBatch", err)
	}
}

// An auth failure must abort immediately rather than replay every batch
// against an endpoint that will reject all of them.
func TestShareStopsOnUnauthorized(t *testing.T) {
	cs := newCaptureServer(t)
	cs.status = http.StatusUnauthorized
	rec := newFakeRecorder()

	var cands []Candidate
	for i := 0; i < 60; i++ { // > default batch size, so >1 batch would be sent
		c := goodCandidate()
		c.URL = "http://185.7.214.3/bins/x86-" + strconv.Itoa(i)
		cands = append(cands, c)
	}
	submitted, _, err := Share(context.Background(), rec, cands,
		Options{APIKey: "bad", Endpoint: cs.URL, RateLimit: time.Millisecond})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if submitted != 0 {
		t.Errorf("submitted = %d, want 0", submitted)
	}
	cs.mu.Lock()
	batches := len(cs.bodies)
	cs.mu.Unlock()
	if batches != 1 {
		t.Errorf("should stop after the first 401, sent %d batches", batches)
	}
	if len(rec.submitted) != 0 {
		t.Error("a rejected submission must not be recorded (so it retries later)")
	}
}

func TestShareBatchesLargeSets(t *testing.T) {
	cs := newCaptureServer(t)
	rec := newFakeRecorder()
	var cands []Candidate
	for i := 0; i < 55; i++ {
		c := goodCandidate()
		c.URL = "http://185.7.214.3/x-" + strconv.Itoa(i)
		cands = append(cands, c)
	}
	submitted, _, err := Share(context.Background(), rec, cands,
		Options{APIKey: "k", Endpoint: cs.URL, BatchSize: 25, RateLimit: time.Millisecond})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 55 {
		t.Errorf("submitted = %d, want 55", submitted)
	}
	cs.mu.Lock()
	batches := len(cs.bodies)
	cs.mu.Unlock()
	if batches != 3 { // 25 + 25 + 5
		t.Errorf("batches = %d, want 3", batches)
	}
	if n := len(cs.allEntries()); n != 55 {
		t.Errorf("total entries = %d, want 55", n)
	}
}

func TestShareCollapsesDuplicateURLs(t *testing.T) {
	cs := newCaptureServer(t)
	rec := newFakeRecorder()
	c := goodCandidate()
	submitted, skipped, err := Share(context.Background(), rec, []Candidate{c, c, c},
		Options{APIKey: "k", Endpoint: cs.URL, RateLimit: time.Millisecond})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 1 || skipped != 2 {
		t.Errorf("submitted=%d skipped=%d, want 1/2", submitted, skipped)
	}
}

func TestClientRejectsEmptyInputs(t *testing.T) {
	c := NewClient("")
	if c.endpoint != DefaultEndpoint {
		t.Errorf("endpoint = %q, want default", c.endpoint)
	}
	if _, err := c.Submit(context.Background(), "", []Entry{{URL: "http://x.tld/a"}}, false); !errors.Is(err, ErrMissingAPIKey) {
		t.Errorf("err = %v, want ErrMissingAPIKey", err)
	}
	if _, err := c.Submit(context.Background(), "k", nil, false); !errors.Is(err, ErrNoEntries) {
		t.Errorf("err = %v, want ErrNoEntries", err)
	}
}

// anonymous is a STRING on the wire ("0"/"1"), per the documented API.
func TestClientAnonymousFlagIsStringy(t *testing.T) {
	cs := newCaptureServer(t)
	c := NewClient(cs.URL)
	if _, err := c.Submit(context.Background(), "k", []Entry{{URL: "http://x.tld/a", Threat: ThreatMalwareDownload}}, true); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if got := cs.bodies[0].Anonymous; got != "1" {
		t.Errorf("anonymous = %q, want \"1\"", got)
	}
}
