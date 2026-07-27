package abuseipdb

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/netmatch"
)

// fakeRecorder is an in-memory ReportRecorder for orchestrator tests.
type fakeRecorder struct {
	mu       sync.Mutex
	reported map[string]time.Time
}

func newFakeRecorder() *fakeRecorder { return &fakeRecorder{reported: map[string]time.Time{}} }

func (f *fakeRecorder) AbuseIPDBReported(ip string, within time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	at, ok := f.reported[ip]
	if !ok {
		return false, nil
	}
	if within <= 0 {
		return true, nil
	}
	return time.Since(at) < within, nil
}

func (f *fakeRecorder) RecordAbuseIPDBReport(ip, status string, score int, cats []int, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reported[ip] = at
	return nil
}

// TestReportHappyPathAndDedup drives one confirmed brute-forcer through the
// orchestrator against a fake AbuseIPDB, then confirms a second run dedups it.
func TestReportHappyPathAndDedup(t *testing.T) {
	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		if r.Header.Get("Key") == "" {
			t.Errorf("missing Key header")
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.FormValue("ip") == "" || r.FormValue("categories") == "" {
			t.Errorf("missing ip/categories: %v", r.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"abuseConfidenceScore":100}}`))
	}))
	defer srv.Close()

	rec := newFakeRecorder()
	cands := []ReportCandidate{{
		SrcIP: "8.8.8.8", Playbook: "fast_dictionary_spray",
		ProbeScore: 90, EventCount: 400, UniqueUsers: 30,
	}}
	opts := Options{
		APIKey: "k", Endpoint: srv.URL, Categories: []int{18, 22},
		MinProbe: 60, Rewindow: time.Hour, RateLimit: time.Millisecond,
		Admin: netmatch.New(nil),
	}

	reported, skipped, err := Report(context.Background(), rec, cands, opts)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if reported != 1 || skipped != 0 {
		t.Fatalf("reported=%d skipped=%d (want 1/0)", reported, skipped)
	}
	if posts != 1 {
		t.Fatalf("expected 1 POST, got %d", posts)
	}

	// Second run: the recorder now shows it reported within the window → skip,
	// no new POST.
	reported2, skipped2, err := Report(context.Background(), rec, cands, opts)
	if err != nil {
		t.Fatalf("Report(2): %v", err)
	}
	if reported2 != 0 || skipped2 != 1 {
		t.Fatalf("second run reported=%d skipped=%d (want 0/1)", reported2, skipped2)
	}
	if posts != 1 {
		t.Fatalf("dedup should have prevented a 2nd POST, got %d", posts)
	}
}

// TestReportVetRejectsNeverPost confirms a vet-rejected candidate (admin IP)
// never reaches the network and is counted as skipped.
func TestReportVetRejectsNeverPost(t *testing.T) {
	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		w.Write([]byte(`{"data":{"abuseConfidenceScore":0}}`))
	}))
	defer srv.Close()

	rec := newFakeRecorder()
	cands := []ReportCandidate{{
		SrcIP: "10.0.0.5", Playbook: "fast_dictionary_spray",
		ProbeScore: 90, EventCount: 400, UniqueUsers: 30,
	}}
	opts := Options{
		APIKey: "k", Endpoint: srv.URL, Categories: []int{18, 22},
		MinProbe: 60, Rewindow: time.Hour, RateLimit: time.Millisecond,
		Admin: netmatch.New([]string{"10.0.0.0/8"}),
	}
	reported, skipped, err := Report(context.Background(), rec, cands, opts)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if reported != 0 || skipped != 1 {
		t.Fatalf("reported=%d skipped=%d (want 0/1)", reported, skipped)
	}
	if posts != 0 {
		t.Fatalf("vet-rejected candidate must never POST, got %d", posts)
	}
}

// TestReportRateLimitHalts confirms a 429 stops the batch, preserves counts,
// calls progress, and returns a machine-detectable error.
func TestReportRateLimitHalts(t *testing.T) {
	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"errors":[{"detail":"Daily rate limit"}]}`))
	}))
	defer srv.Close()

	rec := newFakeRecorder()
	cands := []ReportCandidate{
		{SrcIP: "8.8.8.8", Playbook: "dictionary_spray", ProbeScore: 90, EventCount: 400, UniqueUsers: 30},
		{SrcIP: "1.1.1.1", Playbook: "dictionary_spray", ProbeScore: 90, EventCount: 400, UniqueUsers: 30},
	}
	var progressCalls int
	var progressResult *Result
	var progressErr error
	opts := Options{
		APIKey: "k", Endpoint: srv.URL, MinProbe: 60, Rewindow: time.Hour,
		RateLimit: time.Millisecond, Admin: netmatch.New(nil),
		OnProgress: func(_ ReportCandidate, result *Result, err error) {
			progressCalls++
			progressResult = result
			progressErr = err
		},
	}
	reported, skipped, err := Report(context.Background(), rec, cands, opts)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Report error = %v, want ErrRateLimited", err)
	}
	if reported != 0 || skipped != 0 {
		t.Fatalf("429 counts = (%d reported, %d skipped), want (0, 0)", reported, skipped)
	}
	if posts != 1 {
		t.Fatalf("429 must halt batch after one POST, got %d", posts)
	}
	if progressCalls != 1 || progressResult == nil || !progressResult.RateLimited {
		t.Fatalf("progress = calls:%d result:%+v, want one rate-limited result", progressCalls, progressResult)
	}
	if !errors.Is(progressErr, ErrRateLimited) {
		t.Fatalf("progress error = %v, want ErrRateLimited", progressErr)
	}
}

// TestReportDryRunNoNetwork confirms --dry-run never POSTs.
func TestReportDryRunNoNetwork(t *testing.T) {
	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
	}))
	defer srv.Close()
	rec := newFakeRecorder()
	cands := []ReportCandidate{{SrcIP: "9.9.9.9", Playbook: "dictionary_spray", ProbeScore: 90, EventCount: 400, UniqueUsers: 30}}
	opts := Options{Endpoint: srv.URL, DryRun: true, MinProbe: 60, Rewindow: time.Hour, Admin: netmatch.New(nil)}
	if _, _, err := Report(context.Background(), rec, cands, opts); err != nil {
		t.Fatalf("Report dry-run: %v", err)
	}
	if posts != 0 {
		t.Fatalf("dry-run must not POST, got %d", posts)
	}
}
