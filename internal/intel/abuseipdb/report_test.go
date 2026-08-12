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
		LastSeen: vetNow.Add(-time.Hour),
	}}
	// Now is pinned so LastSeen stays inside the staleness gate no matter when the
	// suite runs; production leaves it unset and Report falls back to time.Now().
	opts := Options{
		APIKey: "k", Endpoint: srv.URL, Categories: []int{18, 22},
		MinProbe: 60, Rewindow: time.Hour, RateLimit: time.Millisecond,
		Admin: netmatch.New(nil), Now: vetNow,
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
	// LastSeen is fresh deliberately: this test must fail on the ADMIN reject, not
	// coincidentally on the staleness gate, or it would keep passing after the
	// admin check was removed.
	cands := []ReportCandidate{{
		SrcIP: "10.0.0.5", Playbook: "fast_dictionary_spray",
		ProbeScore: 90, EventCount: 400, UniqueUsers: 30,
		LastSeen: vetNow.Add(-time.Hour),
	}}
	opts := Options{
		APIKey: "k", Endpoint: srv.URL, Categories: []int{18, 22},
		MinProbe: 60, Rewindow: time.Hour, RateLimit: time.Millisecond,
		Admin: netmatch.New([]string{"10.0.0.0/8"}), Now: vetNow,
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
		{SrcIP: "8.8.8.8", Playbook: "dictionary_spray", ProbeScore: 90, EventCount: 400, UniqueUsers: 30,
			LastSeen: vetNow.Add(-time.Hour)},
		{SrcIP: "1.1.1.1", Playbook: "dictionary_spray", ProbeScore: 90, EventCount: 400, UniqueUsers: 30,
			LastSeen: vetNow.Add(-time.Hour)},
	}
	var progressCalls int
	var progressResult *Result
	var progressErr error
	opts := Options{
		APIKey: "k", Endpoint: srv.URL, MinProbe: 60, Rewindow: time.Hour,
		RateLimit: time.Millisecond, Admin: netmatch.New(nil), Now: vetNow,
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
	cands := []ReportCandidate{{SrcIP: "9.9.9.9", Playbook: "dictionary_spray", ProbeScore: 90, EventCount: 400,
		UniqueUsers: 30, LastSeen: vetNow.Add(-time.Hour)}}
	var previewed int
	opts := Options{
		Endpoint: srv.URL, DryRun: true, MinProbe: 60, Rewindow: time.Hour,
		Admin: netmatch.New(nil), Now: vetNow,
		OnProgress: func(_ ReportCandidate, _ *Result, err error) {
			if err == nil {
				previewed++
			}
		},
	}
	_, skipped, err := Report(context.Background(), rec, cands, opts)
	if err != nil {
		t.Fatalf("Report dry-run: %v", err)
	}
	if posts != 0 {
		t.Fatalf("dry-run must not POST, got %d", posts)
	}
	// "No POST" alone is also what a vet REJECT looks like, so assert the
	// candidate actually reached the dry-run branch. Otherwise this test would
	// keep passing even if every candidate were being silently refused.
	if previewed != 1 || skipped != 0 {
		t.Fatalf("dry-run previewed=%d skipped=%d, want 1/0: the candidate never "+
			"reached the dry-run branch, so 'no POST' proves nothing", previewed, skipped)
	}
}

// TestReportDedupSkipIsReported pins that the dedup skip explains itself. Every
// other skip path calls OnProgress; this one did not, so on real data a run that
// skipped 25 candidates printed only 14 reasons. The missing ones were the
// already-reported IPs — including the operator's top attacker, which made a
// working gate look like a broken one.
func TestReportDedupSkipIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"abuseConfidenceScore":100}}`))
	}))
	defer srv.Close()

	rec := newFakeRecorder()
	cands := []ReportCandidate{{SrcIP: "8.8.8.8", Playbook: "dictionary_spray", ProbeScore: 90,
		EventCount: 400, UniqueUsers: 30, LastSeen: vetNow.Add(-time.Hour)}}
	var reasons []string
	opts := Options{
		APIKey: "k", Endpoint: srv.URL, MinProbe: 60, Rewindow: time.Hour,
		RateLimit: time.Millisecond, Admin: netmatch.New(nil), Now: vetNow,
		OnProgress: func(_ ReportCandidate, _ *Result, err error) {
			if err != nil {
				reasons = append(reasons, err.Error())
			}
		},
	}
	// First run reports it and records it; second must skip WITH a reason.
	if _, _, err := Report(context.Background(), rec, cands, opts); err != nil {
		t.Fatalf("Report(1): %v", err)
	}
	reasons = nil
	_, skipped, err := Report(context.Background(), rec, cands, opts)
	if err != nil {
		t.Fatalf("Report(2): %v", err)
	}
	if skipped != 1 {
		t.Fatalf("skipped=%d, want 1", skipped)
	}
	if len(reasons) != 1 {
		t.Fatalf("dedup skip produced %d progress reasons, want 1: a counted skip with "+
			"no reason is indistinguishable to the operator from a vet bug", len(reasons))
	}
	if !contains(reasons[0], "already reported") {
		t.Errorf("dedup skip reason = %q, should say the IP was already reported", reasons[0])
	}
}

// TestReportUsesOneClockForTheBatch pins Options.Now: a paced run of many
// candidates must judge them all against the same instant. Without it, a batch
// long enough to straddle the day boundary of the staleness gate would report the
// head of the list and refuse the tail for no reason the operator can see.
func TestReportUsesOneClockForTheBatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"abuseConfidenceScore":100}}`))
	}))
	defer srv.Close()

	// Both sit just inside the bound relative to vetNow. Judged against a later
	// clock they would drop out.
	edge := vetNow.Add(-defaultMaxAgeDays * 24 * time.Hour).Add(2 * time.Minute)
	cands := []ReportCandidate{
		{SrcIP: "8.8.8.8", Playbook: "dictionary_spray", ProbeScore: 90, EventCount: 400, UniqueUsers: 30, LastSeen: edge},
		{SrcIP: "1.1.1.1", Playbook: "dictionary_spray", ProbeScore: 90, EventCount: 400, UniqueUsers: 30, LastSeen: edge},
	}
	reported, skipped, err := Report(context.Background(), newFakeRecorder(), cands, Options{
		APIKey: "k", Endpoint: srv.URL, MinProbe: 60, Rewindow: time.Hour,
		RateLimit: time.Millisecond, Admin: netmatch.New(nil), Now: vetNow,
	})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if reported != 2 || skipped != 0 {
		t.Fatalf("reported=%d skipped=%d, want 2/0: candidates equally fresh at the "+
			"start of the batch must not be judged against different clocks", reported, skipped)
	}
}

// TestReportMaxAgeDaysReachesVet confirms the Options knob is actually wired to
// the gate rather than accepted and dropped.
func TestReportMaxAgeDaysReachesVet(t *testing.T) {
	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"abuseConfidenceScore":100}}`))
	}))
	defer srv.Close()

	cands := []ReportCandidate{{SrcIP: "8.8.8.8", Playbook: "dictionary_spray", ProbeScore: 90,
		EventCount: 400, UniqueUsers: 30, LastSeen: vetNow.Add(-5 * 24 * time.Hour)}}
	opts := Options{
		APIKey: "k", Endpoint: srv.URL, MinProbe: 60, Rewindow: time.Hour,
		RateLimit: time.Millisecond, Admin: netmatch.New(nil), Now: vetNow,
		MaxAgeDays: 2,
	}
	reported, skipped, err := Report(context.Background(), newFakeRecorder(), cands, opts)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if reported != 0 || skipped != 1 || posts != 0 {
		t.Fatalf("reported=%d skipped=%d posts=%d, want 0/1/0: MaxAgeDays=2 should have "+
			"rejected a 5-day-old candidate before the network", reported, skipped, posts)
	}
}
