package abuseipdb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// dedupedIP/freshIP generate distinct PUBLIC addresses. They must be public:
// Vet hard-rejects private and reserved ranges as an account-strike risk, and
// that includes the RFC 5737 documentation blocks (192.0.2/24, 198.51.100/24,
// 203.0.113/24) — so the obvious "example IP" choices would make every
// candidate here fail the gate and mask what these tests are measuring.
func dedupedIP(i int) string { return "45.33.1." + strconv.Itoa(i+1) }
func freshIP(i int) string   { return "185.220.101." + strconv.Itoa(i+1) }

// reportableCandidate builds a candidate that clears Vet: a confirmed spray
// playbook, comfortably above every floor, seen minutes ago.
func reportableCandidate(ip string, now time.Time) ReportCandidate {
	return ReportCandidate{
		SrcIP:           ip,
		Playbook:        "fast_dictionary_spray",
		ProbeScore:      90,
		EventCount:      500,
		UniqueUsers:     40,
		AttemptsPerHour: 900,
		LastSeen:        now.Add(-10 * time.Minute),
	}
}

// recordingRecorder is a fakeRecorder that also keeps an ordered audit log of
// which IPs were actually recorded, so a test can assert WHICH candidates the
// budget was spent on — not merely how many.
type recordingRecorder struct {
	*fakeRecorder
	mu      sync.Mutex
	records []string
}

func newRecordingRecorder() *recordingRecorder {
	return &recordingRecorder{fakeRecorder: newFakeRecorder()}
}

func (r *recordingRecorder) RecordAbuseIPDBReport(ip, status string, score int, cats []int, at time.Time) error {
	r.mu.Lock()
	r.records = append(r.records, ip)
	r.mu.Unlock()
	return r.fakeRecorder.RecordAbuseIPDBReport(ip, status, score, cats, at)
}

// TestReportLimitBoundsReportsNotCandidates is the regression test for the
// --limit bug, the AbuseIPDB twin of the one fixed in bazaar.Share.
//
// The limit used to be applied by the CLI as `cands = cands[:limit]` BEFORE
// Report ran. Candidates arrive worst-offender-first (ordered by aggression),
// and the worst offenders are precisely the ones already sitting in the
// re-report window from the previous run — so the default --limit=25 spent its
// entire budget on dedup hits and reported nobody, while fresh brute-forcers
// waited just below the cut. A cap meant to bound API calls was instead
// bounding how far down the list we bothered to look.
//
// The fixture reproduces exactly that: 25 already-reported IPs ahead of 3
// fresh ones, with a limit of 2.
func TestReportLimitBoundsReportsNotCandidates(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":100}}`))
	}))
	defer srv.Close()

	now := time.Now()
	rec := newRecordingRecorder()
	var cands []ReportCandidate
	for i := 0; i < 25; i++ {
		ip := dedupedIP(i)
		// Pre-seed the dedup ledger: reported moments ago, inside the window.
		if err := rec.fakeRecorder.RecordAbuseIPDBReport(ip, "reported", 100, nil, now); err != nil {
			t.Fatal(err)
		}
		cands = append(cands, reportableCandidate(ip, now))
	}
	for i := 0; i < 3; i++ {
		cands = append(cands, reportableCandidate(freshIP(i), now))
	}
	// Drop the audit log so only this run's reports are counted; the dedup
	// state seeded above is what we want to keep.
	rec.records = nil

	var limitHit int
	reported, _, err := Report(context.Background(), rec, cands, Options{
		APIKey: "k", Endpoint: srv.URL,
		Rewindow:       24 * time.Hour,
		RateLimit:      time.Millisecond,
		MaxReports:     2,
		Now:            now,
		OnLimitReached: func(unexamined int) { limitHit = unexamined },
	})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if reported != 2 {
		t.Fatalf("reported = %d, want 2 — the limit must bound SUBMISSIONS. If this is 0, "+
			"the budget was spent on the 25 already-reported IPs ahead of the fresh ones, "+
			"which is the bug: a run that reported nobody while brute-forcers waited.", reported)
	}
	if got := posts.Load(); got != 2 {
		t.Errorf("network calls = %d, want 2 — the cap exists to bound API calls", got)
	}
	// One fresh candidate remains unexamined; the caller must be able to say so
	// rather than implying the backlog is clear.
	if limitHit != 1 {
		t.Errorf("OnLimitReached(unexamined) = %d, want 1 — a bounded run must not read "+
			"as an exhausted one", limitHit)
	}
	got := append([]string(nil), rec.records...)
	sort.Strings(got)
	if len(got) != 2 || got[0] != freshIP(0) || got[1] != freshIP(1) {
		t.Errorf("recorded %v, want the two un-deduped attackers (%s, %s)", got, freshIP(0), freshIP(1))
	}
}

// TestReportLimitCountsDryRunPreviews pins that --dry-run --limit N previews
// the same N candidates the real run would send. A dry run that showed more
// than the real run would report is a preview of a different operation.
func TestReportLimitCountsDryRunPreviews(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("dry-run hit the network")
	}))
	defer srv.Close()

	now := time.Now()
	var cands []ReportCandidate
	for i := 0; i < 5; i++ {
		cands = append(cands, reportableCandidate(freshIP(i), now))
	}
	previews := 0
	_, _, err := Report(context.Background(), newFakeRecorder(), cands, Options{
		APIKey: "k", Endpoint: srv.URL, DryRun: true,
		RateLimit: time.Millisecond, MaxReports: 2, Now: now,
		OnProgress: func(_ ReportCandidate, _ *Result, err error) {
			if err == nil {
				previews++
			}
		},
	})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if previews != 2 {
		t.Fatalf("dry-run previewed %d candidates under --limit=2, want 2", previews)
	}
}

// TestReportZeroLimitIsUnbounded pins that 0 keeps the "report everything"
// behaviour, which is what --limit=0 documents.
func TestReportZeroLimitIsUnbounded(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":100}}`))
	}))
	defer srv.Close()

	now := time.Now()
	var cands []ReportCandidate
	for i := 0; i < 4; i++ {
		cands = append(cands, reportableCandidate(freshIP(i), now))
	}
	limitFired := false
	reported, _, err := Report(context.Background(), newFakeRecorder(), cands, Options{
		APIKey: "k", Endpoint: srv.URL, RateLimit: time.Millisecond,
		MaxReports: 0, Now: now,
		OnLimitReached: func(int) { limitFired = true },
	})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if reported != 4 {
		t.Errorf("reported = %d, want 4 (MaxReports=0 means unbounded)", reported)
	}
	if limitFired {
		t.Error("OnLimitReached fired with no limit set")
	}
}

// TestReportLimitNotSpentOnVetRejections pins the other half of "bounds
// submissions": a candidate the gate REJECTS costs no API call, so it must not
// cost budget either. Truncation-before-Vet had this failure mode too — a
// dormant or admin IP at the top of the list silently consumed a slot.
func TestReportLimitNotSpentOnVetRejections(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":100}}`))
	}))
	defer srv.Close()

	now := time.Now()
	rec := newRecordingRecorder()
	// Three candidates Vet hard-rejects, ahead of two real ones.
	stale := reportableCandidate(dedupedIP(9), now)
	stale.LastSeen = now.Add(-31 * 24 * time.Hour) // dormant a month
	undated := reportableCandidate(dedupedIP(10), now)
	undated.LastSeen = time.Time{} // no timestamp at all
	private := reportableCandidate("192.168.1.50", now)

	cands := []ReportCandidate{
		stale, undated, private,
		reportableCandidate(freshIP(0), now),
		reportableCandidate(freshIP(1), now),
	}

	reported, skipped, err := Report(context.Background(), rec, cands, Options{
		APIKey: "k", Endpoint: srv.URL, RateLimit: time.Millisecond,
		Rewindow: 24 * time.Hour, MaxReports: 2, Now: now,
	})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if reported != 2 {
		t.Fatalf("reported = %d, want 2 — three Vet rejections ate the budget, but a "+
			"rejected candidate costs no API call and must cost no slot", reported)
	}
	if skipped != 3 {
		t.Errorf("skipped = %d, want 3 (stale, undated, private)", skipped)
	}
	got := append([]string(nil), rec.records...)
	sort.Strings(got)
	if len(got) != 2 || got[0] != freshIP(0) || got[1] != freshIP(1) {
		t.Errorf("recorded %v, want the two vettable attackers", got)
	}
}

// TestReportBudgetCountsAttemptsNotAcceptances pins the "counted on attempt"
// semantics that survived the first mutation pass: moving submitted++ after
// reported++ (count-on-acceptance) left the whole suite green, and under that
// mutant a run of transport errors makes --limit unbounded in POST attempts —
// hammering the API with exactly the calls the budget exists to bound. Five
// candidates, an upstream that fails every POST, budget 2: exactly 2 POSTs.
func TestReportBudgetCountsAttemptsNotAcceptances(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`upstream on fire`))
	}))
	defer srv.Close()

	now := time.Now()
	var cands []ReportCandidate
	for i := 0; i < 5; i++ {
		cands = append(cands, reportableCandidate(freshIP(i), now))
	}
	reported, _, _ := Report(context.Background(), newFakeRecorder(), cands, Options{
		APIKey: "k", Endpoint: srv.URL, RateLimit: time.Millisecond,
		MaxReports: 2, Now: now,
	})
	if got := posts.Load(); got != 2 {
		t.Fatalf("POSTs = %d, want 2 — a rejected POST was still a call we made, so it must "+
			"consume budget; counting on acceptance turns --limit into unbounded attempts "+
			"whenever the upstream is failing", got)
	}
	if reported != 0 {
		t.Errorf("reported = %d, want 0 (every POST failed)", reported)
	}
}
