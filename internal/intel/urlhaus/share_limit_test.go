package urlhaus

import (
	"context"
	"strconv"
	"testing"
	"time"
)

// freshCandidate builds a candidate that clears Vet with Share's own wall
// clock (unlike goodCandidate, whose FetchedAt is pinned to the fixed vetNow
// used by the pure Vet tests).
func freshCandidate(i int) Candidate {
	return Candidate{
		URL:       "http://185.7.214." + strconv.Itoa(10+i) + "/bins/x86",
		SHA256:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		SizeBytes: 45000,
		Origin:    "quarantine_fetch",
		Status:    "fetched",
		// Pinned to vetNow (not time.Now()) so the fixture cannot age past the
		// active-days window as wall-clock time passes — the time-bomb that hit
		// the original share_test. Every Share call below passes Now: vetNow.
		FetchedAt: vetNow.Add(-1 * time.Hour),
		FileKind:  "ELF",
	}
}

// unvettable builds a candidate Vet hard-rejects (URL shortener) — the shape
// that could occupy --limit slots when the bound lived in the candidate QUERY,
// since the SQL replicates dedup but not the shortener/private-host rejects.
func unvettable(i int) Candidate {
	c := freshCandidate(i)
	c.URL = "https://bit.ly/x" + strconv.Itoa(i)
	return c
}

// TestShareLimitBoundsSubmissionsNotCandidates is the urlhaus twin of
// bazaar.MaxUploads / abuseipdb.MaxReports: with three unvettable URLs ahead
// of three vettable ones and a budget of 2, the run must submit 2 — not spend
// its slots on the rejects at the head of the list.
func TestShareLimitBoundsSubmissionsNotCandidates(t *testing.T) {
	srv := newCaptureServer(t)
	rec := newFakeRecorder()

	cands := []Candidate{
		unvettable(0), unvettable(1), unvettable(2),
		freshCandidate(0), freshCandidate(1), freshCandidate(2),
	}
	var limitHit int
	submitted, skipped, err := Share(context.Background(), rec, cands, Options{
		APIKey: "k", Endpoint: srv.URL, RateLimit: time.Millisecond,
		MaxSubmissions: 2, Now: vetNow,
		OnLimitReached: func(unexamined int) { limitHit = unexamined },
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 2 {
		t.Fatalf("submitted = %d, want 2 — the limit must bound SUBMISSIONS; if this is 0, "+
			"the budget was spent on the unvettable URLs at the head of the list", submitted)
	}
	if skipped != 3 {
		t.Errorf("skipped = %d, want 3 (the shorteners) — a Vet reject costs no slot", skipped)
	}
	// freshCandidate(2) cleared nothing yet: it sits beyond the spent budget.
	if limitHit != 1 {
		t.Errorf("OnLimitReached(unexamined) = %d, want 1 — a bounded run must not read as exhausted", limitHit)
	}
	if got := len(srv.allEntries()); got != 2 {
		t.Errorf("entries POSTed = %d, want 2 — the cap exists to bound what ships", got)
	}
}

// TestShareZeroLimitIsUnbounded pins that 0 keeps the submit-everything
// behaviour --limit=0 documents.
func TestShareZeroLimitIsUnbounded(t *testing.T) {
	srv := newCaptureServer(t)
	rec := newFakeRecorder()
	cands := []Candidate{freshCandidate(0), freshCandidate(1), freshCandidate(2)}
	limitFired := false
	submitted, _, err := Share(context.Background(), rec, cands, Options{
		APIKey: "k", Endpoint: srv.URL, RateLimit: time.Millisecond,
		MaxSubmissions: 0, Now: vetNow,
		OnLimitReached: func(int) { limitFired = true },
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 3 {
		t.Errorf("submitted = %d, want 3 (MaxSubmissions=0 means unbounded)", submitted)
	}
	if limitFired {
		t.Error("OnLimitReached fired with no limit set")
	}
}

// TestShareLimitCountsDryRunPreviews pins that --dry-run --limit N previews
// exactly the N URLs a real run would submit.
func TestShareLimitCountsDryRunPreviews(t *testing.T) {
	rec := newFakeRecorder()
	cands := []Candidate{
		freshCandidate(0), freshCandidate(1), freshCandidate(2), freshCandidate(3),
	}
	previews := 0
	_, _, err := Share(context.Background(), rec, cands, Options{
		DryRun: true, RateLimit: time.Millisecond, MaxSubmissions: 2, Now: vetNow,
		OnProgress: func(_ Candidate, submitted bool, _ string) {
			if submitted {
				previews++
			}
		},
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if previews != 2 {
		t.Fatalf("dry-run previewed %d URLs under --limit=2, want 2", previews)
	}
}
