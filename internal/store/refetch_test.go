package store

import (
	"errors"
	"testing"
	"time"
)

func TestNextRefetchSchedule(t *testing.T) {
	first := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	h := time.Hour
	d := 24 * h
	cases := []struct {
		name      string
		age       time.Duration
		failures  int
		wantState string
		wantNext  time.Duration // offset from now; 0 for done
	}{
		{"age0", 0, 0, "active", h},
		{"age23h", 23 * h, 0, "active", h},
		{"age25h", 25 * h, 0, "active", 6 * h},
		{"age6d", 6 * d, 0, "active", 6 * h},
		{"age7d01m", 7*d + time.Minute, 0, "done", 0},
		{"age9d23h", 9*d + 23*h, 0, "done", 0},
		{"fail5 early", 2 * h, 5, "active", h},
		{"fail6 early", 2 * h, 6, "offline", d},
		{"fail6 day8", 8 * d, 6, "offline", d},
		{"fail6 day9 crosses 10", 9*d + h, 6, "done", 0},
		{"offline past day10", 10*d + h, 6, "done", 0},
		{"age10d", 10 * d, 0, "done", 0},
		{"age6d20h crosses day 7 still active", 6*d + 20*h, 0, "active", 6 * h},
	}
	for _, c := range cases {
		now := first.Add(c.age)
		next, state := NextRefetch(first, now, c.failures)
		if state != c.wantState {
			t.Errorf("%s: state=%s want %s", c.name, state, c.wantState)
			continue
		}
		if c.wantNext == 0 {
			if !next.IsZero() {
				t.Errorf("%s: next=%v want zero", c.name, next)
			}
			continue
		}
		if !next.Equal(now.Add(c.wantNext)) {
			t.Errorf("%s: next=%v want %v", c.name, next, now.Add(c.wantNext))
		}
	}
}

func refetchRow(t *testing.T, st *Store, url string) (state string, failures, checks int, next, last, lastSHA string, leased bool) {
	t.Helper()
	var lease *string
	var lastp, shap *string
	if err := st.db.QueryRow(`SELECT state, consecutive_failures, checks, next_check_at, last_check_at, last_sha256, lease_until
FROM refetch_schedule WHERE url=?`, url).Scan(&state, &failures, &checks, &next, &lastp, &shap, &lease); err != nil {
		t.Fatal(err)
	}
	if lastp != nil {
		last = *lastp
	}
	if shap != nil {
		lastSHA = *shap
	}
	return state, failures, checks, next, last, lastSHA, lease != nil
}

func countRefetch(t *testing.T, st *Store) int {
	t.Helper()
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM refetch_schedule`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSeedRefetchOnlyHTTPAndIdempotent(t *testing.T) {
	st := newTestStore(t, "seed.db")
	first := time.Now().UTC().Add(-time.Minute)
	for _, u := range []string{"cowrie-download:abc", "cowrie-event:1", "ftp://x/y", ""} {
		if err := st.SeedRefetch(u, first, "aa"); err != nil {
			t.Fatal(err)
		}
	}
	if n := countRefetch(t, st); n != 0 {
		t.Fatalf("non-http seeded %d rows", n)
	}
	u := "HTTP://198.51.100.9/x"
	if err := st.SeedRefetch(u, first, "aa"); err != nil {
		t.Fatal(err)
	}
	if err := st.SeedRefetch(u, first.Add(time.Hour), "bb"); err != nil {
		t.Fatal(err)
	}
	if n := countRefetch(t, st); n != 1 {
		t.Fatalf("rows=%d want 1", n)
	}
	state, _, checks, next, _, sha, leased := refetchRow(t, st, u)
	if state != "active" || checks != 0 || sha != "aa" || leased || next != captureTime(first.Add(time.Hour)) {
		t.Fatalf("seed row = %s %d %q %v %s", state, checks, sha, leased, next)
	}
}

func seedFetched(t *testing.T, st *Store, u, sha string, first time.Time) {
	t.Helper()
	if err := st.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}
	ft := captureTime(first)
	if _, err := st.db.Exec(`INSERT INTO artifacts(ts,src_ip,session_id,actor_id,url,local_path,sha256,size_bytes,origin,status,created_at,attempt_count,first_observed_at,last_seen_at,last_successful_fetch_at,parent_sha256,depth)
VALUES(?,?,?,?,?,?,?,4096,'quarantine_fetch','fetched',?,1,?,?,?,?,?)`,
		ft, "203.0.113.5", "sess-0", "cowrie:hh", u, "/e/q/"+sha, sha, ft, ft, ft, ft, "parentsha", 1); err != nil {
		t.Fatal(err)
	}
	if err := st.SeedRefetch(u, first, sha); err != nil {
		t.Fatal(err)
	}
}

func TestClaimRefetchDueAndLease(t *testing.T) {
	st := newTestStore(t, "claim.db")
	first := time.Now().UTC().Add(-10 * time.Minute)
	u := "http://198.51.100.9/bins/x"
	seedFetched(t, st, u, "aa", first)

	job, err := st.ClaimRefetch(first.Add(30*time.Minute), time.Minute)
	if err != nil || job != nil {
		t.Fatalf("before due: %v %v", job, err)
	}
	now := first.Add(time.Hour + time.Second)
	job, err = st.ClaimRefetch(now, time.Minute)
	if err != nil || job == nil {
		t.Fatalf("due claim: %v %v", job, err)
	}
	if job.URL != u || job.Checks != 0 || !job.FirstSeen.Equal(first.Truncate(time.Nanosecond)) {
		t.Fatalf("job = %+v", job)
	}
	if again, err := st.ClaimRefetch(now.Add(30*time.Second), time.Minute); err != nil || again != nil {
		t.Fatalf("claim inside lease: %v %v", again, err)
	}
	// After the lease lapses the row is claimable again.
	if again, err := st.ClaimRefetch(now.Add(2*time.Minute), time.Minute); err != nil || again == nil {
		t.Fatalf("claim after lease: %v %v", again, err)
	}
}

func TestCompleteRefetchSameSHA(t *testing.T) {
	st := newTestStore(t, "same.db")
	first := time.Now().UTC().Add(-2 * time.Hour)
	u := "http://198.51.100.9/bins/x"
	seedFetched(t, st, u, "aa", first)
	now := first.Add(time.Hour + time.Second)
	job, err := st.ClaimRefetch(now, time.Minute)
	if err != nil || job == nil {
		t.Fatal(job, err)
	}
	newPayload, err := st.CompleteRefetch(*job, now, RefetchOutcome{OK: true, SHA256: "aa", LocalPath: "/e/q/aa", Size: 4096})
	if err != nil || newPayload {
		t.Fatalf("same sha: %v %v", newPayload, err)
	}
	var rows int
	var lastOK, lastSeen string
	if err := st.db.QueryRow(`SELECT COUNT(*), MAX(last_successful_fetch_at), MAX(last_seen_at) FROM artifacts WHERE url=?`, u).Scan(&rows, &lastOK, &lastSeen); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || lastOK != captureTime(now) || lastSeen != captureTime(now) {
		t.Fatalf("rows=%d lastOK=%s lastSeen=%s", rows, lastOK, lastSeen)
	}
	state, failures, checks, next, last, sha, leased := refetchRow(t, st, u)
	if state != "active" || failures != 0 || checks != 1 || sha != "aa" || leased || last != captureTime(now) || next != captureTime(now.Add(time.Hour)) {
		t.Fatalf("schedule = %s %d %d %s %s %s %v", state, failures, checks, next, last, sha, leased)
	}
	// The same job cannot complete twice.
	if _, err := st.CompleteRefetch(*job, now, RefetchOutcome{OK: true, SHA256: "aa"}); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("double completion: %v", err)
	}
}

func TestCompleteRefetchNewSHAInsertsEpoch(t *testing.T) {
	st := newTestStore(t, "new.db")
	first := time.Now().UTC().Add(-2 * time.Hour)
	u := "http://198.51.100.9/bins/x"
	seedFetched(t, st, u, "aa", first)
	now := first.Add(time.Hour + time.Second)
	job, err := st.ClaimRefetch(now, time.Minute)
	if err != nil || job == nil {
		t.Fatal(job, err)
	}
	newPayload, err := st.CompleteRefetch(*job, now, RefetchOutcome{OK: true, SHA256: "bb", LocalPath: "/e/q/bb", Size: 777, Detail: "rotated"})
	if err != nil || !newPayload {
		t.Fatalf("new sha: %v %v", newPayload, err)
	}
	var srcIP, sess, actor, parent, origin, status, path, firstObs, attempted, fetched, detail string
	var depth, attempts int
	var size int64
	if err := st.db.QueryRow(`SELECT src_ip, session_id, actor_id, parent_sha256, depth, first_observed_at, origin, status, attempt_count,
  last_fetch_attempt_at, last_successful_fetch_at, local_path, size_bytes, detail
FROM artifacts WHERE url=? AND fetch_epoch=1 AND sha256='bb'`, u).Scan(&srcIP, &sess, &actor, &parent, &depth, &firstObs, &origin, &status, &attempts,
		&attempted, &fetched, &path, &size, &detail); err != nil {
		t.Fatal(err)
	}
	if srcIP != "203.0.113.5" || sess != "sess-0" || actor != "cowrie:hh" || parent != "parentsha" || depth != 1 || firstObs != captureTime(first) {
		t.Fatalf("provenance not copied: %s %s %s %s %d %s", srcIP, sess, actor, parent, depth, firstObs)
	}
	if origin != "quarantine_fetch" || status != "fetched" || attempts != 1 || attempted != captureTime(now) || fetched != captureTime(now) ||
		path != "/e/q/bb" || size != 777 || detail != "rotated" {
		t.Fatalf("epoch-1 row: %s %s %d %s %s %s %d %s", origin, status, attempts, attempted, fetched, path, size, detail)
	}
	if _, _, _, _, _, sha, _ := refetchRow(t, st, u); sha != "bb" {
		t.Fatalf("last_sha256=%s", sha)
	}

	// The next check sees the rotated payload as already present; a third
	// sha lands at epoch 2.
	now2 := now.Add(time.Hour + time.Second)
	job, err = st.ClaimRefetch(now2, time.Minute)
	if err != nil || job == nil {
		t.Fatal(job, err)
	}
	if np, err := st.CompleteRefetch(*job, now2, RefetchOutcome{OK: true, SHA256: "bb"}); err != nil || np {
		t.Fatalf("repeat of epoch-1 sha: %v %v", np, err)
	}
	now3 := now2.Add(time.Hour + time.Second)
	job, _ = st.ClaimRefetch(now3, time.Minute)
	if np, err := st.CompleteRefetch(*job, now3, RefetchOutcome{OK: true, SHA256: "cc"}); err != nil || !np {
		t.Fatalf("third sha: %v %v", np, err)
	}
	var maxEpoch int
	if err := st.db.QueryRow(`SELECT MAX(fetch_epoch) FROM artifacts WHERE url=?`, u).Scan(&maxEpoch); err != nil || maxEpoch != 2 {
		t.Fatalf("max epoch=%d %v", maxEpoch, err)
	}
}

// A failed row carrying a sha (e.g. a stale failed re-fetch) is not proof
// the payload is held; only fetched rows count as "already present".
func TestCompleteRefetchIgnoresNonFetchedSHA(t *testing.T) {
	st := newTestStore(t, "nonfetched.db")
	first := time.Now().UTC().Add(-2 * time.Hour)
	u := "http://198.51.100.9/bins/x"
	seedFetched(t, st, u, "aa", first)
	if _, err := st.db.Exec(`INSERT INTO artifacts(ts,url,origin,status,created_at,fetch_epoch,sha256) VALUES(?,?,'quarantine_fetch','failed',?,5,'zz')`,
		captureTime(first), u, captureTime(first)); err != nil {
		t.Fatal(err)
	}
	now := first.Add(time.Hour + time.Second)
	job, _ := st.ClaimRefetch(now, time.Minute)
	np, err := st.CompleteRefetch(*job, now, RefetchOutcome{OK: true, SHA256: "zz"})
	if err != nil || !np {
		t.Fatalf("sha on a failed row counted as held: %v %v", np, err)
	}
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM artifacts WHERE url=? AND fetch_epoch=6 AND status='fetched' AND sha256='zz'`, u).Scan(&n); err != nil || n != 1 {
		t.Fatalf("epoch-6 row count=%d %v", n, err)
	}
}

func TestCompleteRefetchFailuresGoOffline(t *testing.T) {
	st := newTestStore(t, "offline.db")
	first := time.Now().UTC().Add(-time.Minute)
	u := "http://198.51.100.9/bins/x"
	seedFetched(t, st, u, "aa", first)
	now := first.Add(time.Hour + time.Second)
	for i := 1; i <= 6; i++ {
		job, err := st.ClaimRefetch(now, time.Minute)
		if err != nil || job == nil {
			t.Fatalf("claim %d: %v %v", i, job, err)
		}
		if np, err := st.CompleteRefetch(*job, now, RefetchOutcome{Detail: "connection refused"}); err != nil || np {
			t.Fatalf("fail %d: %v %v", i, np, err)
		}
		state, failures, checks, next, _, _, _ := refetchRow(t, st, u)
		want := "active"
		wantNext := now.Add(time.Hour)
		if i == 6 {
			want = "offline"
			wantNext = now.Add(24 * time.Hour)
		}
		if state != want || failures != i || checks != i || next != captureTime(wantNext) {
			t.Fatalf("after %d failures: %s %d %d %s", i, state, failures, checks, next)
		}
		now = wantNext.Add(time.Second)
	}
	// A success resets the failure streak.
	job, _ := st.ClaimRefetch(now, time.Minute)
	if _, err := st.CompleteRefetch(*job, now, RefetchOutcome{OK: true, SHA256: "aa"}); err != nil {
		t.Fatal(err)
	}
	if state, failures, _, _, _, _, _ := refetchRow(t, st, u); state != "active" || failures != 0 {
		t.Fatalf("after success: %s %d", state, failures)
	}
}

func TestCompleteRefetchDoneKeepsLastCheckAndIsNeverClaimed(t *testing.T) {
	st := newTestStore(t, "done.db")
	first := time.Now().UTC().Add(-8 * 24 * time.Hour)
	u := "http://198.51.100.9/bins/x"
	seedFetched(t, st, u, "aa", first)
	now := time.Now().UTC()
	job, err := st.ClaimRefetch(now, time.Minute)
	if err != nil || job == nil {
		t.Fatal(job, err)
	}
	if _, err := st.CompleteRefetch(*job, now, RefetchOutcome{OK: true, SHA256: "aa"}); err != nil {
		t.Fatal(err)
	}
	state, _, _, next, last, _, leased := refetchRow(t, st, u)
	if state != "done" || next != captureTime(now) || last != captureTime(now) || leased {
		t.Fatalf("done row: %s %s %s %v", state, next, last, leased)
	}
	if j, err := st.ClaimRefetch(now.Add(365*24*time.Hour), time.Minute); err != nil || j != nil {
		t.Fatalf("done row claimed: %v %v", j, err)
	}
}

func TestCompleteRefetchStaleChecks(t *testing.T) {
	st := newTestStore(t, "stale.db")
	first := time.Now().UTC().Add(-2 * time.Hour)
	u := "http://198.51.100.9/bins/x"
	seedFetched(t, st, u, "aa", first)
	now := first.Add(time.Hour + time.Second)
	job, err := st.ClaimRefetch(now, time.Minute)
	if err != nil || job == nil {
		t.Fatal(job, err)
	}
	stale := *job
	stale.Checks++
	if _, err := st.CompleteRefetch(stale, now, RefetchOutcome{OK: true, SHA256: "bb"}); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("stale checks: %v", err)
	}
	// After the lease lapses, the original holder is fenced out too.
	if _, err := st.CompleteRefetch(*job, now.Add(2*time.Minute), RefetchOutcome{OK: true, SHA256: "bb"}); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("expired lease: %v", err)
	}
	// A reclaim after expiry fences the first holder even though checks
	// did not move.
	job2, err := st.ClaimRefetch(now.Add(2*time.Minute), time.Minute)
	if err != nil || job2 == nil {
		t.Fatal(job2, err)
	}
	if _, err := st.CompleteRefetch(*job, now.Add(2*time.Minute), RefetchOutcome{OK: true, SHA256: "bb"}); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("superseded holder: %v", err)
	}
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM artifacts WHERE url=?`, u).Scan(&n); err != nil || n != 1 {
		t.Fatalf("stale completion wrote artifacts: %d %v", n, err)
	}
	if _, err := st.CompleteRefetch(*job2, now.Add(2*time.Minute), RefetchOutcome{OK: true, SHA256: "aa"}); err != nil {
		t.Fatal(err)
	}
}

func TestCompleteArtifactCaptureSeedsRefetch(t *testing.T) {
	st := newTestStore(t, "capseed.db")
	if err := st.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	first := now.Add(-5 * time.Minute)
	for _, u := range []string{"http://198.51.100.7/a.sh", "cowrie-download:deadbeef"} {
		if _, err := st.db.Exec(`INSERT INTO artifacts(ts,url,origin,status,created_at,attempt_count,first_observed_at) VALUES(?,?,'quarantine_fetch','pending',?,0,?)`,
			captureTime(first), u, captureTime(first), captureTime(first)); err != nil {
			t.Fatal(err)
		}
		if err := st.ClaimArtifactCapture(u, now, now.Add(time.Minute), 0); err != nil {
			t.Fatal(err)
		}
		if err := st.CompleteArtifactCapture(u, 1, "fetched", "", "/e/q/aa", "aa", 100, nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := countRefetch(t, st); n != 1 {
		t.Fatalf("schedule rows=%d want 1", n)
	}
	state, _, _, next, _, sha, _ := refetchRow(t, st, "http://198.51.100.7/a.sh")
	if state != "active" || sha != "aa" || next != captureTime(first.Add(time.Hour)) {
		t.Fatalf("seeded row: %s %s %s", state, sha, next)
	}

	// A failed completion seeds nothing; a stale completion seeds nothing.
	u := "http://198.51.100.7/b.sh"
	if _, err := st.db.Exec(`INSERT INTO artifacts(ts,url,origin,status,created_at,attempt_count) VALUES(?,?,'quarantine_fetch','pending',?,0)`,
		captureTime(first), u, captureTime(first)); err != nil {
		t.Fatal(err)
	}
	if err := st.ClaimArtifactCapture(u, now, now.Add(time.Minute), 0); err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteArtifactCapture(u, 1, "failed", "x", "", "", 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteArtifactCapture(u, 1, "fetched", "", "/e", "bb", 1, nil); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("stale: %v", err)
	}
	if n := countRefetch(t, st); n != 1 {
		t.Fatalf("schedule rows=%d want 1", n)
	}
}
