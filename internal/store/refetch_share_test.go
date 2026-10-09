package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Cross-feature tests from the Phase C final review: each joins a re-fetched
// or harvested row to what the share path and the schedule see.

func sharePolicyForTest() SharePolicy {
	return SharePolicy{MinBytes: 64, Origins: []string{"cowrie_download", "cowrie_file_download", "quarantine_fetch"}}
}

// C1: a sample first fetched 16 days ago and re-fetched with the same hash
// yesterday is not a share candidate (outside the 10-day window), and the
// funnel's captured stage does not count it. Before the fix the re-fetch
// moved last_successful_fetch_at, which the pool, Vet's ObservedAt and the
// funnel read, so the sample looked 1 day old.
func TestSameHashRefetchDoesNotRefreshShareFreshness(t *testing.T) {
	st := newTestStore(t, "c1.db")
	if err := st.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	old := now.Add(-16 * 24 * time.Hour)
	u := "http://198.51.100.9/bins/x86"
	if _, err := st.db.Exec(`INSERT INTO artifacts(ts,src_ip,session_id,url,local_path,sha256,size_bytes,origin,status,created_at,attempt_count,first_observed_at,last_seen_at,last_successful_fetch_at)
VALUES(?,?,?,?,?,?,4096,'quarantine_fetch','fetched',?,1,?,?,?)`,
		captureTime(old), "203.0.113.5", "sess-0", u, "/e/q/aa", "aa", captureTime(old), captureTime(old), captureTime(old), captureTime(old)); err != nil {
		t.Fatal(err)
	}
	// The schedule row is placed so yesterday's check is inside its window;
	// only the artifact's own capture time is old.
	yesterday := now.Add(-24 * time.Hour)
	seedAt(t, st, u, yesterday.Add(-2*time.Hour), yesterday.Add(-2*time.Hour), "aa")
	job, err := st.ClaimRefetch(yesterday, time.Minute)
	if err != nil || job == nil {
		t.Fatalf("claim: %+v %v", job, err)
	}
	if np, err := st.CompleteRefetch(*job, yesterday, RefetchOutcome{OK: true, SHA256: "aa", LocalPath: "/e/q/aa", Size: 4096}); err != nil || np {
		t.Fatalf("same-hash re-fetch: %v %v", np, err)
	}

	var lastOK, lastRefetch string
	if err := st.db.QueryRow(`SELECT last_successful_fetch_at, last_refetch_at FROM artifacts WHERE url=?`, u).Scan(&lastOK, &lastRefetch); err != nil {
		t.Fatal(err)
	}
	if lastOK != captureTime(old) || lastRefetch != captureTime(yesterday) {
		t.Fatalf("last_successful_fetch_at=%s (want write-once %s), last_refetch_at=%s", lastOK, captureTime(old), lastRefetch)
	}

	pol := sharePolicyForTest()
	pool, err := st.ArtifactsForShare(now.Add(-10*24*time.Hour), pol)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range pool {
		if a.SHA256 == "aa" {
			t.Fatalf("a 16-day-old sample re-fetched yesterday is in the bazaar pool: fetched %s", a.LastSuccessfulFetchAt)
		}
	}
	if a, err := st.GetArtifactForShareBySHA("aa", pol); err != nil || !a.LastSuccessfulFetchAt.Equal(old.Truncate(time.Nanosecond)) {
		t.Fatalf("the share row's freshness must stay the first fetch: %+v %v", a, err)
	}
	for _, win := range []time.Duration{24 * time.Hour, 7 * 24 * time.Hour} {
		got, err := st.PayloadFunnel(context.Background(), now.Add(-win), pol)
		if err != nil {
			t.Fatal(err)
		}
		if got.Captured != 0 || got.NewPayloads != 0 {
			t.Fatalf("funnel %s counted a re-fetch as a capture: captured=%d new=%d", win, got.Captured, got.NewPayloads)
		}
	}
}

// I1: rows first seen 11 and 60 days ago (left active while re-fetching was
// off or the daemon was down) are never returned by ClaimRefetch and end done.
func TestClaimRefetchSettlesOverdueRowsWithoutFetching(t *testing.T) {
	st := newTestStore(t, "i1.db")
	now := time.Now().UTC()
	for _, age := range []time.Duration{11 * 24 * time.Hour, 60 * 24 * time.Hour} {
		u := fmt.Sprintf("http://198.51.100.9/old-%d", int(age.Hours()))
		if _, err := st.db.Exec(`INSERT INTO refetch_schedule(url, first_seen_at, next_check_at, state) VALUES(?,?,?,'active')`,
			u, captureTime(now.Add(-age)), captureTime(now.Add(-age).Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	offline := "http://198.51.100.9/offline-12d"
	if _, err := st.db.Exec(`INSERT INTO refetch_schedule(url, first_seen_at, next_check_at, state, consecutive_failures) VALUES(?,?,?,'offline',6)`,
		offline, captureTime(now.Add(-12*24*time.Hour)), captureTime(now.Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	if j, err := st.ClaimRefetch(now, time.Minute); err != nil || j != nil {
		t.Fatalf("an overdue row was claimed: %+v %v", j, err)
	}
	rows, err := st.db.Query(`SELECT url, state, lease_until IS NULL FROM refetch_schedule`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var u, state string
		var unleased bool
		if err := rows.Scan(&u, &state, &unleased); err != nil {
			t.Fatal(err)
		}
		n++
		if state != "done" || !unleased {
			t.Errorf("%s: state=%s unleased=%v, want done and unleased", u, state, unleased)
		}
	}
	if n != 3 {
		t.Fatalf("rows=%d", n)
	}
	// A row still inside the window is claimed as before.
	fresh := "http://198.51.100.9/fresh"
	seedAt(t, st, fresh, now.Add(-2*time.Hour), now.Add(-2*time.Hour), "aa")
	if j, err := st.ClaimRefetch(now, time.Minute); err != nil || j == nil || j.URL != fresh {
		t.Fatalf("fresh row: %+v %v", j, err)
	}
}

// I1: the claim query repeats the age bound, so an overdue row the bounded
// settle has not reached yet is still never claimed.
func TestClaimRefetchSkipsOverdueRowsBeyondTheSettleChunk(t *testing.T) {
	st := newTestStore(t, "i1chunk.db")
	now := time.Now().UTC()
	tx, err := st.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < refetchSettleChunk+5; i++ {
		first := now.Add(-11 * 24 * time.Hour)
		if _, err := tx.Exec(`INSERT INTO refetch_schedule(url, first_seen_at, next_check_at, state) VALUES(?,?,?,'active')`,
			fmt.Sprintf("http://198.51.100.9/o/%04d", i), captureTime(first), captureTime(first.Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// A due row inside the window, ordered after every overdue row: an
	// overdue row reaching the claim would be picked first and block it.
	fresh := "http://198.51.100.9/fresh"
	seedAt(t, st, fresh, now.Add(-2*time.Hour), now.Add(-2*time.Hour), "aa")
	if j, err := st.ClaimRefetch(now, time.Minute); err != nil || j == nil || j.URL != fresh {
		t.Fatalf("claim with overdue rows past the settle chunk: %+v %v, want the fresh row", j, err)
	}
	const overdueActive = `SELECT COUNT(*) FROM refetch_schedule WHERE state='active' AND url != 'http://198.51.100.9/fresh'`
	var active int
	if err := st.db.QueryRow(overdueActive).Scan(&active); err != nil || active != 5 {
		t.Fatalf("after one bounded settle: active=%d (%v), want 5", active, err)
	}
	// The fresh row's lease has lapsed by now; it is the only claimable row.
	if j, err := st.ClaimRefetch(now.Add(2*time.Minute), time.Minute); err != nil || (j != nil && j.URL != fresh) {
		t.Fatalf("second claim: %+v %v", j, err)
	}
	if err := st.db.QueryRow(overdueActive).Scan(&active); err != nil || active != 0 {
		t.Fatalf("after two settles: active=%d (%v)", active, err)
	}
}

// I1: retention also removes rows in any state that are past day 10 and
// older than the retention cutoff (seeded while capture.refetch was off,
// never claimed), and keeps young ones.
func TestMaintenancePurgeDropsAgedRefetchRowsInAnyState(t *testing.T) {
	st := newTestStore(t, "i1purge.db")
	now := time.Now().UTC()
	ins := func(u, state string, age time.Duration) {
		t.Helper()
		first := now.Add(-age)
		if _, err := st.db.Exec(`INSERT INTO refetch_schedule(url, first_seen_at, next_check_at, state) VALUES(?,?,?,?)`,
			u, captureTime(first), captureTime(first.Add(time.Hour)), state); err != nil {
			t.Fatal(err)
		}
	}
	ins("http://x/active-45d", "active", 45*24*time.Hour)
	ins("http://x/offline-45d", "offline", 45*24*time.Hour)
	ins("http://x/active-12d", "active", 12*24*time.Hour) // past day 10, inside retention: settled by claims, kept here
	ins("http://x/active-2d", "active", 2*24*time.Hour)
	if err := st.MaintenancePurgeContext(context.Background(), 30); err != nil {
		t.Fatal(err)
	}
	var kept []string
	rows, err := st.db.Query(`SELECT url FROM refetch_schedule ORDER BY url`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			t.Fatal(err)
		}
		kept = append(kept, u)
	}
	if fmt.Sprint(kept) != "[http://x/active-12d http://x/active-2d]" {
		t.Fatalf("kept %v", kept)
	}
}

// I3: the fourth distinct new payload a URL yields by re-fetch settles its
// schedule done.
func TestCompleteRefetchCapsNewPayloadsPerURL(t *testing.T) {
	st := newTestStore(t, "i3cap.db")
	first := time.Now().UTC().Add(-2 * time.Hour)
	u := "http://198.51.100.9/bins/rot"
	seedFetched(t, st, u, "s0", first)
	now := first.Add(time.Hour + time.Second)
	for i := 1; i <= RefetchMaxNewPayloads; i++ {
		job, err := st.ClaimRefetch(now, time.Minute)
		if err != nil || job == nil {
			t.Fatalf("claim %d: %+v %v", i, job, err)
		}
		np, err := st.CompleteRefetch(*job, now, RefetchOutcome{OK: true, SHA256: fmt.Sprintf("s%d", i), LocalPath: "/e/q/x", Size: 4096})
		if err != nil || !np {
			t.Fatalf("payload %d: %v %v", i, np, err)
		}
		state, _, _, _, _, _, _ := refetchRow(t, st, u)
		want := "active"
		if i == RefetchMaxNewPayloads {
			want = "done"
		}
		if state != want {
			t.Fatalf("after %d new payloads: state=%s want %s", i, state, want)
		}
		now = now.Add(time.Hour + time.Second)
	}
	if j, err := st.ClaimRefetch(now.Add(24*time.Hour), time.Minute); err != nil || j != nil {
		t.Fatalf("a capped URL was claimed again: %+v %v", j, err)
	}
}
