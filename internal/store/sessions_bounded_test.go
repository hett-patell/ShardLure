package store

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Regression (ARM rollout of the v2.8.0 candidate, 2026-09-25): session
// summaries were rebuilt by streaming EVERY event in the window through Go
// (twice per request: list and count), so /api/intel/sessions at 30d/90d on the
// 1.75M-event prod database never answered. Aggregation must stay in SQLite:
// asking for the newest 10 sessions must not cost an allocation per event.
func TestSessionSummariesDoNotMaterializeTheWindow(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "sessions-bounded.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC().Add(-time.Minute)
	const events = 30000
	tx, err := st.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < events; i++ {
		ts := now.Add(-time.Duration(i) * time.Second)
		if _, err := tx.Exec(`INSERT INTO events(ts,ts_unix_ns,source,kind,session_id,src_ip,username,command,actor_id) VALUES(?,?,?,?,?,?,?,?,?)`,
			formatFixedUTC(ts), ts.UnixNano(), "cowrie", "command", fmt.Sprintf("s%05d", i/3), "192.0.2.1", "root", "uname -a", "cowrie:x"); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	since := now.Add(-24 * time.Hour)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	listed, err := st.ListSessions(since, 10)
	if err != nil {
		t.Fatal(err)
	}
	count, err := st.CountSessionsSince(since)
	if err != nil {
		t.Fatal(err)
	}
	shells, err := st.RecentShellSessions(since, 10)
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if len(listed) != 10 || count != events/3 || len(shells) != 10 {
		t.Fatalf("listed=%d count=%d shells=%d", len(listed), count, len(shells))
	}
	if listed[0].ID != "s00000" || shells[0].FirstCommand != "uname -a" {
		t.Fatalf("newest session %q first command %q", listed[0].ID, shells[0].FirstCommand)
	}
	if n := after.Mallocs - before.Mallocs; n > events {
		t.Fatalf("%d allocations for %d events in the window; the window was materialized in Go", n, events)
	}
}

// The sessions endpoint needs both a page and the true total. Grouping the
// window twice (list, then count) doubled the cost of the slowest intel
// panel on prod (8 s at 30d, 17 s at 90d); one pass must give the same answer.
func TestListSessionsWithTotalMatchesSeparateCalls(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "sessions-total.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC().Add(-time.Minute)
	for i := 0; i < 90; i++ {
		ts := now.Add(-time.Duration(i) * time.Minute)
		cmd := ""
		if i%3 == 0 {
			cmd = "id"
		}
		if _, err := st.db.Exec(`INSERT INTO events(ts,ts_unix_ns,source,kind,session_id,src_ip,command) VALUES(?,?,?,?,?,?,?)`,
			formatFixedUTC(ts), ts.UnixNano(), "cowrie", "command", fmt.Sprintf("s%02d", i/2), "192.0.2.1", cmd); err != nil {
			t.Fatal(err)
		}
	}
	since := now.Add(-24 * time.Hour)
	for _, opts := range [][]SessionListOptions{nil, {{MinCommands: 1}}} {
		want, err := st.ListSessions(since, 7, opts...)
		if err != nil {
			t.Fatal(err)
		}
		wantTotal, err := st.CountSessionsSince(since, opts...)
		if err != nil {
			t.Fatal(err)
		}
		got, total, err := st.ListSessionsWithTotal(since, 7, opts...)
		if err != nil {
			t.Fatal(err)
		}
		if total != wantTotal || len(got) != len(want) {
			t.Fatalf("opts=%v total=%d/%d rows=%d/%d", opts, total, wantTotal, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("row %d: %+v != %+v", i, got[i], want[i])
			}
		}
	}
}
