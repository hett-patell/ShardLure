package store

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// seedShellWindow writes many command-less sessions (the ~99.5% bare-connect
// majority), a few sessions with commands, legacy (pre-v20) rows on both sides
// of the window edge, and a session whose command predates the window.
func seedShellWindow(t *testing.T, st *Store, since time.Time) {
	t.Helper()
	tx, err := st.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	native := func(at time.Time, session, kind, command string) {
		if _, err := tx.Exec(`INSERT INTO events(ts,ts_unix_ns,source,kind,session_id,src_ip,username,command,actor_id) VALUES(?,?,?,?,?,?,?,?,?)`,
			formatFixedUTC(at), at.UnixNano(), "cowrie", kind, session, "192.0.2.9", "root", command, "cowrie:x"); err != nil {
			t.Fatal(err)
		}
	}
	legacy := func(ts, session, kind, command string) {
		if _, err := tx.Exec(`INSERT INTO events(ts,source,kind,session_id,src_ip,command,actor_id) VALUES(?,?,?,?,?,?,?)`,
			ts, "cowrie", kind, session, "192.0.2.8", command, "cowrie:y"); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3000; i++ {
		at := since.Add(time.Duration(i) * time.Second)
		native(at, fmt.Sprintf("bare%04d", i/3), "connect", "")
	}
	for i := 0; i < 40; i++ {
		at := since.Add(time.Duration(i*60+7) * time.Second)
		id := fmt.Sprintf("shell%02d", i)
		native(at, id, "connect", "")
		native(at.Add(time.Second), id, "command", fmt.Sprintf("echo %d", i))
		// The session's newest event is not a command: ordering must use it.
		native(at.Add(time.Duration(90-i)*time.Second), id, "session_closed", "")
	}
	// A download carries its URL in command: it counts as a command-bearing event.
	native(since.Add(time.Hour), "dl", "file_download", "http://198.51.100.1/x")
	// Legacy command session inside the window, written with a far-west offset.
	legacy(since.Add(30*time.Minute).In(time.FixedZone("w", -14*3600)).Format(time.RFC3339Nano), "legacyshell", "command", "id")
	legacy(since.Add(31*time.Minute).Format(time.RFC3339Nano), "legacyshell", "connect", "")
	// Legacy command just outside the window, although its text sorts after since.
	legacy(since.Add(-time.Minute).In(time.FixedZone("e", 14*3600)).Format(time.RFC3339Nano), "oldshell", "command", "old")
	// A session whose only command predates the window is not a shell session
	// in the window, even though it has later in-window events.
	native(since.Add(-time.Hour), "stale", "command", "whoami")
	native(since.Add(2*time.Hour), "stale", "connect", "")
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// The bounded shell-session query must return exactly what grouping the whole
// window and filtering on command count returned.
func TestRecentShellSessionsMatchesWholeWindowGrouping(t *testing.T) {
	st := newTestStore(t, "shell_equiv.db")
	since := time.Now().UTC().Add(-23 * time.Hour).Truncate(time.Second)
	seedShellWindow(t, st, since)

	all, _, err := st.sessionSummaryPage(since, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var want []ShellSessionSummary
	for _, s := range all {
		if s.CmdCount >= 1 {
			want = append(want, s)
		}
	}
	sort.SliceStable(want, func(i, j int) bool {
		if !want[i].EndTS.Equal(want[j].EndTS) {
			return want[i].EndTS.After(want[j].EndTS)
		}
		return want[i].ID < want[j].ID
	})
	for _, limit := range []int{0, 5, 30} {
		got, total, err := st.sessionSummaryPage(since, 1, limit)
		if err != nil {
			t.Fatal(err)
		}
		w := want
		if limit > 0 && len(w) > limit {
			w = w[:limit]
		}
		if total != len(want) {
			t.Fatalf("limit %d: total %d, want %d", limit, total, len(want))
		}
		if !reflect.DeepEqual(got, w) {
			t.Fatalf("limit %d:\n got %+v\nwant %+v", limit, got, w)
		}
	}
	ids := map[string]bool{}
	for _, s := range want {
		ids[s.ID] = true
	}
	if len(want) != 42 || !ids["legacyshell"] || !ids["dl"] || ids["oldshell"] || ids["stale"] {
		t.Fatalf("fixture population wrong (%d): %v", len(want), ids)
	}
}

// RecentShellSessions feeds the landing dashboard (3.5 s of a 60 s ARM
// profile). ~99.5% of sessions are bare connects, so grouping every session in
// the window to keep the ones with commands scanned the whole window. The
// candidates now come from command-bearing rows only, and each candidate's
// aggregate is read through idx_events_session.
func TestShellSessionQueryAggregatesOnlyCandidateSessions(t *testing.T) {
	st := newTestStore(t, "shell_plan.db")
	query, args := sessionSummaryQuery(time.Now().Add(-24*time.Hour), 1, 30)
	rows, err := st.db.Query("EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(plan, "\n")
	if !strings.Contains(joined, "idx_events_session (source=? AND session_id=?") {
		t.Fatalf("candidate sessions are not aggregated through idx_events_session:\n%s", joined)
	}
	for _, line := range plan {
		if strings.HasPrefix(line, "SCAN events") && !strings.Contains(line, "idx_events_legacy_ts") {
			t.Fatalf("unbounded scan in plan:\n%s", joined)
		}
	}
}
