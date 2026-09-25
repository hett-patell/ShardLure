package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSessionSummariesUseExactMixedTimes(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "sessions-time.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	since := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	times := []struct {
		session, ts, kind, command string
	}{
		{"live", since.Add(time.Minute).In(time.FixedZone("minus-14", -14*60*60)).Format(time.RFC3339Nano), "connect", ""},
		{"live", since.Add(2 * time.Minute).Format(time.RFC3339Nano), "command", "first"},
		{"live", since.Add(2 * time.Minute).Format(time.RFC3339Nano), "command", "second"},
		{"old", since.Add(-time.Minute).In(time.FixedZone("plus-14", 14*60*60)).Format(time.RFC3339Nano), "command", "old"},
	}
	for _, row := range times {
		if _, err := st.db.Exec(`INSERT INTO events(ts,source,kind,session_id,command,src_ip,actor_id) VALUES(?,?,?,?,?,?,?)`,
			row.ts, "cowrie", row.kind, row.session, row.command, "8.8.8.8", "cowrie:test"); err != nil {
			t.Fatal(err)
		}
	}
	count, err := st.CountSessionsSince(since)
	if err != nil || count != 1 {
		t.Fatalf("count=%d err=%v, want 1", count, err)
	}
	listed, err := st.ListSessions(since, 10)
	if err != nil || len(listed) != 1 {
		t.Fatalf("listed=%+v err=%v", listed, err)
	}
	if !listed[0].StartTS.Equal(since.Add(time.Minute)) || !listed[0].EndTS.Equal(since.Add(2*time.Minute)) || listed[0].EventCount != 3 {
		t.Fatalf("summary=%+v", listed[0])
	}
	shells, err := st.RecentShellSessions(since, 10)
	if err != nil || len(shells) != 1 || shells[0].FirstCommand != "first" {
		t.Fatalf("shells=%+v err=%v", shells, err)
	}
	events, err := st.SessionEvents("live")
	if err != nil || len(events) != 3 || events[1].Command != "first" || events[2].Command != "second" {
		t.Fatalf("events=%+v err=%v", events, err)
	}
}

func TestSessionReadersRejectMalformedTime(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "sessions-malformed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.db.Exec(`INSERT INTO events(ts,source,kind,session_id) VALUES('zzzz','cowrie','connect','bad')`); err != nil {
		t.Fatal(err)
	}
	since := time.Now().Add(-time.Hour)
	checks := []struct {
		name string
		fn   func() error
	}{
		{"count", func() error { _, err := st.CountSessionsSince(since); return err }},
		{"list", func() error { _, err := st.ListSessions(since, 10); return err }},
		{"shells", func() error { _, err := st.RecentShellSessions(since, 10); return err }},
		{"events", func() error { _, err := st.SessionEvents("bad"); return err }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.fn(); err == nil || !strings.Contains(err.Error(), "event") {
				t.Fatalf("error=%v, want contextual timestamp failure", err)
			}
		})
	}
}
