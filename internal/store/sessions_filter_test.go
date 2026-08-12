package store

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// seedSessions writes `n` cowrie sessions, each with a login event and `cmds`
// command events. Sessions are staggered in time so end_ts DESC is a stable,
// predictable order: index 0 is the newest.
func seedSessions(t *testing.T, st *Store, prefix string, n, cmds int, base time.Time) {
	t.Helper()
	var events []*models.Event
	for i := 0; i < n; i++ {
		sid := prefix + strconv.Itoa(i)
		ts := base.Add(-time.Duration(i) * time.Minute)
		events = append(events, &models.Event{
			TS: ts, Source: models.SourceCowrie, Kind: models.KindAccepted,
			SrcIP: "9.9.9.9", SessionID: sid, ActorID: "cowrie:a", Username: "root",
		})
		for c := 0; c < cmds; c++ {
			events = append(events, &models.Event{
				TS: ts.Add(time.Duration(c+1) * time.Second), Source: models.SourceCowrie,
				Kind: models.KindCommand, SrcIP: "9.9.9.9", SessionID: sid,
				ActorID: "cowrie:a", Command: "uname -a",
			})
		}
	}
	if err := st.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatalf("append %s: %v", prefix, err)
	}
}

// TestListSessionsMinCommandsFiltersBeforeLimit is the regression test for the
// replay dropdown's blind spot. The filter has to be applied IN the query, so
// the LIMIT caps replayable sessions rather than all sessions.
//
// The dropdown used to fetch the newest N sessions and discard command-less ones
// in JavaScript. Because ~99.5% of real sessions are bare connects, that turned
// a 200-row page into 8 selectable sessions out of 1,876 — and a page that
// happened to hold only connects rendered "no sessions with commands in window",
// asserting something about the window that had only been checked of the page.
//
// The shape here reproduces that ratio deliberately: 30 command-less sessions
// NEWER than the 5 with commands. Filtering after a limit of 10 finds zero.
func TestListSessionsMinCommandsFiltersBeforeLimit(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "sessfilter.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	// Older: 5 sessions that ran commands (2 each).
	seedSessions(t, st, "cmd", 5, 2, now.Add(-2*time.Hour))
	// Newer: 30 bare connects, which crowd out the interesting ones by end_ts.
	seedSessions(t, st, "bare", 30, 0, now.Add(-1*time.Minute))

	since := now.Add(-24 * time.Hour)

	// Unfiltered, limit 10: every row is a bare connect. This is exactly what the
	// client used to receive — and then filter to nothing.
	unfiltered, err := st.ListSessions(since, 10)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(unfiltered) != 10 {
		t.Fatalf("unfiltered limit=10 returned %d rows, want 10", len(unfiltered))
	}
	clientSideSurvivors := 0
	for _, s := range unfiltered {
		if s.CmdCount > 0 {
			clientSideSurvivors++
		}
	}
	if clientSideSurvivors != 0 {
		t.Fatalf("expected the newest 10 to be all bare connects (got %d with commands); "+
			"the fixture no longer reproduces the bug it guards", clientSideSurvivors)
	}

	// Filtered: the same limit now returns replayable sessions, because the
	// filter runs before the cap.
	filtered, err := st.ListSessions(since, 10, SessionListOptions{MinCommands: 1})
	if err != nil {
		t.Fatalf("ListSessions(MinCommands): %v", err)
	}
	if len(filtered) != 5 {
		t.Fatalf("MinCommands=1 returned %d sessions, want 5: the filter must run in the "+
			"query, or the LIMIT caps all sessions instead of replayable ones", len(filtered))
	}
	for _, s := range filtered {
		if s.CmdCount < 1 {
			t.Fatalf("session %s has %d commands but passed MinCommands=1", s.ID, s.CmdCount)
		}
		// The aggregate must still describe the WHOLE session: HAVING filters
		// groups, so the login event stays counted. A WHERE command != '' would
		// have silently dropped it and broken every other column.
		if s.EventCount != 3 {
			t.Fatalf("session %s: eventCount = %d, want 3 (1 login + 2 commands) — the "+
				"filter must not drop non-command rows from the group", s.ID, s.EventCount)
		}
		if s.Username != "root" {
			t.Fatalf("session %s: username = %q, want \"root\" — lost because the login "+
				"event was filtered out of the group", s.ID, s.Username)
		}
	}

	// The count must agree with the filtered page, or the UI reads a mismatch as
	// truncation.
	total, err := st.CountSessionsSince(since, SessionListOptions{MinCommands: 1})
	if err != nil {
		t.Fatalf("CountSessionsSince(MinCommands): %v", err)
	}
	if total != 5 {
		t.Fatalf("filtered count = %d, want 5", total)
	}

	// And the unfiltered count still describes all 35 sessions: the option must
	// not leak into callers that didn't pass it.
	allTotal, err := st.CountSessionsSince(since)
	if err != nil {
		t.Fatalf("CountSessionsSince: %v", err)
	}
	if allTotal != 35 {
		t.Fatalf("unfiltered count = %d, want 35 — the default must stay unfiltered "+
			"for the sessions timeline, which lists bare connects on purpose", allTotal)
	}
}

// TestSessionMinCommandsThreshold pins that the threshold is a real >= and not
// just a non-zero test, since the replay generator only wants sessions with
// enough commands to be worth scripting.
func TestSessionMinCommandsThreshold(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "sessthresh.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	seedSessions(t, st, "one", 3, 1, now.Add(-3*time.Hour))
	seedSessions(t, st, "five", 2, 5, now.Add(-2*time.Hour))
	since := now.Add(-24 * time.Hour)

	for _, tc := range []struct{ min, want int }{
		{0, 5}, // unset: everything
		{1, 5},
		{2, 2}, // only the 5-command sessions clear it
		{5, 2},
		{6, 0},
	} {
		got, err := st.ListSessions(since, 100, SessionListOptions{MinCommands: tc.min})
		if err != nil {
			t.Fatalf("ListSessions(min=%d): %v", tc.min, err)
		}
		if len(got) != tc.want {
			t.Errorf("MinCommands=%d returned %d sessions, want %d", tc.min, len(got), tc.want)
		}
		n, err := st.CountSessionsSince(since, SessionListOptions{MinCommands: tc.min})
		if err != nil {
			t.Fatalf("CountSessionsSince(min=%d): %v", tc.min, err)
		}
		if n != tc.want {
			t.Errorf("count(MinCommands=%d) = %d, want %d — the count and the page must "+
				"describe the same population", tc.min, n, tc.want)
		}
	}
}
