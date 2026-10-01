package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The dashboard's background cache refreshes run the tier reads on the
// server's drain context so a shutdown interrupts them; each Context variant
// must therefore honour cancellation rather than run to completion.
func TestContextReadsHonourCancellation(t *testing.T) {
	st := newTestStore(t, "ctx_reads.db")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	since := time.Now().Add(-24 * time.Hour)
	reads := map[string]func() error{
		"EventCount":              func() error { _, err := st.EventCountContext(ctx); return err },
		"ActorCount":              func() error { _, err := st.ActorCountContext(ctx); return err },
		"CountsByKind":            func() error { _, err := st.CountsByKindContext(ctx); return err },
		"CountsByIntent":          func() error { _, err := st.CountsByIntentContext(ctx); return err },
		"CountsByPlaybook":        func() error { _, err := st.CountsByPlaybookContext(ctx); return err },
		"CountsBySource":          func() error { _, err := st.CountsBySourceContext(ctx); return err },
		"HourlyEventCountsByKind": func() error { _, err := st.HourlyEventCountsByKindContext(ctx, 72); return err },
		"HourlyEventCounts":       func() error { _, err := st.HourlyEventCountsContext(ctx, 72); return err },
		"UniqueIPCount":           func() error { _, err := st.UniqueIPCountContext(ctx); return err },
		"TopSourceIPs":            func() error { _, err := st.TopSourceIPsContext(ctx, 5); return err },
		"TopUsernames":            func() error { _, err := st.TopUsernamesContext(ctx, 5); return err },
		"TopCommands":             func() error { _, err := st.TopCommandsContext(ctx, 5); return err },
		"DistinctGeoCountryCount": func() error { _, err := st.DistinctGeoCountryCountContext(ctx); return err },
		"CountSessions":           func() error { _, err := st.CountSessionsContext(ctx); return err },
		"RecentShellSessions":     func() error { _, err := st.RecentShellSessionsContext(ctx, since, 30); return err },
		"SessionMetaForSessions":  func() error { _, err := st.SessionMetaForSessionsContext(ctx, []string{"s1"}); return err },
		// Runs on the SWR drain context too (recentCountsCached).
		"RecentEventCountsByActor": func() error { _, err := st.RecentEventCountsByActor(ctx, since); return err },
	}
	for name, read := range reads {
		if err := read(); !errors.Is(err, context.Canceled) {
			t.Errorf("%s with a cancelled context returned %v, want context.Canceled", name, err)
		}
	}
	// And the context-free forms still work, for callers without one.
	if _, err := st.EventCount(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecentShellSessions(since, 30); err != nil {
		t.Fatal(err)
	}
}
