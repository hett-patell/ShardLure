package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// seedRateWindow writes native rows and pre-v20 legacy rows (ts_unix_ns NULL,
// offset timestamps) on both sides of the window edge, plus rows without an
// actor, so the SQL count is checked against the exact-time iterator it
// replaced.
func seedRateWindow(t *testing.T, st *Store, since time.Time, perActor int) {
	t.Helper()
	tx, err := st.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < perActor; i++ {
		for j, actor := range []string{"cowrie:a", "cowrie:b", "journal:c"} {
			at := since.Add(time.Duration(i*3+j+1) * time.Second)
			if _, err := tx.Exec(`INSERT INTO events(ts,ts_unix_ns,source,kind,actor_id) VALUES(?,?,?,?,?)`,
				formatFixedUTC(at), at.UnixNano(), models.SourceCowrie, models.KindFailedPass, actor); err != nil {
				t.Fatal(err)
			}
		}
	}
	rows := []struct {
		ts    string
		actor any
	}{
		// Legacy, in window, written with a far-west offset.
		{since.Add(time.Minute).In(time.FixedZone("w", -14*3600)).Format(time.RFC3339Nano), "cowrie:a"},
		{since.Add(2 * time.Minute).In(time.FixedZone("e", 14*3600)).Format(time.RFC3339Nano), "journal:legacy"},
		// Legacy, just outside the window although its text sorts after `since`.
		{since.Add(-time.Minute).In(time.FixedZone("e", 14*3600)).Format(time.RFC3339Nano), "journal:old"},
		// No actor: never counted.
		{since.Add(3 * time.Minute).Format(time.RFC3339Nano), nil},
		{since.Add(4 * time.Minute).Format(time.RFC3339Nano), ""},
	}
	for _, r := range rows {
		if _, err := tx.Exec(`INSERT INTO events(ts,source,kind,actor_id) VALUES(?,?,?,?)`,
			r.ts, models.SourceJournal, models.KindFailedPass, r.actor); err != nil {
			t.Fatal(err)
		}
	}
	old := since.Add(-time.Hour)
	if _, err := tx.Exec(`INSERT INTO events(ts,ts_unix_ns,source,kind,actor_id) VALUES(?,?,?,?,?)`,
		formatFixedUTC(old), old.UnixNano(), models.SourceCowrie, models.KindFailedPass, "cowrie:old"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// The SQL GROUP BY must count exactly what the exact-time iterator counted.
func TestRecentEventCountsByActorMatchesExactIterator(t *testing.T) {
	st := newTestStore(t, "rates_sql_equiv.db")
	since := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
	seedRateWindow(t, st, since, 50)

	want := map[string]int{}
	if err := st.IterateEventsSinceContext(context.Background(), since, func(e *models.Event) error {
		if e.ActorID != "" {
			want[e.ActorID]++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := st.recentEventCountsByActor(context.Background(), since)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for id, n := range want {
		if got[id] != n {
			t.Fatalf("actor %s: got %d, want %d (all: %v)", id, got[id], n, got)
		}
	}
	if got["cowrie:a"] != 51 || got["journal:legacy"] != 1 || got["journal:old"] != 0 || got["cowrie:old"] != 0 {
		t.Fatalf("window edges wrong: %v", got)
	}
}

// The count used to decode every event of the window into a models.Event in
// Go - 1.65 s of a 60 s ARM profile with the dashboard polled every 10 s. It is
// one GROUP BY now, so its allocations follow the number of actors, not the
// number of events.
func TestRecentEventCountsByActorDoesNotDecodeEvents(t *testing.T) {
	st := newTestStore(t, "rates_sql_allocs.db")
	since := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
	seedRateWindow(t, st, since, 2000) // ~6,000 events, 5 actors
	allocs := testing.AllocsPerRun(3, func() {
		if _, err := st.recentEventCountsByActor(context.Background(), since); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 1000 {
		t.Fatalf("%.0f allocations for ~6,000 events in 5 actors: the window is being decoded row by row", allocs)
	}
}

// Both branches must stay bounded: the native branch on a ts-restricted index
// SEARCH and the legacy branch on the shrinking partial index. Either
// one falling back to a table scan would make the count O(all events) instead
// of O(window).
//
// The plan is checked before and after ANALYZE on seeded data, because that is
// what production runs (PRAGMA optimize at Open and each purge). Analysed, the
// native branch leaves idx_events_ts for a skip-scan of idx_events_kind_ts
// (ANY(kind) AND ts>?), which is still bounded by the window, so the test pins
// the property, "a SEARCH restricted on ts", not an index name
// (store-reads audit Minor 3).
func TestRecentEventCountsByActorPlan(t *testing.T) {
	st := newTestStore(t, "rates_sql_plan.db")
	tx, err := st.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	kinds := []string{"connect", "login_failed", "login_success", "command", "session_closed", "client_version"}
	for i := range 30000 {
		ts := base.Add(time.Duration(i) * time.Minute)
		var ns any = ts.UnixNano()
		if i%20 == 0 {
			ns = nil // legacy row, not yet backfilled
		}
		if _, err := tx.Exec(`INSERT INTO events(ts,ts_unix_ns,source,kind,src_ip,actor_id) VALUES(?,?,?,?,?,?)`,
			formatFixedUTC(ts), ns, "cowrie", kinds[(i*7)%len(kinds)], fmt.Sprintf("198.51.100.%d", i%200), fmt.Sprintf("cowrie:a%d", i%300)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	query, args := recentActorCountsQuery(base.Add(29000 * time.Minute))
	check := func(label string) {
		t.Helper()
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
		if !strings.Contains(joined, "idx_events_legacy_ts") {
			t.Fatalf("%s: legacy branch is off its partial index:\n%s", label, joined)
		}
		searches := 0
		for _, line := range plan {
			// The legacy branch walks the partial index of unconverted rows
			// (it parses their text exactly, so it cannot seek on ts); that
			// index only shrinks as the backfill runs, so it is the one scan
			// allowed. Any other SCAN of events is O(all events).
			if strings.HasPrefix(line, "SCAN events") && !strings.Contains(line, "USING INDEX idx_events_legacy_ts") {
				t.Fatalf("%s: events scanned, not searched by the window:\n%s", label, joined)
			}
			if strings.HasPrefix(line, "SEARCH events") {
				if !strings.Contains(line, "ts>") && !strings.Contains(line, "ts_unix_ns>") {
					t.Fatalf("%s: an events SEARCH is not bounded by the window:\n%s", label, joined)
				}
				searches++
			}
		}
		if searches < 1 {
			t.Fatalf("%s: the native branch is not a window-bounded SEARCH:\n%s", label, joined)
		}
		t.Logf("%s plan:\n%s", label, joined)
	}
	check("unanalysed")
	if _, err := st.db.Exec(`ANALYZE`); err != nil {
		t.Fatal(err)
	}
	check("after ANALYZE")
}
