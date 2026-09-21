package store

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

func seedQueryRows(t testing.TB, st *Store, n int, startID int64) {
	t.Helper()
	base := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
	err := st.WithTx(func(tx *sql.Tx) error {
		stmt, err := tx.Prepare("INSERT INTO events(id,ts,ts_unix_ns,source,kind) VALUES(?,?,?,?,?)")
		if err != nil {
			return err
		}
		defer stmt.Close()
		// Same timestamp reproduces the previous unbounded millisecond bucket.
		for i := 0; i < n; i++ {
			if _, err := stmt.Exec(startID+int64(i), formatFixedUTC(base), base.UnixNano(), "cowrie", "connect"); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCappedEventReadDoesNotAllocateEveryDiscardedRow(t *testing.T) {
	st := newTestStore(t, "bounded-window.db")
	since := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	seedQueryRows(t, st, 10, 1)
	read := func() {
		events, err := st.EventsSince(since, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 1 {
			t.Fatalf("returned %d events", len(events))
		}
	}
	small := testing.AllocsPerRun(2, read)
	seedQueryRows(t, st, 3000, 11)
	large := testing.AllocsPerRun(2, read)
	// This protects the public row-cap contract, not an implementation constant:
	// retaining/scanning all Go Event structs used >100k allocations for this
	// fixture. An indexed LIMIT is independent of the discarded event count.
	if large > small*4+1000 {
		t.Fatalf("limit=1 allocation count grew with history: small=%.0f large=%.0f", small, large)
	}
	t.Logf("limit=1 allocations: 10 rows %.0f; 3010 rows %.0f", small, large)
}

func TestLatestEventQueryDoesNotSortMigratedHistory(t *testing.T) {
	st := newTestStore(t, "latest-plan.db")
	for _, q := range []string{latestEventQuery} {
		rows, err := st.db.Query("EXPLAIN QUERY PLAN " + q)
		if err != nil {
			t.Fatal(err)
		}
		var details []string
		for rows.Next() {
			var a, b, c int
			var detail string
			if err := rows.Scan(&a, &b, &c, &detail); err != nil {
				t.Fatal(err)
			}
			details = append(details, detail)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
		plan := strings.Join(details, "\n")
		if strings.Contains(plan, "USE TEMP B-TREE") {
			t.Fatalf("latest-event poll sorts full history:\n%s", plan)
		}
		for _, d := range details {
			if d == "SCAN events" {
				t.Fatalf("unindexed full event scan:\n%s", plan)
			}
		}
		if !strings.Contains(plan, "idx_events_ts") || !strings.Contains(plan, "idx_events_legacy_ts") {
			t.Fatalf("missing migrated/legacy index paths:\n%s", plan)
		}
	}
}

func BenchmarkMigratedEventRead(b *testing.B) {
	st, err := Open(b.TempDir() + "/bench.db")
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()
	seedQueryRows(b, st, 50000, 1)
	since := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	for _, kind := range []string{"latest", "newest-one", "capped-total"} {
		b.Run(kind, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				switch kind {
				case "latest":
					_, err = st.LatestEventTime()
				case "newest-one":
					_, err = st.EventsSince(since, 1)
				case "capped-total":
					_, _, err = st.EventsSinceCapped(since, 1)
				}
				if err != nil {
					b.Fatal(fmt.Errorf("%s: %w", kind, err))
				}
			}
		})
	}
}

func TestV21UpgradePreservesUnbackfilledEventRows(t *testing.T) {
	path := t.TempDir() + "/v20.db"
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// v21 adds only an index; removing that step recreates a populated v20 DB.
	if _, err := st.db.Exec("DROP INDEX idx_events_legacy_ts; DELETE FROM schema_migrations WHERE version=21;"); err != nil {
		t.Fatal(err)
	}
	const legacy = "2026-01-01T01:00:00+02:00"
	if _, err := st.db.Exec("INSERT INTO events(ts,source,kind) VALUES(?,?,?)", legacy, "cowrie", "connect"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("CREATE TRIGGER forbid_event_startup_rewrite BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'startup event rewrite'); END"); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		st, err = Open(path)
		if err != nil {
			t.Fatal(err)
		}
		var ts string
		var ns sql.NullInt64
		if err := st.db.QueryRow("SELECT ts,ts_unix_ns FROM events").Scan(&ts, &ns); err != nil {
			st.Close()
			t.Fatal(err)
		}
		if ts != legacy || ns.Valid {
			st.Close()
			t.Fatalf("migration changed legacy row: %q %v", ts, ns)
		}
		version, err := st.currentSchemaVersion()
		if err != nil || version < 21 {
			st.Close()
			t.Fatalf("version=%d err=%v", version, err)
		}
		indexes, err := indexNames(st)
		if err != nil || !indexes["idx_events_legacy_ts"] {
			st.Close()
			t.Fatalf("legacy index missing: %v", err)
		}
		events, err := st.EventsSince(time.Date(2025, 12, 31, 22, 0, 0, 0, time.UTC), 1)
		if err != nil || len(events) != 1 {
			st.Close()
			t.Fatalf("legacy read failed rows=%d error=%v", len(events), err)
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestActorEventQueryUsesScopedLegacyIndex(t *testing.T) {
	st := newTestStore(t, "actor-query-plan.db")
	query, args := orderedEventQuery(fullEventColumns, nil, "actor_id=?", []any{"cowrie:one"}, false, 0)
	rows, err := st.db.Query("EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plans []string
	lookups := 0
	for rows.Next() {
		var a, b, c int
		var detail string
		if err := rows.Scan(&a, &b, &c, &detail); err != nil {
			t.Fatal(err)
		}
		plans = append(plans, detail)
		if strings.HasPrefix(detail, "SEARCH events") && strings.Contains(detail, "actor_id=?") {
			lookups++
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if lookups != 2 {
		t.Fatalf("both branches must seek by actor; got %d actor lookups:\n%s", lookups, strings.Join(plans, "\n"))
	}
}

func TestCredentialAggregateUsesBoundedNativeAndLegacyQueries(t *testing.T) {
	st := newTestStore(t, "credential-plan.db")
	since := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
	query, args := credentialWindowQuery(since)
	query += "SELECT username,COUNT(*) FROM credential_events GROUP BY username ORDER BY COUNT(*) DESC LIMIT 1"
	rows, err := st.db.Query("EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var a, b, c int
		var detail string
		if err := rows.Scan(&a, &b, &c, &detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	plan := strings.Join(details, "\n")
	if !strings.Contains(plan, "ts>?") || !strings.Contains(plan, "idx_events_legacy_ts") {
		t.Fatalf("credential polls must seek native time and scan only unconverted legacy rows:\n%s", plan)
	}
}

func TestAggregateReadsDoNotAllocateEventHistory(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%v", legacy), func(t *testing.T) {
			st := newTestStore(t, "aggregate-allocations.db")
			since := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
			seedQueryRows(t, st, 10, 1)
			if _, err := st.db.Exec("UPDATE events SET kind='failed_password',username='root',password='inert'"); err != nil {
				t.Fatal(err)
			}
			if legacy {
				if _, err := st.db.Exec("UPDATE events SET ts='2026-09-18T00:00:00Z',ts_unix_ns=NULL WHERE id=1"); err != nil {
					t.Fatal(err)
				}
			}
			read := func() {
				rows, err := st.TopUsernamesSince(since, 1)
				if err != nil || len(rows) != 1 {
					t.Fatalf("rows=%+v err=%v", rows, err)
				}
				if _, err := st.WindowActivitySince(since); err != nil {
					t.Fatal(err)
				}
			}
			small := testing.AllocsPerRun(2, read)
			seedQueryRows(t, st, 3000, 11)
			if _, err := st.db.Exec("UPDATE events SET kind='failed_password',username='root',password='inert' WHERE id>10"); err != nil {
				t.Fatal(err)
			}
			large := testing.AllocsPerRun(2, read)
			if large > small*4+1000 {
				t.Fatalf("aggregate allocations scale with events: %.0f -> %.0f", small, large)
			}
			rows, err := st.TopUsernamesSince(since, 1)
			if err != nil || len(rows) != 1 || rows[0].Count != 3010 {
				t.Fatalf("true total lost: rows=%+v err=%v", rows, err)
			}
			t.Logf("10 -> 3010 rows: allocations %.0f -> %.0f", small, large)
		})
	}
}
