package store

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// recentCommandsWholeWindow is the pre-round-3 query, kept as the oracle.
func recentCommandsWholeWindow(s *Store, limit int) ([]CommandEvent, error) {
	query, args := orderedGlobalEventQuery(commandEventColumns, nil, "command IS NOT NULL AND command != ''", nil, true, limit)
	return s.commandEvents(query, args)
}

func TestRecentCommandsMatchesOldQuery(t *testing.T) {
	s := newTestStore(t, "recent_cmd_equiv.db")
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	seedLastCommands(t, s, base) // native/legacy mix, offset rows, id ties, NULL/empty
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	// Many native commands, older than the fixture's newest rows, plus
	// command-less noise and a legacy row newer than all natives by instant.
	for i := 0; i < 300; i++ {
		at := base.Add(-time.Duration(i) * time.Minute)
		if _, err := tx.Exec(`INSERT INTO events(ts,ts_unix_ns,source,kind,command,actor_id) VALUES(?,?,?,?,?,?)`,
			formatFixedUTC(at), at.UnixNano(), "cowrie", "command", "cmd-"+at.Format("1504"), "cowrie:bulk"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO events(ts,ts_unix_ns,source,kind,command,actor_id) VALUES(?,?,?,?,'',?)`,
			formatFixedUTC(at), at.UnixNano(), "cowrie", "connect", "cowrie:bulk"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO events(ts,source,kind,command,actor_id) VALUES(?,?,?,?,?)`,
		base.Add(20*time.Hour).In(time.FixedZone("w", -12*3600)).Format(time.RFC3339Nano), "cowrie", "command", "legacy-newest", "cowrie:l"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{0, 1, 5, 120, 1000} {
		want, err := recentCommandsWholeWindow(s, max(limit, 0))
		if limit == 0 {
			want, err = recentCommandsWholeWindow(s, 50)
		}
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.RecentCommands(limit)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("limit %d: got %d rows, want %d\n got[0:3] %+v\nwant[0:3] %+v", limit, len(got), len(want), got[:min(3, len(got))], want[:min(3, len(want))])
		}
	}
	if got, _ := s.RecentCommands(1); len(got) != 1 || got[0].Command != "legacy-newest" {
		t.Fatalf("newest by exact time: %+v", got)
	}
}

// The native branch reads the partial command index newest-first and stops
// after `limit` rows; it used to visit every migrated row of the table to
// find the ~1% with a command (~260 ms per /api/intel request on 640k
// events). The legacy branch stays on the pinned shrinking legacy index.
func TestRecentCommandsPlanIsBounded(t *testing.T) {
	s := newTestStore(t, "recent_cmd_plan.db")
	query, args := recentCommandsQuery(120)
	rows, err := s.db.Query("EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var a, b, c int
		var d string
		if err := rows.Scan(&a, &b, &c, &d); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, d)
	}
	joined := strings.Join(plan, "\n")
	if !strings.Contains(joined, "SCAN events USING INDEX idx_events_cmd_ts") {
		t.Fatalf("native branch does not read the command index:\n%s", joined)
	}
	if !strings.Contains(joined, "idx_events_legacy_ts") {
		t.Fatalf("legacy branch is not on the legacy index:\n%s", joined)
	}
	for _, line := range plan {
		if strings.HasPrefix(line, "SCAN events") && !strings.Contains(line, "INDEX") {
			t.Fatalf("table scan:\n%s", joined)
		}
	}
}
