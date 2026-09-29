package store

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// lastCommandsWholeHistory is the pre-round-2 implementation, kept as the
// equivalence oracle: rank every command event of each actor's whole history.
func lastCommandsWholeHistory(s *Store, ids []string) (map[string]string, error) {
	out := map[string]string{}
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i], args[i] = "?", id
	}
	base, args := eventTimeBranches("id,actor_id,command", nil,
		"actor_id IN ("+strings.Join(placeholders, ",")+") AND command IS NOT NULL AND command != ''", args)
	rows, err := s.db.Query("WITH command_events AS ("+base+") SELECT actor_id, command FROM (SELECT actor_id, command, "+
		"ROW_NUMBER() OVER (PARTITION BY actor_id ORDER BY exact_ts DESC,id DESC) AS rn FROM command_events) WHERE rn = 1", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, cmd string
		if err := rows.Scan(&id, &cmd); err != nil {
			return nil, err
		}
		out[id] = cmd
	}
	return out, rows.Err()
}

func seedLastCommands(t *testing.T, s *Store, base time.Time) []string {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	native := func(actor string, at time.Time, kind, command string) {
		if _, err := tx.Exec(`INSERT INTO events(ts,ts_unix_ns,source,kind,command,actor_id) VALUES(?,?,?,?,?,?)`,
			formatFixedUTC(at), at.UnixNano(), "cowrie", kind, command, actor); err != nil {
			t.Fatal(err)
		}
	}
	legacy := func(actor, ts, kind string, command any) {
		if _, err := tx.Exec(`INSERT INTO events(ts,source,kind,command,actor_id) VALUES(?,?,?,?,?)`, ts, "cowrie", kind, command, actor); err != nil {
			t.Fatal(err)
		}
	}
	// A: native only, many connects after its last command.
	native("cowrie:a", base, "command", "first")
	native("cowrie:a", base.Add(time.Minute), "command", "latest-a")
	for i := 0; i < 500; i++ {
		native("cowrie:a", base.Add(time.Duration(2+i)*time.Minute), "connect", "")
	}
	// B: a legacy command whose offset text sorts BEFORE the native one but
	// is the later instant, so exact-time ordering must pick it.
	native("cowrie:b", base.Add(time.Hour), "command", "native-b")
	legacy("cowrie:b", base.Add(2*time.Hour).In(time.FixedZone("w", -12*3600)).Format(time.RFC3339Nano), "command", "legacy-b")
	// C: the newest legacy command loses to a newer native one.
	legacy("cowrie:c", base.Add(time.Hour).Format(time.RFC3339Nano), "command", "legacy-c")
	native("cowrie:c", base.Add(3*time.Hour), "file_download", "http://198.51.100.7/x")
	// D: a same-instant tie is broken by id (the later insert wins).
	native("cowrie:d", base, "command", "tie-1")
	native("cowrie:d", base, "command", "tie-2")
	// E: no command at all, only NULL/empty commands and a long history.
	for i := 0; i < 300; i++ {
		native("cowrie:e", base.Add(time.Duration(i)*time.Second), "connect", "")
	}
	legacy("cowrie:e", base.Format(time.RFC3339Nano), "connect", nil)
	// F: legacy only.
	legacy("cowrie:f", base.Format(time.RFC3339Nano), "command", "old-f")
	legacy("cowrie:f", base.Add(time.Second).Format(time.RFC3339), "command", "new-f")
	// Z: not asked for; must never appear.
	native("cowrie:z", base.Add(9*time.Hour), "command", "unrelated")
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return []string{"cowrie:a", "cowrie:b", "cowrie:c", "cowrie:d", "cowrie:e", "cowrie:f", "cowrie:missing"}
}

func TestLastCommandsForActorsMatchesWholeHistoryRanking(t *testing.T) {
	s := newTestStore(t, "last_cmd_equiv.db")
	ids := seedLastCommands(t, s, time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC))
	want, err := lastCommandsWholeHistory(s, ids)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.LastCommandsForActors(ids)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	exp := map[string]string{"cowrie:a": "latest-a", "cowrie:b": "legacy-b", "cowrie:c": "http://198.51.100.7/x",
		"cowrie:d": "tie-2", "cowrie:f": "new-f"}
	if !reflect.DeepEqual(got, exp) {
		t.Fatalf("fixture expectation: got %v want %v", got, exp)
	}
}

// Command-less actors (most of them: handshake scanners) used to be walked
// through their whole history on every /api/intel poll - 0.87 s of CPU per
// request on a 640k-event DB. The read now goes through the partial
// command index, per actor, newest first, and stops at the first native row;
// the legacy branch stays actor-scoped (never the global legacy index).
func TestLastCommandsForActorsPlanIsBounded(t *testing.T) {
	s := newTestStore(t, "last_cmd_plan.db")
	for i, q := range []string{lastCommandNativeQuery, lastCommandLegacyQuery} {
		rows, err := s.db.Query("EXPLAIN QUERY PLAN "+q, "cowrie:a")
		if err != nil {
			t.Fatal(err)
		}
		var plan []string
		for rows.Next() {
			var a, b, c int
			var d string
			if err := rows.Scan(&a, &b, &c, &d); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, d)
		}
		rows.Close()
		joined := strings.Join(plan, "\n")
		if !strings.Contains(joined, "idx_events_actor_cmd (actor_id=?)") {
			t.Errorf("query %d does not seek the actor's command rows:\n%s", i, joined)
		}
		if strings.Contains(joined, "idx_events_legacy_ts") {
			t.Errorf("query %d forces the global legacy index on an actor read:\n%s", i, joined)
		}
		if i == 0 && strings.Contains(joined, "TEMP B-TREE") {
			t.Errorf("native query sorts instead of reading the index newest-first:\n%s", joined)
		}
	}
}
