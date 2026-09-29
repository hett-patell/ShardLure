package store

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCarryScriptAssignmentsRules(t *testing.T) {
	a := func(id string, seq int64) scriptAssignment { return scriptAssignment{id, seq} }
	cases := []struct {
		name     string
		pairs    [][2]string
		assigned map[string]scriptAssignment
		set      map[string]scriptAssignment
		del      []string
	}{
		{name: "unchanged", pairs: [][2]string{{"o", "o"}, {"o", "o"}},
			assigned: map[string]scriptAssignment{"o": a("c1", 1)}, set: map[string]scriptAssignment{}},
		{name: "a minority survivor does not keep the row", pairs: [][2]string{{"o", "o"}, {"o", "n"}, {"o", "n"}},
			assigned: map[string]scriptAssignment{"o": a("c1", 1)}, set: map[string]scriptAssignment{"n": a("c1", 1)}, del: []string{"o"}},
		{name: "old keeps the majority", pairs: [][2]string{{"o", "o"}, {"o", "o"}, {"o", "n"}},
			assigned: map[string]scriptAssignment{"o": a("c1", 1)}, set: map[string]scriptAssignment{}},
		{name: "old ties with a larger fingerprint and keeps it", pairs: [][2]string{{"o", "o"}, {"o", "p"}},
			assigned: map[string]scriptAssignment{"o": a("c1", 1)}, set: map[string]scriptAssignment{}},
		{name: "old ties with a smaller fingerprint and loses it", pairs: [][2]string{{"o", "o"}, {"o", "n"}},
			assigned: map[string]scriptAssignment{"o": a("c1", 1)}, set: map[string]scriptAssignment{"n": a("c1", 1)}, del: []string{"o"}},
		{name: "changed", pairs: [][2]string{{"o", "n"}, {"o", "n"}},
			assigned: map[string]scriptAssignment{"o": a("c1", 4)}, set: map[string]scriptAssignment{"n": a("c1", 4)}, del: []string{"o"}},
		{name: "split goes to the majority", pairs: [][2]string{{"o", "n1"}, {"o", "n2"}, {"o", "n2"}},
			assigned: map[string]scriptAssignment{"o": a("c1", 4)}, set: map[string]scriptAssignment{"n2": a("c1", 4)}, del: []string{"o"}},
		{name: "split tie goes to the smallest fingerprint", pairs: [][2]string{{"o", "nb"}, {"o", "na"}},
			assigned: map[string]scriptAssignment{"o": a("c1", 4)}, set: map[string]scriptAssignment{"na": a("c1", 4)}, del: []string{"o"}},
		{name: "collapse keeps the lowest seq", pairs: [][2]string{{"o1", "n"}, {"o2", "n"}, {"o3", "n"}},
			assigned: map[string]scriptAssignment{"o1": a("c1", 9), "o2": a("c2", 3), "o3": a("c3", 7)},
			set:      map[string]scriptAssignment{"n": a("c2", 3)}, del: []string{"o1", "o2", "o3"}},
		{name: "collapse seq tie keeps the lowest key", pairs: [][2]string{{"ob", "n"}, {"oa", "n"}},
			assigned: map[string]scriptAssignment{"oa": a("c1", 3), "ob": a("c2", 3)},
			set:      map[string]scriptAssignment{"n": a("c1", 3)}, del: []string{"oa", "ob"}},
		{name: "existing row with a lower seq wins", pairs: [][2]string{{"o", "n"}},
			assigned: map[string]scriptAssignment{"o": a("c1", 5), "n": a("c2", 2)},
			set:      map[string]scriptAssignment{}, del: []string{"o"}},
		{name: "existing row with a higher seq loses", pairs: [][2]string{{"o", "n"}},
			assigned: map[string]scriptAssignment{"o": a("c1", 5), "n": a("c2", 8)},
			set:      map[string]scriptAssignment{"n": a("c1", 5)}, del: []string{"o"}},
		{name: "rotation: a moved-away row does not compete", pairs: [][2]string{{"o1", "o2"}, {"o2", "u"}},
			assigned: map[string]scriptAssignment{"o1": a("c1", 9), "o2": a("c2", 1)},
			set:      map[string]scriptAssignment{"o2": a("c1", 9), "u": a("c2", 1)}, del: []string{"o1"}},
		{name: "no row, or nothing settled: skipped", pairs: [][2]string{{"x", "n"}},
			assigned: map[string]scriptAssignment{"o": a("c1", 1)}, set: map[string]scriptAssignment{}},
	}
	for _, tc := range cases {
		set, del := carryScriptAssignments(tc.pairs, tc.assigned)
		if !reflect.DeepEqual(set, tc.set) || !reflect.DeepEqual(del, tc.del) {
			t.Errorf("%s: set=%v del=%v, want set=%v del=%v", tc.name, set, del, tc.set, tc.del)
		}
	}
}

// The hold waits for the recorder and for every session with a line at or
// below the high-water mark to settle, and ends at the deadline regardless.
func TestScriptRebuildHoldGates(t *testing.T) {
	s := newTestStore(t, "hold.db")
	ctx := context.Background()
	now := time.Now().UTC()
	cowrieEvent(t, s, "s1", "cowrie:a", "command", "id", "", "", now.Add(-time.Hour))
	if _, err := s.RecordCampaignEvidence(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	if reset, err := s.ResetScriptsForVersion(ctx, 99); err != nil || !reset {
		t.Fatalf("reset=%v err=%v", reset, err)
	}
	if held, err := s.ScriptRebuildHold(ctx, time.Now()); err != nil || !held {
		t.Fatalf("recorder behind: held=%v err=%v", held, err)
	}
	if _, err := s.RecordCampaignEvidence(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	if held, err := s.ScriptRebuildHold(ctx, time.Now()); err != nil || !held {
		t.Fatalf("session unsettled: held=%v err=%v", held, err)
	}
	// The deadline ends it even with the session still unsettled.
	if held, err := s.ScriptRebuildHold(ctx, time.Now().Add(scriptHoldDuration+time.Minute)); err != nil || held {
		t.Fatalf("past the deadline: held=%v err=%v", held, err)
	}
	if held, err := s.ScriptRebuildHold(ctx, time.Now()); err != nil || held {
		t.Fatalf("released hold came back: held=%v err=%v", held, err)
	}
	// A second bump: settling ends it before the deadline.
	if _, err := s.ResetScriptsForVersion(ctx, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordCampaignEvidence(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	if n, err := s.SettleSessionScripts(ctx, time.Now().Add(time.Minute), 10); err != nil || n != 1 {
		t.Fatalf("settle %d %v", n, err)
	}
	if held, err := s.ScriptRebuildHold(ctx, time.Now()); err != nil || held {
		t.Fatalf("all settled: held=%v err=%v", held, err)
	}
}

// Downtime after a reset must not release the hold: the deadline counts from
// the first check that sees the recorder past the high-water mark, and is
// persisted so a restart keeps it. Before, it counted from the reset, and a
// restart 2 hours later released at once with nothing re-recorded, deleting
// the carry snapshot.
func TestScriptRebuildHoldSurvivesDowntime(t *testing.T) {
	s := newTestStore(t, "hold-downtime.db")
	ctx := context.Background()
	cowrieEvent(t, s, "s1", "cowrie:a", "command", "id", "", "", time.Now().UTC().Add(-time.Hour))
	if _, err := s.RecordCampaignEvidence(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO session_scripts(session_id,actor_id,first_seen,last_seen,updated_at,fingerprint) VALUES('old','cowrie:a','x','x','x','fp')`); err != nil {
		t.Fatal(err)
	}
	if reset, err := s.ResetScriptsForVersion(ctx, 99); err != nil || !reset {
		t.Fatalf("reset=%v err=%v", reset, err)
	}
	restart := time.Now().Add(2 * time.Hour)
	if held, err := s.ScriptRebuildHold(ctx, restart); err != nil || !held {
		t.Fatalf("restart after downtime, recorder behind: held=%v err=%v", held, err)
	}
	if _, err := s.RecordCampaignEvidence(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	if held, err := s.ScriptRebuildHold(ctx, restart); err != nil || !held {
		t.Fatalf("recorder caught up, session unsettled: held=%v err=%v", held, err)
	}
	var carried int
	s.db.QueryRow(`SELECT COUNT(*) FROM script_version_carry`).Scan(&carried)
	if carried != 1 {
		t.Fatalf("carry snapshot lost (%d rows)", carried)
	}
	// The clock started at the first observation (restart), not the reset.
	if held, err := s.ScriptRebuildHold(ctx, restart.Add(scriptHoldDuration-time.Minute)); err != nil || !held {
		t.Fatalf("inside the deadline: held=%v err=%v", held, err)
	}
	if held, err := s.ScriptRebuildHold(ctx, restart.Add(scriptHoldDuration+time.Minute)); err != nil || held {
		t.Fatalf("past the deadline: held=%v err=%v", held, err)
	}
}

// The release applies the majority rule through SQL: two of O's three
// sessions settled to N, one still to O, so O's row moves to N.
func TestScriptRebuildReleaseMovesRowToMajority(t *testing.T) {
	s := newTestStore(t, "hold-majority.db")
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO script_version_carry(session_id,fingerprint) VALUES('s1','O'),('s2','O'),('s3','O')`,
		`INSERT INTO session_scripts(session_id,actor_id,first_seen,last_seen,updated_at,settled_at,fingerprint) VALUES
  ('s1','cowrie:a','x','x','x','x','O'),('s2','cowrie:b','x','x','x','x','N'),('s3','cowrie:c','x','x','x','x','N')`,
		`INSERT INTO campaign_ids(kind,value,campaign_id,seq) VALUES('script','O','c-keep',3),('ssh_key','k','c-other',1)`,
		`INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES('script_version','hold_hwm',0,0,'','x')`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if held, err := s.ScriptRebuildHold(ctx, time.Now()); err != nil || held {
		t.Fatalf("held=%v err=%v", held, err)
	}
	rows, err := s.db.Query(`SELECT kind, value, campaign_id, seq FROM campaign_ids ORDER BY kind, value`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var k, v, id string
		var seq int
		if err := rows.Scan(&k, &v, &id, &seq); err != nil {
			t.Fatal(err)
		}
		got = append(got, fmt.Sprintf("%s:%s=%s/%d", k, v, id, seq))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if want := "script:N=c-keep/3 ssh_key:k=c-other/1"; strings.Join(got, " ") != want {
		t.Fatalf("campaign_ids %v, want %s", got, want)
	}
}
