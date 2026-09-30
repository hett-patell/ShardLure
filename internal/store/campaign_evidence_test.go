package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/script"
	"github.com/networkshard/shardlure/pkg/models"
)

func cowrieEvent(t *testing.T, s *Store, session, actorID, kind, cmd, sha, file string, ts time.Time) {
	t.Helper()
	if err := s.InsertEvent(&models.Event{TS: ts, Source: models.SourceCowrie, Kind: models.EventKind(kind), SrcIP: "203.0.113.7",
		SessionID: session, ActorID: actorID, Command: cmd, SHA256: sha, Filename: file}); err != nil {
		t.Fatal(err)
	}
}

const injector = `cd ~; chattr -ia .ssh; rm -rf .ssh && mkdir .ssh && echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKBT1fubDzcjP8Ntf33MZwaTgCpwTQRaj7IrSvXO0lBU mdrfckr" >> .ssh/authorized_keys && chmod -R go= ~/.ssh`

func TestRecordCampaignEvidence(t *testing.T) {
	s := newTestStore(t, "evidence.db")
	ctx := context.Background()
	now := time.Now().UTC()
	cowrieEvent(t, s, "s1", "cowrie:h1", "command", injector, "", "", now)
	cowrieEvent(t, s, "s1", "cowrie:h1", "command", "uname -a", "", "", now.Add(time.Second))
	sha := "a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2"
	cowrieEvent(t, s, "s2", "cowrie:h2", "file_upload", "", sha, "redtail.arm7", now)
	cowrieEvent(t, s, "s3", "", "command", injector, "", "", now) // admin: never recorded

	res, err := s.RecordCampaignEvidence(ctx, 1000)
	if err != nil || !res.Done || res.Scanned != 4 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	var lines, count int
	s.db.QueryRow(`SELECT COUNT(*) FROM session_script_lines WHERE session_id='s1'`).Scan(&lines)
	s.db.QueryRow(`SELECT line_count FROM session_scripts WHERE session_id='s1'`).Scan(&count)
	if lines != 2 || count != 2 {
		t.Fatalf("lines=%d count=%d", lines, count)
	}
	var key, label, ip string
	if err := s.db.QueryRow(`SELECT value, label, src_ip FROM campaign_evidence WHERE kind='ssh_key' AND session_id='s1'`).Scan(&key, &label, &ip); err != nil ||
		key != "SHA256:a3pXoOM5a2tpPZaM56vV25nc+/JCaTsQNGnx6Na1k8I" || label != "mdrfckr" || ip != "203.0.113.7" {
		t.Fatalf("key evidence %q %q %q %v", key, label, ip, err)
	}
	var pl string
	if err := s.db.QueryRow(`SELECT label FROM campaign_evidence WHERE kind='payload' AND value=?`, sha).Scan(&pl); err != nil || pl != "redtail.arm7" {
		t.Fatalf("payload label %q %v", pl, err)
	}
	var admin int
	s.db.QueryRow(`SELECT COUNT(*) FROM session_scripts WHERE session_id='s3'`).Scan(&admin)
	if admin != 0 {
		t.Fatal("admin session recorded")
	}
	// Replay safety: rewinding the cursor must not double-append.
	if _, err := s.db.Exec(`DELETE FROM ingest_state WHERE source='campaign'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	s.db.QueryRow(`SELECT line_count FROM session_scripts WHERE session_id='s1'`).Scan(&count)
	if count != 2 {
		t.Fatalf("replay changed line_count to %d", count)
	}
}

func TestEvidenceScanSeeksRowidWindow(t *testing.T) {
	s := newTestStore(t, "evidence-plan.db")
	rows, err := s.db.Query("EXPLAIN QUERY PLAN "+evidenceScanQuery, 1, 2)
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
	if j := strings.Join(plan, "\n"); !strings.Contains(j, "SEARCH events USING INTEGER PRIMARY KEY (rowid>? AND rowid<?)") {
		t.Fatalf("must seek the rowid window:\n%s", j)
	}
}

func TestEvidenceCursorAdvancesPastEmptyWindows(t *testing.T) {
	s := newTestStore(t, "evidence-empty.db")
	for i := 0; i < 5; i++ {
		if err := s.InsertEvent(&models.Event{TS: time.Now().UTC(), Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: "192.0.2.1", ActorID: "journal:192.0.2.1"}); err != nil {
			t.Fatal(err)
		}
	}
	var res EvidenceRecordResult
	var err error
	for i := 0; i < 4 && !res.Done; i++ {
		if res, err = s.RecordCampaignEvidence(context.Background(), 2); err != nil {
			t.Fatal(err)
		}
	}
	if !res.Done {
		t.Fatal("cursor stuck on windows without Cowrie events")
	}
}

func TestEvidenceWindowByteBudget(t *testing.T) {
	s := newTestStore(t, "evidence-bytes.db")
	old := maxEvidenceWindowBytes
	maxEvidenceWindowBytes = 100
	t.Cleanup(func() { maxEvidenceWindowBytes = old })
	for i := 0; i < 3; i++ {
		cowrieEvent(t, s, "s", "cowrie:a", "command", strings.Repeat("x", 80), "", "", time.Now().UTC())
	}
	res, err := s.RecordCampaignEvidence(context.Background(), 1000)
	if err != nil || res.Done || res.Scanned >= 3 {
		t.Fatalf("byte budget ignored: %+v %v", res, err)
	}
	for i := 0; i < 5 && !res.Done; i++ {
		if res, err = s.RecordCampaignEvidence(context.Background(), 1000); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	s.db.QueryRow(`SELECT line_count FROM session_scripts WHERE session_id='s'`).Scan(&n)
	if !res.Done || n != 3 {
		t.Fatalf("resume after budget: done=%v lines=%d", res.Done, n)
	}
}

func TestEvidenceFollowsHASSHRekey(t *testing.T) {
	s := newTestStore(t, "rekey.db")
	cowrieEvent(t, s, "s1", "cowrie:203.0.113.7", "command", injector, "", "", time.Now().UTC())
	if _, err := s.RecordCampaignEvidence(context.Background(), 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO campaign_members(campaign_id,actor_id,sessions,ips,reasons) VALUES('c-000000000001','cowrie:203.0.113.7',1,1,'ssh_key')`); err != nil {
		t.Fatal(err)
	}
	// The IP actor ends up empty, so reconcile deletes it; its membership must go too.
	stub := func(map[string]*ActorState, func(func(*models.Event) error) error) ([]*models.AggregatedActor, error) {
		return []*models.AggregatedActor{{Actor: &models.Actor{ID: "cowrie:203.0.113.7", Source: models.SourceCowrie}}}, nil
	}
	if err := s.ReconcileSessionHASSH("s1", "cowrie:hh", "hh", stub); err != nil {
		t.Fatal(err)
	}
	var a1, a2 string
	s.db.QueryRow(`SELECT actor_id FROM session_scripts WHERE session_id='s1'`).Scan(&a1)
	s.db.QueryRow(`SELECT actor_id FROM campaign_evidence WHERE session_id='s1'`).Scan(&a2)
	if a1 != "cowrie:hh" || a2 != "cowrie:hh" {
		t.Fatalf("evidence did not follow the re-key: %q %q", a1, a2)
	}
	var ghost int
	s.db.QueryRow(`SELECT COUNT(*) FROM campaign_members WHERE actor_id='cowrie:203.0.113.7'`).Scan(&ghost)
	if ghost != 0 {
		t.Fatal("deleted IP actor left a ghost campaign member")
	}
}

// More than one purge chunk of expired sessions must all be removed. 5,100
// one-line sessions exceed step 1's 5,000-row candidate query, so a second
// chunk has to delete rows (the old 1,200 fit into one chunk; store-pipeline
// audit M7). 5,100 old evidence rows do the same for the evidence step's
// LIMIT 5000.
func TestRetentionPurgeFinishesPastOneChunk(t *testing.T) {
	s := newTestStore(t, "retention-chunks.db")
	ctx := context.Background()
	old := formatFixedUTC(time.Now().UTC().AddDate(0, 0, -120))
	const n = 5100
	if err := s.WithTx(func(tx *sql.Tx) error {
		for i := 0; i < n; i++ {
			sess := fmt.Sprintf("old%05d", i)
			if _, err := tx.Exec(`INSERT INTO session_scripts(session_id,actor_id,line_count,bytes,first_seen,last_seen,updated_at) VALUES(?,'cowrie:old',1,2,?,?,?)`, sess, old, old, old); err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO session_script_lines(session_id,event_id,line) VALUES(?,?,'id')`, sess, i+1); err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO campaign_evidence(kind,value,session_id,first_seen,last_seen) VALUES('ssh_key',?,?,?,?)`, fmt.Sprintf("SHA256:k%05d", i), sess, old, old); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	working := map[int]int{}
	purgeChunkDone = func(step int, deleted int64) {
		if deleted > 0 {
			working[step]++
		}
	}
	t.Cleanup(func() { purgeChunkDone = nil })
	if err := s.purgeCampaignDerived(ctx, time.Now().UTC().AddDate(0, 0, -90)); err != nil {
		t.Fatal(err)
	}
	var left int
	s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM session_scripts)+(SELECT COUNT(*) FROM session_script_lines)+(SELECT COUNT(*) FROM campaign_evidence)`).Scan(&left)
	if left != 0 {
		t.Fatalf("%d rows left after purge", left)
	}
	if working[0] < 2 || working[1] < 2 {
		t.Fatalf("chunks that deleted rows: sessions %d, evidence %d; want at least 2 each", working[0], working[1])
	}
}

func TestRetentionPurgesCampaignDerived(t *testing.T) {
	s := newTestStore(t, "retention.db")
	ctx := context.Background()
	old := time.Now().UTC().AddDate(0, 0, -120)
	cowrieEvent(t, s, "old", "cowrie:old", "command", injector, "", "", old)
	cowrieEvent(t, s, "new", "cowrie:new", "command", injector, "", "", time.Now().UTC())
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	if err := upsertActor(s.db, &models.Actor{ID: "cowrie:old", Source: models.SourceCowrie, FirstSeen: old, LastSeen: old}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO campaigns(id,name,updated_at) VALUES('c-000000000001','Outlaw','now')`); err != nil {
		t.Fatal(err)
	}
	if err := s.MaintenancePurge(90); err != nil {
		t.Fatal(err)
	}
	var oldRows, newRows, named int
	s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM session_script_lines WHERE session_id='old')+(SELECT COUNT(*) FROM session_scripts WHERE session_id='old')+(SELECT COUNT(*) FROM campaign_evidence WHERE session_id='old')`).Scan(&oldRows)
	s.db.QueryRow(`SELECT COUNT(*) FROM campaign_evidence WHERE session_id='new'`).Scan(&newRows)
	s.db.QueryRow(`SELECT COUNT(*) FROM campaigns WHERE id='c-000000000001'`).Scan(&named)
	if oldRows != 0 || newRows != 1 || named != 1 {
		t.Fatalf("old=%d new=%d named=%d", oldRows, newRows, named)
	}
}

// A Cowrie replace-ingest drops derived rows and parks the recorder, but
// keeps operator-named campaigns; a journal replace leaves them alone.
func TestReplaceClearsCampaignDerived(t *testing.T) {
	s := newTestStore(t, "replace.db")
	cowrieEvent(t, s, "s1", "cowrie:h1", "command", injector, "", "", time.Now().UTC())
	if _, err := s.RecordCampaignEvidence(context.Background(), 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO campaigns(id,name,updated_at) VALUES('c-named','Outlaw','now'),('c-auto','','now')`); err != nil {
		t.Fatal(err)
	}
	count := func() (n int) {
		s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM session_scripts)+(SELECT COUNT(*) FROM session_script_lines)+(SELECT COUNT(*) FROM campaign_evidence)`).Scan(&n)
		return n
	}
	if err := s.ReplaceSourceEventsAndActorsAgg(models.SourceJournal, nil, nil); err != nil {
		t.Fatal(err)
	}
	if count() == 0 {
		t.Fatal("journal replace cleared Cowrie-derived rows")
	}
	var oldMax int64
	s.db.QueryRow(`SELECT MAX(id) FROM events`).Scan(&oldMax)
	if err := s.ReplaceSourceEventsAndActorsAgg(models.SourceCowrie, nil, nil); err != nil {
		t.Fatal(err)
	}
	var campaigns string
	s.db.QueryRow(`SELECT group_concat(id) FROM campaigns`).Scan(&campaigns)
	if n := count(); n != 0 || campaigns != "c-named" {
		t.Fatalf("derived=%d campaigns=%q", n, campaigns)
	}
	// The recorder is parked at the pre-delete MAX(id), not deleted: with
	// nothing re-ingested the next window has nothing to walk.
	if c := evidenceCursorValue(t, s); c != oldMax {
		t.Fatalf("cursor after replace %d, want %d", c, oldMax)
	}
	if res, err := s.RecordCampaignEvidence(context.Background(), 1000); err != nil || !res.Done || res.Scanned != 0 {
		t.Fatalf("window after an empty replace: %+v %v", res, err)
	}
}

// A --replace parks the recorder at the pre-delete MAX(id) instead of
// deleting the cursor. events.id is AUTOINCREMENT and sqlite_sequence never
// resets, so every re-ingested row gets a larger id: the first tick after a
// replace reads them in one window instead of first stepping 5,000-rowid
// windows across the emptied range (~350 empty seeks on prod), and none of
// them is skipped.
func TestReplaceParksCursorBelowReingestedRows(t *testing.T) {
	s := newTestStore(t, "replace-cursor.db")
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 6; i++ {
		cowrieEvent(t, s, fmt.Sprintf("old%d", i), "cowrie:a", "command", "id", "", "", now)
	}
	var res EvidenceRecordResult
	var err error
	for !res.Done {
		if res, err = s.RecordCampaignEvidence(ctx, 2); err != nil {
			t.Fatal(err)
		}
	}
	var oldMax int64
	s.db.QueryRow(`SELECT MAX(id) FROM events`).Scan(&oldMax)
	fresh := []*models.Event{
		{TS: now, Source: models.SourceCowrie, Kind: models.KindCommand, SrcIP: "203.0.113.7", SessionID: "n1", ActorID: "cowrie:h1", Command: injector},
		{TS: now, Source: models.SourceCowrie, Kind: models.KindCommand, SrcIP: "203.0.113.7", SessionID: "n1", ActorID: "cowrie:h1", Command: "uname -a"},
	}
	if err := s.ReplaceSourceEventsAndActorsAgg(models.SourceCowrie, fresh, nil); err != nil {
		t.Fatal(err)
	}
	if c := evidenceCursorValue(t, s); c != oldMax {
		t.Fatalf("cursor after replace %d, want the pre-delete max %d", c, oldMax)
	}
	var minNew int64
	s.db.QueryRow(`SELECT MIN(id) FROM events`).Scan(&minNew)
	if minNew <= oldMax {
		t.Fatalf("re-ingested ids start at %d, not above the pre-delete max %d", minNew, oldMax)
	}
	// One 2-rowid window covers both re-ingested rows: no empty range first.
	res, err = s.RecordCampaignEvidence(ctx, 2)
	if err != nil || !res.Done || res.Scanned != 2 || res.Recorded != 2 {
		t.Fatalf("first window after the replace: %+v %v", res, err)
	}
	var lines int
	s.db.QueryRow(`SELECT line_count FROM session_scripts WHERE session_id='n1'`).Scan(&lines)
	if lines != 2 {
		t.Fatalf("re-ingested lines=%d, want 2", lines)
	}
}

// Stored bytes must equal the length of the joined script, separators
// included, and never exceed MaxNormalizedBytes. The one exception is a
// session a refused line closed: its bytes read exactly the cap, so no later
// line is admitted (see TestSessionScriptByteCapKeepsThePrefix).
func TestSessionScriptByteCapCountsSeparators(t *testing.T) {
	s := newTestStore(t, "evidence-cap.db")
	cmd := strings.Repeat("x", 218) // 300 lines fit without separators, not with
	if l := script.EncodeLine(cmd); len(l) != 218 {
		t.Fatalf("encoding changed: %d", len(l))
	}
	now := time.Now().UTC()
	for i := 0; i < script.MaxCommands; i++ {
		cowrieEvent(t, s, "cap", "cowrie:a", "command", cmd, "", "", now.Add(time.Duration(i)*time.Millisecond))
	}
	if _, err := s.RecordCampaignEvidence(context.Background(), 1000); err != nil {
		t.Fatal(err)
	}
	var stored int
	if err := s.db.QueryRow(`SELECT bytes FROM session_scripts WHERE session_id='cap'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	rows, err := s.db.Query(`SELECT line FROM session_script_lines WHERE session_id='cap' ORDER BY event_id`)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for rows.Next() {
		var l string
		if err := rows.Scan(&l); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, l)
	}
	rows.Close()
	joined := len(script.Join(lines))
	// 300 x 218 bytes plus separators overflows on the last line, which
	// closes the session.
	if joined > script.MaxNormalizedBytes || stored != script.MaxNormalizedBytes || len(lines) != script.MaxCommands-1 {
		t.Fatalf("stored=%d joined=%d lines=%d cap=%d", stored, joined, len(lines), script.MaxNormalizedBytes)
	}
}

func TestPayloadEvidenceRejectsUnusableHashes(t *testing.T) {
	s := newTestStore(t, "evidence-payload.db")
	now := time.Now().UTC()
	cowrieEvent(t, s, "p1", "cowrie:a", "file_download", "", "not-a-hash", "x.sh", now)
	cowrieEvent(t, s, "p2", "cowrie:a", "file_download", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty", now)
	cowrieEvent(t, s, "p3", "cowrie:a", "file_download", "", "", "nohash", now)
	res, err := s.RecordCampaignEvidence(context.Background(), 1000)
	if err != nil || res.Scanned != 3 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM campaign_evidence`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d payload evidence rows from unusable hashes", n)
	}
}

// Stored times are always fixed-width UTC: ts_unix_ns wins, a parseable ts is
// normalised, and a row with neither is skipped rather than stored raw.
func TestEvidenceTimestampsAreFixedWidth(t *testing.T) {
	s := newTestStore(t, "evidence-ts.db")
	at := time.Date(2026, 9, 1, 12, 0, 0, 5, time.UTC)
	cowrieEvent(t, s, "ns", "cowrie:a", "command", "id", "", "", at)
	cowrieEvent(t, s, "legacy", "cowrie:a", "command", "id", "", "", at)
	cowrieEvent(t, s, "bad", "cowrie:a", "command", "id", "", "", at)
	if _, err := s.db.Exec(`UPDATE events SET ts='garbage' WHERE session_id='ns'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE events SET ts='2026-09-01T14:00:00.000000005+02:00', ts_unix_ns=NULL WHERE session_id='legacy'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE events SET ts='garbage', ts_unix_ns=NULL WHERE session_id='bad'`); err != nil {
		t.Fatal(err)
	}
	res, err := s.RecordCampaignEvidence(context.Background(), 1000)
	if err != nil || res.Scanned != 3 || res.Recorded != 2 || res.Skipped != 1 {
		t.Fatalf("res=%+v err=%v (want 3 scanned, 2 recorded, 1 skipped)", res, err)
	}
	want := formatFixedUTC(at)
	for _, sess := range []string{"ns", "legacy"} {
		var first, last string
		if err := s.db.QueryRow(`SELECT first_seen, last_seen FROM session_scripts WHERE session_id=?`, sess).Scan(&first, &last); err != nil || first != want || last != want {
			t.Fatalf("%s: %q %q %v", sess, first, last, err)
		}
	}
	var bad int
	s.db.QueryRow(`SELECT COUNT(*) FROM session_scripts WHERE session_id='bad'`).Scan(&bad)
	if bad != 0 {
		t.Fatal("unparseable timestamp was stored")
	}
}

// Sessions with many lines each must be purged in bounded chunks and finish.
func TestRetentionPurgesLongSessionsInChunks(t *testing.T) {
	s := newTestStore(t, "retention-long.db")
	old := formatFixedUTC(time.Now().UTC().AddDate(0, 0, -120))
	err := s.WithTx(func(tx *sql.Tx) error {
		for i := 0; i < 30; i++ {
			sess := fmt.Sprintf("long%d", i)
			if _, err := tx.Exec(`INSERT INTO session_scripts(session_id,actor_id,line_count,bytes,first_seen,last_seen,updated_at) VALUES(?,?,300,0,?,?,?)`, sess, "cowrie:x", old, old, old); err != nil {
				return err
			}
			for j := 0; j < 300; j++ {
				if _, err := tx.Exec(`INSERT INTO session_script_lines(session_id,event_id,line) VALUES(?,?,'id')`, sess, i*1000+j); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.purgeCampaignDerived(context.Background(), time.Now().UTC().AddDate(0, 0, -90)); err != nil {
		t.Fatal(err)
	}
	var left int
	s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM session_scripts)+(SELECT COUNT(*) FROM session_script_lines)`).Scan(&left)
	if left != 0 {
		t.Fatalf("%d rows left", left)
	}
}

// A window request above the clamp is cut to 5,000 rowids: one window is one
// writeMu transaction, and 5,000 matches the MaintenancePurge chunk size.
func TestRecordCampaignEvidenceClampsWindowTo5000(t *testing.T) {
	s := newTestStore(t, "clamp.db")
	ctx := context.Background()
	now := time.Now().UTC()
	cowrieEvent(t, s, "a", "cowrie:a", "command", "id", "", "", now)
	cowrieEvent(t, s, "b", "cowrie:b", "command", "id", "", "", now)
	if _, err := s.db.Exec(`UPDATE events SET id=9000 WHERE id=(SELECT MAX(id) FROM events)`); err != nil {
		t.Fatal(err)
	}
	res, err := s.RecordCampaignEvidence(ctx, 50000)
	if err != nil {
		t.Fatal(err)
	}
	if res.Done || res.Scanned != 1 {
		t.Fatalf("window not clamped to 5000: %+v", res)
	}
	if res, err = s.RecordCampaignEvidence(ctx, 50000); err != nil || !res.Done || res.Scanned != 1 {
		t.Fatalf("second window %+v %v", res, err)
	}
}

func evidenceCursorValue(t *testing.T, s *Store) int64 {
	t.Helper()
	c, err := evidenceCursor(context.Background(), s.db)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The recorder normalises outside writeMu and re-reads the window inside it.
// Rows deleted between the phases (a purge) leave nothing to insert, and the
// cursor still advances past them.
func TestEvidenceRowsDeletedBetweenPhasesAdvanceCursor(t *testing.T) {
	s := newTestStore(t, "evidence-phases-delete.db")
	ctx := context.Background()
	now := time.Now().UTC()
	cowrieEvent(t, s, "s1", "cowrie:a", "command", "id", "", "", now)
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	cowrieEvent(t, s, "s2", "cowrie:b", "command", injector, "", "", now)
	cowrieEvent(t, s, "s2", "cowrie:b", "command", "uname -a", "", "", now)
	var maxID int64
	s.db.QueryRow(`SELECT MAX(id) FROM events`).Scan(&maxID)
	evidenceBetweenPhases = func() {
		evidenceBetweenPhases = nil
		if _, err := s.db.Exec(`DELETE FROM events WHERE session_id='s2'`); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { evidenceBetweenPhases = nil })
	res, err := s.RecordCampaignEvidence(ctx, 1000)
	if err != nil || !res.Done || res.Scanned != 2 || res.Recorded != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if c := evidenceCursorValue(t, s); c != maxID {
		t.Fatalf("cursor %d, want %d (past the deleted rows)", c, maxID)
	}
	var n int
	s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM session_scripts WHERE session_id='s2')+(SELECT COUNT(*) FROM session_script_lines WHERE session_id='s2')+(SELECT COUNT(*) FROM campaign_evidence WHERE session_id='s2')`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d derived rows written for deleted events", n)
	}
}

// A --replace between the phases resets the cursor. Advancing it to this
// window's end would overwrite the reset and skip the re-ingested rows, so
// the recorder drops the window and reports Done:false for the tick to retry.
func TestEvidenceReplaceBetweenPhasesKeepsResetCursor(t *testing.T) {
	s := newTestStore(t, "evidence-phases-replace.db")
	ctx := context.Background()
	now := time.Now().UTC()
	cowrieEvent(t, s, "s1", "cowrie:a", "command", "id", "", "", now)
	cowrieEvent(t, s, "s1", "cowrie:a", "command", "w", "", "", now)
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	cowrieEvent(t, s, "s2", "cowrie:b", "command", injector, "", "", now)
	var want int64
	evidenceBetweenPhases = func() {
		evidenceBetweenPhases = nil
		if err := s.ReplaceSourceEventsAndActorsAgg(models.SourceCowrie, nil, nil); err != nil {
			t.Fatal(err)
		}
		want = evidenceCursorValue(t, s)
	}
	t.Cleanup(func() { evidenceBetweenPhases = nil })
	res, err := s.RecordCampaignEvidence(ctx, 1000)
	if err != nil || res.Done || res.Recorded != 0 {
		t.Fatalf("a window overtaken by a replace must be retried, not committed: %+v %v", res, err)
	}
	if got := evidenceCursorValue(t, s); got != want {
		t.Fatalf("cursor %d, the replace left %d", got, want)
	}
	var n int
	s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM session_script_lines)+(SELECT COUNT(*) FROM campaign_evidence)`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d derived rows written after the replace", n)
	}
}

// No normalisation runs under writeMu: every EncodeLine and ExtractKeys call
// happens before the between-phases seam, none after it (the attacker-shaped
// CPU stays outside the write transaction).
func TestEvidenceNormalisesOutsideWriteLock(t *testing.T) {
	s := newTestStore(t, "evidence-phases-cpu.db")
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		cowrieEvent(t, s, "s1", "cowrie:a", "command", injector, "", "", now.Add(time.Duration(i)*time.Second))
	}
	oldEnc, oldKeys := evidenceEncodeLine, evidenceExtractKeys
	var calls, atSeam int
	evidenceEncodeLine = func(c string) string { calls++; return oldEnc(c) }
	evidenceExtractKeys = func(c string) []script.Key { calls++; return oldKeys(c) }
	evidenceBetweenPhases = func() { atSeam = calls }
	t.Cleanup(func() { evidenceEncodeLine, evidenceExtractKeys, evidenceBetweenPhases = oldEnc, oldKeys, nil })
	res, err := s.RecordCampaignEvidence(context.Background(), 1000)
	if err != nil || !res.Done || res.Recorded != 3 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if atSeam != 6 || calls != atSeam {
		t.Fatalf("normaliser calls: %d before the write transaction, %d in total (want 6 and 6)", atSeam, calls)
	}
	var lines, keys int
	s.db.QueryRow(`SELECT line_count FROM session_scripts WHERE session_id='s1'`).Scan(&lines)
	s.db.QueryRow(`SELECT COUNT(*) FROM campaign_evidence WHERE kind='ssh_key' AND session_id='s1'`).Scan(&keys)
	if lines != 3 || keys != 1 {
		t.Fatalf("lines=%d keys=%d", lines, keys)
	}
}

// A session already at MaxCommands does not pay EncodeLine for further
// commands (the transaction would drop the line anyway); keys are still
// extracted, because a key is evidence past the line cap.
func TestEvidenceSkipsNormalisingCappedSessions(t *testing.T) {
	s := newTestStore(t, "evidence-phases-cap.db")
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < script.MaxCommands; i++ {
		cowrieEvent(t, s, "cap", "cowrie:a", "command", "id", "", "", now.Add(time.Duration(i)*time.Millisecond))
	}
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	cowrieEvent(t, s, "cap", "cowrie:a", "command", injector, "", "", now.Add(time.Second))
	cowrieEvent(t, s, "cap", "cowrie:a", "command", "uname -a", "", "", now.Add(2*time.Second))
	oldEnc, oldKeys := evidenceEncodeLine, evidenceExtractKeys
	var enc, keys int
	evidenceEncodeLine = func(c string) string { enc++; return oldEnc(c) }
	evidenceExtractKeys = func(c string) []script.Key { keys++; return oldKeys(c) }
	t.Cleanup(func() { evidenceEncodeLine, evidenceExtractKeys = oldEnc, oldKeys })
	res, err := s.RecordCampaignEvidence(ctx, 1000)
	if err != nil || res.Scanned != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if enc != 0 || keys != 2 {
		t.Fatalf("capped session: EncodeLine calls=%d (want 0), ExtractKeys calls=%d (want 2)", enc, keys)
	}
	var count, evidence int
	s.db.QueryRow(`SELECT line_count FROM session_scripts WHERE session_id='cap'`).Scan(&count)
	s.db.QueryRow(`SELECT COUNT(*) FROM campaign_evidence WHERE kind='ssh_key' AND session_id='cap'`).Scan(&evidence)
	if count != script.MaxCommands || evidence != 1 {
		t.Fatalf("line_count=%d evidence=%d", count, evidence)
	}
}

// The batched phase-2 write spans many multi-row statements (lines, session
// counters, the IN-list reads) and must keep the per-row semantics: caps
// applied in event-id order across statement boundaries, the last line's
// actor, min/max times, the first line's IP, and replays neither re-inserted
// nor counted.
func TestEvidenceBatchedWriteKeepsPerRowSemantics(t *testing.T) {
	s := newTestStore(t, "evidence-batched.db")
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)
	const sessions = 400
	if err := s.WithTx(func(tx *sql.Tx) error {
		for i := 0; i < sessions*3; i++ {
			sess := fmt.Sprintf("s%03d", i%sessions)
			if err := insertEvent(tx, &models.Event{TS: base.Add(time.Duration(i) * time.Second), Source: models.SourceCowrie, Kind: models.KindCommand,
				SrcIP: fmt.Sprintf("198.51.100.%d", i/sessions), SessionID: sess, ActorID: fmt.Sprintf("cowrie:a%d", i/sessions), Command: fmt.Sprintf("echo %d", i)}); err != nil {
				return err
			}
		}
		// One session crosses MaxCommands inside the same window.
		for i := 0; i < script.MaxCommands+5; i++ {
			if err := insertEvent(tx, &models.Event{TS: base.Add(time.Duration(i) * time.Millisecond), Source: models.SourceCowrie, Kind: models.KindCommand,
				SrcIP: "198.51.100.9", SessionID: "capped", ActorID: "cowrie:c", Command: "id"}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	check := func(label string) {
		t.Helper()
		var lines, n int
		s.db.QueryRow(`SELECT COUNT(*) FROM session_script_lines`).Scan(&lines)
		s.db.QueryRow(`SELECT COUNT(*) FROM session_scripts WHERE line_count=3 AND actor_id='cowrie:a2' AND src_ip='198.51.100.0'`).Scan(&n)
		if lines != sessions*3+script.MaxCommands || n != sessions {
			t.Fatalf("%s: lines=%d sessions-ok=%d", label, lines, n)
		}
		var first, last string
		var cnt, bytes int
		s.db.QueryRow(`SELECT first_seen, last_seen, line_count, bytes FROM session_scripts WHERE session_id='s007'`).Scan(&first, &last, &cnt, &bytes)
		want := len(script.Join([]string{script.EncodeLine("echo 7"), script.EncodeLine(fmt.Sprintf("echo %d", 7+sessions)), script.EncodeLine(fmt.Sprintf("echo %d", 7+2*sessions))}))
		if first != formatFixedUTC(base.Add(7*time.Second)) || last != formatFixedUTC(base.Add(time.Duration(7+2*sessions)*time.Second)) || cnt != 3 || bytes != want {
			t.Fatalf("%s: s007 first=%s last=%s count=%d bytes=%d (want %d)", label, first, last, cnt, bytes, want)
		}
		s.db.QueryRow(`SELECT line_count FROM session_scripts WHERE session_id='capped'`).Scan(&cnt)
		if cnt != script.MaxCommands {
			t.Fatalf("%s: capped session has %d lines", label, cnt)
		}
	}
	if res, err := s.RecordCampaignEvidence(ctx, 5000); err != nil || !res.Done {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	check("first pass")
	// Replay the whole window: nothing is inserted or counted twice.
	if _, err := s.db.Exec(`UPDATE ingest_state SET offset=0 WHERE source='campaign'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordCampaignEvidence(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	check("replay")
}

// The orphan-actor sweep removes an orphan's session_scripts rows and, in
// the same transaction, their lines, so a purge never leaves lines without a
// session row. Here the session's last_seen is inside retention (so the
// retention steps keep it) while its actor has no events left: only the
// sweep removes it, and nothing of it may remain.
func TestOrphanSweepRemovesScriptLines(t *testing.T) {
	s := newTestStore(t, "retention-orphan-lines.db")
	old := time.Now().UTC().AddDate(0, 0, -120)
	if err := upsertActor(s.db, &models.Actor{ID: "cowrie:gone", Source: models.SourceCowrie, FirstSeen: old, LastSeen: old}); err != nil {
		t.Fatal(err)
	}
	recent := formatFixedUTC(time.Now().UTC())
	for _, q := range []string{
		`INSERT INTO session_scripts(session_id,actor_id,line_count,bytes,first_seen,last_seen,updated_at) VALUES('sx','cowrie:gone',2,5,'` + recent + `','` + recent + `','` + recent + `')`,
		`INSERT INTO session_script_lines(session_id,event_id,line) VALUES('sx',1,'id'),('sx',2,'w')`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.MaintenancePurge(90); err != nil {
		t.Fatal(err)
	}
	var actors, left int
	s.db.QueryRow(`SELECT COUNT(*) FROM actors WHERE id='cowrie:gone'`).Scan(&actors)
	s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM session_scripts)+(SELECT COUNT(*) FROM session_script_lines)`).Scan(&left)
	if actors != 0 || left != 0 {
		t.Fatalf("actor rows=%d, script rows left=%d", actors, left)
	}
}

// Retention step 1 lists old sessions through the last_seen index and
// deletes their lines through the (session_id, event_id) key: a scan of
// either table under writeMu is what the chunking exists to avoid.
func TestPurgeScriptLinesPlan(t *testing.T) {
	s := newTestStore(t, "retention-plan.db")
	plan := func(q string, args ...any) string {
		t.Helper()
		rows, err := s.db.Query("EXPLAIN QUERY PLAN "+q, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var a, b, c int
			var d string
			if err := rows.Scan(&a, &b, &c, &d); err != nil {
				t.Fatal(err)
			}
			out = append(out, d)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return strings.Join(out, "\n")
	}
	// The settle list and the hold's pending check state their plans in
	// comments; pin them (store-pipeline audit M9). Both must go through the
	// pending partial index, never a scan of every session.
	if j := plan(settlePendingQuery, "x", "x", 10); !strings.Contains(j, "USING INDEX idx_session_scripts_pending (last_seen<?)") || strings.Contains(j, "SCAN session_scripts") {
		t.Fatalf("settle list must seek the pending partial index:\n%s", j)
	}
	if j := plan(holdPendingQuery, 10); !strings.Contains(j, "idx_session_scripts_pending") || !strings.Contains(j, "sqlite_autoindex_session_script_lines_1 (session_id=? AND event_id<?)") || strings.Contains(j, "SCAN l") {
		t.Fatalf("hold pending check must walk the pending index and probe the line key:\n%s", j)
	}
	if j := plan(purgeOldSessionsQuery, formatFixedUTC(time.Now())); !strings.Contains(j, "USING INDEX idx_session_scripts_last_seen (last_seen<?)") || strings.Contains(j, "SCAN ") {
		t.Fatalf("session selection must seek the last_seen index:\n%s", j)
	}
	if j := plan(`DELETE FROM session_script_lines WHERE session_id IN (?,?)`, "a", "b"); !strings.Contains(j, "sqlite_autoindex_session_script_lines_1 (session_id=?)") || strings.Contains(j, "SCAN ") {
		t.Fatalf("line delete must seek the line key:\n%s", j)
	}
	if j := plan(`DELETE FROM session_scripts WHERE session_id IN (?,?)`, "a", "b"); !strings.Contains(j, "sqlite_autoindex_session_scripts_1 (session_id=?)") || strings.Contains(j, "SCAN ") {
		t.Fatalf("session delete must seek the session key:\n%s", j)
	}
}

// Retention deletes a session's lines and its row in one transaction, so a
// settle running between purge chunks never sees a session with some of its
// lines gone and never fingerprints a partial script.
func TestSettleNeverSeesPartlyPurgedSession(t *testing.T) {
	s := newTestStore(t, "retention-settle.db")
	ctx := context.Background()
	old := formatFixedUTC(time.Now().UTC().AddDate(0, 0, -120))
	// 40 sessions x 300 lines = 12,000 lines. A chunk takes sessions until
	// their lines reach 5,000 (17 x 300 = 5,100), so this is three deleting
	// chunks, and the settle below runs between them. The old 17 sessions fit
	// one chunk and only the empty terminating chunk made chunks >= 2
	// (store-pipeline audit M7).
	if err := s.WithTx(func(tx *sql.Tx) error {
		for i := 0; i < 40; i++ {
			sess := fmt.Sprintf("p%02d", i)
			if _, err := tx.Exec(`INSERT INTO session_scripts(session_id,actor_id,line_count,bytes,first_seen,last_seen,updated_at) VALUES(?,?,300,0,?,?,?)`, sess, "cowrie:x", old, old, old); err != nil {
				return err
			}
			for j := 0; j < 300; j++ {
				if _, err := tx.Exec(`INSERT INTO session_script_lines(session_id,event_id,line) VALUES(?,?,'id')`, sess, i*1000+j); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	chunks := 0
	purgeChunkDone = func(step int, deleted int64) {
		if step != 0 || deleted == 0 {
			return
		}
		chunks++
		var partial int
		s.db.QueryRow(`SELECT COUNT(*) FROM session_scripts ss WHERE line_count <> (SELECT COUNT(*) FROM session_script_lines l WHERE l.session_id=ss.session_id)`).Scan(&partial)
		if partial != 0 {
			t.Errorf("chunk %d: %d sessions partly purged", chunks, partial)
		}
		if _, err := s.SettleSessionScripts(ctx, time.Now(), 0); err != nil {
			t.Error(err)
		}
		var short int
		s.db.QueryRow(`SELECT COUNT(*) FROM scripts WHERE command_count <> 300`).Scan(&short)
		if short != 0 {
			t.Errorf("chunk %d: %d scripts fingerprinted from a partial session", chunks, short)
		}
	}
	t.Cleanup(func() { purgeChunkDone = nil })
	if err := s.purgeCampaignDerived(ctx, time.Now().UTC().AddDate(0, 0, -90)); err != nil {
		t.Fatal(err)
	}
	var left int
	s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM session_scripts)+(SELECT COUNT(*) FROM session_script_lines)`).Scan(&left)
	if chunks < 3 || left != 0 {
		t.Fatalf("chunks=%d left=%d", chunks, left)
	}
}

// A campaign-derived retention failure is reported, but the orphan-actor
// sweep still runs: derived data must not keep stale actors alive.
func TestPurgeContinuesPastCampaignDerivedFailure(t *testing.T) {
	s := newTestStore(t, "retention-campaign-fail.db")
	old := time.Now().UTC().AddDate(0, 0, -120)
	if err := upsertActor(s.db, &models.Actor{ID: "cowrie:gone", Source: models.SourceCowrie, FirstSeen: old, LastSeen: old}); err != nil {
		t.Fatal(err)
	}
	purgeCampaignDerivedFail = func() error { return fmt.Errorf("boom") }
	t.Cleanup(func() { purgeCampaignDerivedFail = nil })
	err := s.MaintenancePurge(90)
	if err == nil || !strings.Contains(err.Error(), "campaign-derived retention: boom") {
		t.Fatalf("err = %v", err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM actors WHERE id='cowrie:gone'`).Scan(&n)
	if n != 0 {
		t.Fatal("the orphan sweep was skipped")
	}
}

// When a later purge step also fails, both errors are returned: the
// campaign-derived failure must not be swallowed by the sweep's.
func TestPurgeJoinsCampaignDerivedAndLaterErrors(t *testing.T) {
	s := newTestStore(t, "retention-campaign-join.db")
	old := time.Now().UTC().AddDate(0, 0, -120)
	if err := upsertActor(s.db, &models.Actor{ID: "cowrie:bad", Source: models.SourceCowrie, FirstSeen: old, LastSeen: old}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE actors SET last_seen='not-a-time' WHERE id='cowrie:bad'`); err != nil {
		t.Fatal(err)
	}
	boom := fmt.Errorf("boom")
	purgeCampaignDerivedFail = func() error { return boom }
	t.Cleanup(func() { purgeCampaignDerivedFail = nil })
	err := s.MaintenancePurge(90)
	if !errors.Is(err, boom) || err == nil || !strings.Contains(err.Error(), "last_seen") {
		t.Fatalf("err = %v, want both the campaign and the sweep error", err)
	}
}

// The byte cap must leave the capped prefix. It used to skip only the line
// that did not fit and admit later, smaller ones, so an attacker could drop
// one oversized, payload-bearing command (encodings grow up to 4x) from the
// middle of a script and collide with a session that never ran it (script
// audit M8). Once a line is refused for bytes the session is closed, in the
// same window and in every later one.
func TestSessionScriptByteCapKeepsThePrefix(t *testing.T) {
	// Ingest keeps at most 64 KiB of command text, so the oversized line is
	// one whose *encoding* grows past the budget: each quoted `<` encodes as
	// `<lt>` (120,007 bytes here).
	big := "echo '" + strings.Repeat("<", 30000) + "'"
	if n := len(script.EncodeLine(big)); n <= script.MaxNormalizedBytes {
		t.Fatalf("encoding changed: %d bytes fits the budget", n)
	}
	lines := func(t *testing.T, s *Store, session string) []string {
		t.Helper()
		rows, err := s.db.Query(`SELECT line FROM session_script_lines WHERE session_id=? ORDER BY event_id`, session)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var l string
			if err := rows.Scan(&l); err != nil {
				t.Fatal(err)
			}
			out = append(out, l)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, window := range []int{1000, 1} { // one window, and one window per event
		t.Run(fmt.Sprintf("window-%d", window), func(t *testing.T) {
			s := newTestStore(t, "evidence-prefix.db")
			ctx := context.Background()
			old := time.Now().UTC().Add(-time.Hour)
			cowrieEvent(t, s, "mid", "cowrie:a", "command", "echo a", "", "", old)
			cowrieEvent(t, s, "mid", "cowrie:a", "command", big, "", "", old.Add(time.Second))
			cowrieEvent(t, s, "mid", "cowrie:a", "command", "echo b", "", "", old.Add(2*time.Second))
			cowrieEvent(t, s, "first", "cowrie:b", "command", big, "", "", old)
			cowrieEvent(t, s, "first", "cowrie:b", "command", "echo c", "", "", old.Add(time.Second))
			for {
				res, err := s.RecordCampaignEvidence(ctx, window)
				if err != nil {
					t.Fatal(err)
				}
				if res.Done {
					break
				}
			}
			if got, want := lines(t, s, "mid"), []string{script.EncodeLine("echo a")}; !reflect.DeepEqual(got, want) {
				t.Fatalf("mid lines = %q, want the prefix %q", got, want)
			}
			if got := lines(t, s, "first"); len(got) != 0 {
				t.Fatalf("first lines = %d: a refused first line leaves an empty prefix", len(got))
			}
			if n, err := s.SettleSessionScripts(ctx, time.Now().Add(time.Hour), 100); err != nil || n != 1 {
				t.Fatalf("settled %d, %v; want only the mid session (an empty prefix has no script)", n, err)
			}
			var pending int
			if err := s.db.QueryRow(`SELECT COUNT(*) FROM session_scripts WHERE settled_at='' OR updated_at>settled_at`).Scan(&pending); err != nil || pending != 0 {
				t.Fatalf("pending sessions = %d, %v: a closed empty session must never sit in the settle list", pending, err)
			}
			var fp string
			if err := s.db.QueryRow(`SELECT fingerprint FROM session_scripts WHERE session_id='mid'`).Scan(&fp); err != nil || fp != script.Fingerprint(script.Join([]string{script.EncodeLine("echo a")})) {
				t.Fatalf("mid fingerprint %q, %v", fp, err)
			}
		})
	}
}

// A settle stamps settled_at = max(now, updated_at). If it ran with the clock
// ahead, settled_at lies in the future, and a line recorded after the clock is
// corrected has updated_at < settled_at: the old pending test
// (updated_at > settled_at) was false and the session kept its prefix
// fingerprint for good (store-pipeline audit M1). Adding a line now clears
// settled_at, so the session is pending whatever either clock said.
func TestLateLineResettlesAfterFutureSettle(t *testing.T) {
	s := newTestStore(t, "evidence-future-settle.db")
	ctx := context.Background()
	old := time.Now().UTC().Add(-time.Hour)
	cowrieEvent(t, s, "s1", "cowrie:a", "command", "echo a", "", "", old)
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	if n, err := s.SettleSessionScripts(ctx, time.Now().Add(time.Minute), 10); err != nil || n != 1 {
		t.Fatalf("settle %d %v", n, err)
	}
	// The settle ran with the clock a day ahead.
	future := formatFixedUTC(time.Now().Add(24 * time.Hour))
	if _, err := s.db.Exec(`UPDATE session_scripts SET settled_at=? WHERE session_id='s1'`, future); err != nil {
		t.Fatal(err)
	}
	var before string
	s.db.QueryRow(`SELECT fingerprint FROM session_scripts WHERE session_id='s1'`).Scan(&before)
	cowrieEvent(t, s, "s1", "cowrie:a", "command", "echo b", "", "", old.Add(time.Second))
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	if n, err := s.SettleSessionScripts(ctx, time.Now().Add(time.Minute), 10); err != nil || n != 1 {
		t.Fatalf("late line not re-settled: %d %v", n, err)
	}
	var after string
	s.db.QueryRow(`SELECT fingerprint FROM session_scripts WHERE session_id='s1'`).Scan(&after)
	if after == before || after != script.Fingerprint(script.Join([]string{script.EncodeLine("echo a"), script.EncodeLine("echo b")})) {
		t.Fatalf("fingerprint %s -> %s: still the prefix", before, after)
	}
}

// Phase 2's guard was "cursor unchanged", an ABA check (pipeline audit M1):
// a version reset in another process rewinds the cursor to 0 and can record
// back up to exactly the value phase 1 read, after which phase 2 wrote lines
// the OLD encoder produced under the NEW version stamp. The guard now compares
// the reset epoch as well (bumped by ResetScriptsForVersion and a Cowrie
// --replace), so phase 2 gives up and the tick retries with the new encoder.
func TestRecorderPhaseTwoRefusesStaleCursorAcrossReset(t *testing.T) {
	s := newTestStore(t, "evidence-aba.db")
	ctx := context.Background()
	if _, err := s.ResetScriptsForVersion(ctx, 1); err != nil { // stamp version 1 on the empty DB
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Hour)
	cowrieEvent(t, s, "s1", "cowrie:a", "command", "id", "", "", now)
	cowrieEvent(t, s, "s1", "cowrie:a", "command", "uname -a", "", "", now.Add(time.Second))
	if res, err := s.RecordCampaignEvidence(ctx, 2); err != nil || !res.Done {
		t.Fatalf("%+v %v", res, err)
	}
	cowrieEvent(t, s, "s2", "cowrie:b", "command", "id", "", "", now.Add(2*time.Second))
	cowrieEvent(t, s, "s2", "cowrie:b", "command", "uname -a", "", "", now.Add(3*time.Second))
	if c := evidenceCursorValue(t, s); c != 2 {
		t.Fatalf("cursor %d", c)
	}
	orig := evidenceEncodeLine
	evidenceEncodeLine = func(c string) string { return "OLD:" + orig(c) }
	t.Cleanup(func() { evidenceEncodeLine = orig; evidenceBetweenPhases = nil })
	evidenceBetweenPhases = func() {
		evidenceBetweenPhases = nil
		evidenceEncodeLine = orig
		// The other process (the new binary): version bump, rewind to 0,
		// record the first window, which lands the cursor back on 2.
		if reset, err := s.ResetScriptsForVersion(ctx, 2); err != nil || !reset {
			t.Fatalf("reset=%v %v", reset, err)
		}
		if res, err := s.RecordCampaignEvidence(ctx, 2); err != nil || res.Done {
			t.Fatalf("%+v %v", res, err)
		}
		if c := evidenceCursorValue(t, s); c != 2 {
			t.Fatalf("inner cursor %d", c)
		}
	}
	res, err := s.RecordCampaignEvidence(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if res.Done || res.Recorded != 0 {
		t.Fatalf("phase 2 wrote through a reset: %+v", res)
	}
	lines := func() map[int64]string {
		t.Helper()
		out := map[int64]string{}
		rows, err := s.db.Query(`SELECT event_id, line FROM session_script_lines ORDER BY event_id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var id int64
			var line string
			if err := rows.Scan(&id, &line); err != nil {
				t.Fatal(err)
			}
			out[id] = line
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	for id, line := range lines() {
		if strings.HasPrefix(line, "OLD:") {
			t.Fatalf("event %d carries the old encoding under the new version: %q", id, line)
		}
	}
	if got := lines(); len(got) != 2 || got[3] != "" {
		t.Fatalf("lines after the refused window = %v, want only the first window's two", got)
	}
	// The retry records the second window with the new encoder.
	if res, err := s.RecordCampaignEvidence(ctx, 2); err != nil || !res.Done || res.Recorded != 2 {
		t.Fatalf("retry %+v %v", res, err)
	}
	if got := lines(); len(got) != 4 || got[3] != script.EncodeLine("id") || got[4] != script.EncodeLine("uname -a") {
		t.Fatalf("lines after the retry = %v", got)
	}
}
