package store

import (
	"context"
	"database/sql"
	"fmt"
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

// More than one purge chunk of expired sessions must all be removed.
func TestRetentionPurgeFinishesPastOneChunk(t *testing.T) {
	s := newTestStore(t, "retention-chunks.db")
	ctx := context.Background()
	old := time.Now().UTC().AddDate(0, 0, -120)
	for i := 0; i < 1200; i++ {
		cowrieEvent(t, s, fmt.Sprintf("old%d", i), "cowrie:old", "command", "id", "", "", old)
	}
	if _, err := s.RecordCampaignEvidence(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	if err := s.purgeCampaignDerived(ctx, time.Now().UTC().AddDate(0, 0, -90)); err != nil {
		t.Fatal(err)
	}
	var left int
	s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM session_scripts)+(SELECT COUNT(*) FROM session_script_lines)`).Scan(&left)
	if left != 0 {
		t.Fatalf("%d rows left after purge", left)
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

// A Cowrie replace-ingest drops derived rows and rewinds the recorder, but
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
		s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM session_scripts)+(SELECT COUNT(*) FROM session_script_lines)+(SELECT COUNT(*) FROM campaign_evidence)+(SELECT COUNT(*) FROM ingest_state WHERE source='campaign')`).Scan(&n)
		return n
	}
	if err := s.ReplaceSourceEventsAndActorsAgg(models.SourceJournal, nil, nil); err != nil {
		t.Fatal(err)
	}
	if count() == 0 {
		t.Fatal("journal replace cleared Cowrie-derived rows")
	}
	if err := s.ReplaceSourceEventsAndActorsAgg(models.SourceCowrie, nil, nil); err != nil {
		t.Fatal(err)
	}
	var campaigns string
	s.db.QueryRow(`SELECT group_concat(id) FROM campaigns`).Scan(&campaigns)
	if n := count(); n != 0 || campaigns != "c-named" {
		t.Fatalf("derived=%d campaigns=%q", n, campaigns)
	}
}

// Stored bytes must equal the length of the joined script, separators
// included, and never exceed MaxNormalizedBytes.
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
	if stored > script.MaxNormalizedBytes || joined > script.MaxNormalizedBytes || stored != joined {
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
	if err != nil || res.Scanned != 3 {
		t.Fatalf("res=%+v err=%v", res, err)
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
