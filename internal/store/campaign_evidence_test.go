package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

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
	stub := func(map[string]*ActorState, func(func(*models.Event) error) error) ([]*models.AggregatedActor, error) {
		return nil, nil
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
