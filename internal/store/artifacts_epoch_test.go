package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func insertEpoch(t *testing.T, st *Store, url string, epoch int, status, sha string) {
	t.Helper()
	now := captureTime(time.Now().UTC())
	if _, err := st.db.Exec(`INSERT INTO artifacts(ts,url,origin,status,created_at,fetch_epoch,sha256,attempt_count,last_successful_fetch_at,size_bytes)
VALUES(?,?,'quarantine_fetch',?,?,?,?,1,?,4096)`, now, url, status, now, epoch, sha, now); err != nil {
		t.Fatal(err)
	}
}

func epochRow(t *testing.T, st *Store, url string, epoch int) (status, sha, ts, session string, attempts int) {
	t.Helper()
	if err := st.db.QueryRow(`SELECT status, COALESCE(sha256,''), ts, COALESCE(session_id,''), attempt_count
FROM artifacts WHERE url=? AND fetch_epoch=?`, url, epoch).Scan(&status, &sha, &ts, &session, &attempts); err != nil {
		t.Fatal(err)
	}
	return
}

// A rotated payload's row (epoch 1) must never be claimed, touched or
// re-completed by the epoch-0 capture state machine.
func TestURLKeyedCaptureCodeAddressesEpochZero(t *testing.T) {
	st := newTestStore(t, "epoch.db")
	if err := st.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}
	u := "http://198.51.100.7/bins/x86"
	insertEpoch(t, st, u, 0, "pending", "")
	insertEpoch(t, st, u, 1, "fetched", "bb")
	_, _, ts1, _, _ := epochRow(t, st, u, 1)

	var n int
	if err := st.ArtifactAttemptCount(u, &n); err != nil || n != 1 {
		t.Fatalf("attempt count: %d %v", n, err)
	}
	now := time.Now().UTC()
	due, err := st.DueArtifactCaptures(now, 10, 5)
	if err != nil || len(due) != 1 || due[0] != u {
		t.Fatalf("due = %v, %v; want the epoch-0 row once", due, err)
	}
	if err := st.ClaimArtifactCapture(u, now, now.Add(time.Minute), 1); err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteArtifactCapture(u, 2, "fetched", "", "/e/q/aa", "aa", 10, nil); err != nil {
		t.Fatal(err)
	}
	if status, sha, _, _, attempts := epochRow(t, st, u, 0); status != "fetched" || sha != "aa" || attempts != 2 {
		t.Fatalf("epoch-0 row = %s %q %d; want the completed capture", status, sha, attempts)
	}
	if status, sha, _, _, attempts := epochRow(t, st, u, 1); status != "fetched" || sha != "bb" || attempts != 1 {
		t.Fatalf("epoch-1 row rewritten: %s %q %d", status, sha, attempts)
	}

	if err := st.TouchArtifactTS(u, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, ts, _, _ := epochRow(t, st, u, 1); ts != ts1 {
		t.Fatalf("epoch-1 ts touched: %s -> %s", ts1, ts)
	}
	if _, _, ts, _, _ := epochRow(t, st, u, 0); ts != captureTime(now.Add(time.Hour)) {
		t.Fatalf("epoch-0 ts = %s; want the touch", ts)
	}

	if err := st.SetArtifactSessionByURL(u, "sess-1"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, s, _ := epochRow(t, st, u, 1); s != "" {
		t.Fatalf("epoch-1 session set: %q", s)
	}
	exists, session, err := st.ArtifactCaptureRecord(u)
	if err != nil || !exists || session != "sess-1" {
		t.Fatalf("capture record = %v %q %v", exists, session, err)
	}
	if ok, err := st.ArtifactURLRecorded(u); err != nil || !ok {
		t.Fatalf("recorded = %v %v", ok, err)
	}
}

// A retryable epoch-1 row (not a shape Phase C writes, but the budget sweep
// must not depend on that) is neither listed as due nor marked exhausted.
func TestDueArtifactCapturesIgnoresLaterEpochs(t *testing.T) {
	st := newTestStore(t, "epoch-due.db")
	if err := st.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}
	u := "http://198.51.100.9/y"
	insertEpoch(t, st, u, 0, "fetched", "aa")
	insertEpoch(t, st, u, 1, "failed", "")
	if _, err := st.db.Exec(`UPDATE artifacts SET attempt_count=9 WHERE url=? AND fetch_epoch=1`, u); err != nil {
		t.Fatal(err)
	}
	due, err := st.DueArtifactCaptures(time.Now().UTC(), 10, 5)
	if err != nil || len(due) != 0 {
		t.Fatalf("due = %v, %v; want none", due, err)
	}
	if status, _, _, _, _ := epochRow(t, st, u, 1); status != "failed" {
		t.Fatalf("epoch-1 status = %s; the budget sweep must not touch it", status)
	}
}

func TestURLhausListsEachURLOnce(t *testing.T) {
	st := newTestStore(t, "urlhaus-epochs.db")
	if err := st.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}
	u := "http://198.51.100.8/x"
	insertEpoch(t, st, u, 0, "fetched", "aa")
	insertEpoch(t, st, u, 1, "fetched", "bb")
	// The newer fetch is the row the candidate carries.
	newer := captureTime(time.Now().UTC().Add(time.Minute))
	if _, err := st.db.Exec(`UPDATE artifacts SET last_successful_fetch_at=? WHERE url=? AND fetch_epoch=1`, newer, u); err != nil {
		t.Fatal(err)
	}
	c, err := st.URLhausCandidates(3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != 1 {
		t.Fatalf("candidates = %d, want one per URL", len(c))
	}
	if c[0].SHA256 != "bb" {
		t.Fatalf("candidate sha = %q; want the most recently fetched payload", c[0].SHA256)
	}
	stats, err := st.URLhausSubmissionStats(3)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pending != len(c) {
		t.Fatalf("pending = %d, candidates = %d; they must agree", stats.Pending, len(c))
	}

	// An ineligible newer row (too small) must not hide the eligible one.
	if _, err := st.db.Exec(`UPDATE artifacts SET size_bytes=8 WHERE url=? AND fetch_epoch=1`, u); err != nil {
		t.Fatal(err)
	}
	c, _ = st.URLhausCandidates(3, 0)
	stats, _ = st.URLhausSubmissionStats(3)
	if len(c) != 1 || c[0].SHA256 != "aa" || stats.Pending != 1 {
		t.Fatalf("after shrinking epoch 1: candidates %v, pending %d", c, stats.Pending)
	}
}

// ThreatFox deliberately stays per row: an IOC set is per payload hash, so a
// URL that served two binaries yields two candidates (and two pending).
func TestThreatFoxListsEachPayloadBehindAURL(t *testing.T) {
	st := newTestStore(t, "threatfox-epochs.db")
	if err := st.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}
	u := "http://198.51.100.10/z"
	insertEpoch(t, st, u, 0, "fetched", "aa")
	insertEpoch(t, st, u, 1, "fetched", "bb")
	c, err := st.ThreatFoxCandidates(3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != 2 {
		t.Fatalf("threatfox candidates = %d, want one per payload hash", len(c))
	}
	stats, err := st.ThreatFoxSubmissionStats(3)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pending != 2 {
		t.Fatalf("threatfox pending = %d, want 2", stats.Pending)
	}
}

// A database whose artifacts table is already v27-shaped but stamped 26 (the
// shape the intermediate-v26 tests build) must reopen without re-copying the
// table, keeping later epochs and their provenance columns.
func TestV27RungRerunKeepsEpochs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rerun.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}
	u := "http://198.51.100.11/w"
	insertEpoch(t, st, u, 0, "fetched", "aa")
	insertEpoch(t, st, u, 1, "fetched", "bb")
	if _, err := st.db.Exec(`UPDATE artifacts SET depth=2, parent_sha256='pp' WHERE url=? AND fetch_epoch=1`, u); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`DELETE FROM schema_migrations WHERE version > 26`); err != nil {
		t.Fatal(err)
	}
	st.Close()

	st, err = Open(path)
	if err != nil {
		t.Fatalf("reopen v27-shaped database stamped 26: %v", err)
	}
	defer st.Close()
	var depth int
	var parent string
	if err := st.db.QueryRow(`SELECT depth, COALESCE(parent_sha256,'') FROM artifacts WHERE url=? AND fetch_epoch=1`, u).Scan(&depth, &parent); err != nil {
		t.Fatalf("epoch-1 row: %v", err)
	}
	if depth != 2 || parent != "pp" {
		t.Fatalf("epoch-1 provenance = %d %q; want 2 \"pp\"", depth, parent)
	}
	var stamp int
	if err := st.db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&stamp); err != nil || stamp != latestSnapshotSchema {
		t.Fatalf("stamp = %d, %v; want %d", stamp, err, latestSnapshotSchema)
	}
}

func TestArtifactsTableDDLIsRenamed(t *testing.T) {
	if !strings.HasPrefix(artifactsTableDDL, "CREATE TABLE IF NOT EXISTS artifacts (") {
		t.Fatalf("artifactsTableDDL prefix: %.60q", artifactsTableDDL)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("mustRenameDDL accepted DDL without the expected prefix")
		}
	}()
	mustRenameDDL("CREATE TABLE other (x)", "CREATE TABLE artifacts_v27", "CREATE TABLE IF NOT EXISTS artifacts")
}

// insertArtifactRow writes one artifacts row with explicit columns over a
// fully stamped quarantine_fetch base, so each test can make a later epoch
// differ from epoch 0 in exactly the column the statement under test reads
// or writes. Epoch -1 is used where a read must be shown to ignore a row the
// (url, fetch_epoch) index returns before epoch 0: without the clause such a
// read silently takes whichever row comes first.
func insertArtifactRow(t *testing.T, st *Store, url string, epoch int, cols map[string]any) {
	t.Helper()
	now := captureTime(time.Now().UTC())
	row := map[string]any{
		"ts": now, "url": url, "origin": "quarantine_fetch", "status": "fetched",
		"created_at": now, "fetch_epoch": epoch, "attempt_count": 1,
		"first_observed_at": now, "last_seen_at": now, "size_bytes": 4096,
		"last_successful_fetch_at": now,
	}
	for k, v := range cols {
		row[k] = v
	}
	keys := make([]string, 0, len(row))
	for k := range row {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	args := make([]any, len(keys))
	for i, k := range keys {
		args[i] = row[k]
	}
	q := "INSERT INTO artifacts(" + strings.Join(keys, ",") + ") VALUES(" + strings.TrimSuffix(strings.Repeat("?,", len(keys)), ",") + ")"
	if _, err := st.db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

func artifactCol(t *testing.T, st *Store, url string, epoch int, col string) sql.NullString {
	t.Helper()
	var v sql.NullString
	if err := st.db.QueryRow(`SELECT CAST(`+col+` AS TEXT) FROM artifacts WHERE url=? AND fetch_epoch=?`, url, epoch).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func epochStore(t *testing.T, name string) *Store {
	t.Helper()
	st := newTestStore(t, name)
	if err := st.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}
	return st
}

const epochURL = "http://198.51.100.20/bins/arm7"

// ArtifactURLRecorded and ArtifactCaptureRecord answer for epoch 0: a URL
// whose first-sight row retention removed is not "recorded" just because a
// rotated payload's row survives (discovery must re-queue it).
func TestEpochZeroRecordedReadsIgnoreLaterEpochs(t *testing.T) {
	st := epochStore(t, "epoch-recorded.db")
	insertArtifactRow(t, st, epochURL, 1, map[string]any{"session_id": "s1"})
	if ok, err := st.ArtifactURLRecorded(epochURL); err != nil || ok {
		t.Fatalf("ArtifactURLRecorded = %v, %v; want false (no epoch-0 row)", ok, err)
	}
	if exists, session, err := st.ArtifactCaptureRecord(epochURL); err != nil || exists || session != "" {
		t.Fatalf("ArtifactCaptureRecord = %v %q %v; want no epoch-0 record", exists, session, err)
	}
}

func TestEpochZeroAttemptCountIgnoresLaterEpochs(t *testing.T) {
	st := epochStore(t, "epoch-attempts.db")
	insertArtifactRow(t, st, epochURL, 1, map[string]any{"attempt_count": 3})
	var n int
	if err := st.ArtifactAttemptCount(epochURL, &n); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("attempt count = %d, %v; want ErrNoRows (no epoch-0 row)", n, err)
	}
}

// With no epoch-0 row the touch is a no-op. Unscoped, the read found the
// later epoch's ts, the scoped CAS then matched nothing and the touch retried
// forever, so the call is bounded by a deadline.
func TestEpochZeroTouchReadIgnoresLaterEpochs(t *testing.T) {
	st := epochStore(t, "epoch-touch-read.db")
	old := captureTime(time.Now().UTC().Add(-time.Hour))
	insertArtifactRow(t, st, epochURL, 1, map[string]any{"ts": old})
	done := make(chan error, 1)
	go func() { done <- st.TouchArtifactTS(epochURL, time.Now().UTC()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TouchArtifactTS did not return: its read addressed a later epoch")
	}
	if got := artifactCol(t, st, epochURL, 1, "ts").String; got != old {
		t.Fatalf("epoch-1 ts touched: %s -> %s", old, got)
	}
}

// Identical ts on both rows, so only the epoch clause keeps the CAS UPDATE
// off the later epoch.
func TestEpochZeroTouchCASIgnoresLaterEpochs(t *testing.T) {
	st := epochStore(t, "epoch-touch-cas.db")
	same := captureTime(time.Now().UTC().Add(-time.Hour))
	insertArtifactRow(t, st, epochURL, 1, map[string]any{"ts": same, "last_seen_at": same})
	insertArtifactRow(t, st, epochURL, 0, map[string]any{"ts": same, "last_seen_at": same})
	later := time.Now().UTC()
	if err := st.TouchArtifactTS(epochURL, later); err != nil {
		t.Fatal(err)
	}
	if got := artifactCol(t, st, epochURL, 0, "ts").String; got != captureTime(later) {
		t.Fatalf("epoch-0 ts = %s; want the touch", got)
	}
	if got := artifactCol(t, st, epochURL, 1, "ts").String; got != same {
		t.Fatalf("epoch-1 ts touched: %s", got)
	}
}

// repairArtifactTimesForURL repairs the epoch-0 row only. Epoch 0 is fully
// stamped, so unscoped the repair predicate would select the later epoch.
func TestEpochZeroTimeRepairIgnoresLaterEpochs(t *testing.T) {
	st := epochStore(t, "epoch-repair.db")
	insertArtifactRow(t, st, epochURL, 1, map[string]any{"first_observed_at": nil, "last_seen_at": nil})
	insertArtifactRow(t, st, epochURL, 0, nil)
	if err := st.TouchArtifactTS(epochURL, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if v := artifactCol(t, st, epochURL, 1, "first_observed_at"); v.Valid {
		t.Fatalf("epoch-1 row repaired: first_observed_at=%q", v.String)
	}
}

func TestEpochZeroDueSelectIgnoresLaterEpochs(t *testing.T) {
	st := epochStore(t, "epoch-due-select.db")
	insertArtifactRow(t, st, epochURL, 1, map[string]any{"status": "failed", "attempt_count": 1, "last_successful_fetch_at": nil})
	insertArtifactRow(t, st, epochURL, 0, nil)
	due, err := st.DueArtifactCaptures(time.Now().UTC(), 10, 5)
	if err != nil || len(due) != 0 {
		t.Fatalf("due = %v, %v; a retryable later epoch is not capture work", due, err)
	}
}

func TestEpochZeroClaimIgnoresLaterEpochs(t *testing.T) {
	st := epochStore(t, "epoch-claim.db")
	insertArtifactRow(t, st, epochURL, 1, map[string]any{"status": "failed", "attempt_count": 1})
	insertArtifactRow(t, st, epochURL, 0, map[string]any{"status": "pending", "attempt_count": 1})
	now := time.Now().UTC()
	if err := st.ClaimArtifactCapture(epochURL, now, now.Add(time.Minute), 1); err != nil {
		t.Fatal(err)
	}
	if s := artifactCol(t, st, epochURL, 0, "status").String; s != "capturing" {
		t.Fatalf("epoch-0 status = %s; want capturing", s)
	}
	if s, a := artifactCol(t, st, epochURL, 1, "status").String, artifactCol(t, st, epochURL, 1, "attempt_count").String; s != "failed" || a != "1" {
		t.Fatalf("epoch-1 claimed: status=%s attempts=%s", s, a)
	}
}

// The later epoch carries a live capturing lease at the same attempt count,
// so only the epoch clause keeps the fenced completion off it.
func TestEpochZeroCompleteIgnoresLaterEpochs(t *testing.T) {
	st := epochStore(t, "epoch-complete.db")
	lease := captureTime(time.Now().UTC().Add(time.Hour))
	insertArtifactRow(t, st, epochURL, 1, map[string]any{"status": "capturing", "attempt_count": 2, "lease_until": lease, "sha256": "bb"})
	insertArtifactRow(t, st, epochURL, 0, map[string]any{"status": "pending", "attempt_count": 1})
	now := time.Now().UTC()
	if err := st.ClaimArtifactCapture(epochURL, now, now.Add(time.Minute), 1); err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteArtifactCapture(epochURL, 2, "fetched", "", "/e/q/aa", "aa", 4096, nil); err != nil {
		t.Fatal(err)
	}
	if s := artifactCol(t, st, epochURL, 0, "sha256").String; s != "aa" {
		t.Fatalf("epoch-0 sha = %s; want the completion", s)
	}
	if s, sha := artifactCol(t, st, epochURL, 1, "status").String, artifactCol(t, st, epochURL, 1, "sha256").String; s != "capturing" || sha != "bb" {
		t.Fatalf("epoch-1 completed: status=%s sha=%s", s, sha)
	}
}

// Command re-sighting: the dedup read must see epoch 0's last_seen (epoch -1
// carries a future one that would suppress the touch) and the touch UPDATE
// must leave epoch 1 alone.
func TestEpochZeroCommandDiscoveryTouchIgnoresOtherEpochs(t *testing.T) {
	st := epochStore(t, "epoch-discovery.db")
	base := time.Now().UTC().Truncate(time.Second)
	old := captureTime(base.Add(-2 * time.Hour))
	insertArtifactRow(t, st, epochURL, -1, map[string]any{"ts": old, "last_seen_at": captureTime(base.Add(24 * time.Hour))})
	insertArtifactRow(t, st, epochURL, 0, map[string]any{"ts": old, "last_seen_at": old})
	insertArtifactRow(t, st, epochURL, 1, map[string]any{"ts": old, "last_seen_at": old})
	at := base.Add(-time.Hour)
	ev := &models.Event{TS: at, Source: models.SourceCowrie, Kind: models.KindCommand, SrcIP: "198.51.100.21", SessionID: "s-epoch", ActorID: "cowrie:epoch", Command: "wget " + epochURL}
	if err := st.AppendEventsAndUpsertActorsAgg([]*models.Event{ev}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DiscoverCommandArtifacts(context.Background(), 10, func(string) []string { return []string{epochURL} }); err != nil {
		t.Fatal(err)
	}
	if got := artifactCol(t, st, epochURL, 0, "last_seen_at").String; got != captureTime(at) {
		t.Fatalf("epoch-0 last_seen = %s; want the re-sighting %s", got, captureTime(at))
	}
	if got := artifactCol(t, st, epochURL, 1, "last_seen_at").String; got != old {
		t.Fatalf("epoch-1 last_seen touched: %s", got)
	}
}

// File-capture completion recognises an identical epoch-0 result; a
// different payload at another epoch (returned first by the index) must not
// read as an identity conflict.
func TestEpochZeroFileCaptureConflictReadIgnoresOtherEpochs(t *testing.T) {
	s, job, now := claimedFileFixture(t)
	if err := s.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}
	url := "cowrie-event:" + fmt.Sprint(job.EventID)
	result := FileCaptureResult{Status: FileCaptureArchived, LocalPath: "/inert/evidence/file", SHA256: strings.Repeat("a", 64), SizeBytes: 123}
	insertArtifactRow(t, s, url, -1, map[string]any{"origin": "cowrie_file_download", "sha256": strings.Repeat("c", 64), "size_bytes": 999, "local_path": "/inert/other"})
	insertArtifactRow(t, s, url, 0, map[string]any{"origin": "cowrie_file_download", "sha256": result.SHA256, "size_bytes": result.SizeBytes, "local_path": result.LocalPath})
	if err := s.CompleteFileCapture(context.Background(), job, now.Add(time.Second), result); err != nil {
		t.Fatalf("identical epoch-0 result refused: %v", err)
	}
}

func TestOperationalSnapshotCountsEpochZeroOnly(t *testing.T) {
	st := epochStore(t, "epoch-operational.db")
	insertArtifactRow(t, st, epochURL, 1, map[string]any{"status": "pending"})
	insertArtifactRow(t, st, epochURL+"/b", 0, map[string]any{"status": "pending"})
	stats, err := st.OperationalSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.URLPending != 1 {
		t.Fatalf("URLPending = %d; want only the epoch-0 row", stats.URLPending)
	}
}

func TestArtifactRetentionLiveIsEpochZeroOnly(t *testing.T) {
	st := epochStore(t, "epoch-retention.db")
	old := captureTime(time.Now().UTC().Add(-30 * 24 * time.Hour))
	insertArtifactRow(t, st, epochURL, 0, map[string]any{"status": "failed", "attempt_count": 1, "ts": old, "last_seen_at": old})
	insertArtifactRow(t, st, epochURL, 1, map[string]any{"status": "failed", "attempt_count": 1, "ts": old, "last_seen_at": old})
	expired, _, _, err := artifactRetentionPageTx(st.db, 0, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var epoch1ID int64
	if err := st.db.QueryRow(`SELECT id FROM artifacts WHERE url=? AND fetch_epoch=1`, epochURL).Scan(&epoch1ID); err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0].id != epoch1ID {
		t.Fatalf("expired = %+v; want only the epoch-1 row (epoch 0 is queued work)", expired)
	}
}

// A row fetched in the future (clock skew; urlhaus.Vet refuses it) must not
// hide an older eligible row of the same URL, yet a URL whose only row is
// future-dated still appears so the panel can show Vet's reason.
func TestURLhausSkipsFutureDatedRowForOlderEligibleOne(t *testing.T) {
	st := epochStore(t, "urlhaus-future.db")
	now := time.Now().UTC()
	insertArtifactRow(t, st, epochURL, 0, map[string]any{"sha256": "aa", "last_successful_fetch_at": captureTime(now.Add(-time.Hour))})
	insertArtifactRow(t, st, epochURL, 1, map[string]any{"sha256": "bb", "last_successful_fetch_at": captureTime(now.Add(2 * time.Hour))})
	only := epochURL + "/future-only"
	insertArtifactRow(t, st, only, 0, map[string]any{"sha256": "cc", "last_successful_fetch_at": captureTime(now.Add(2 * time.Hour))})
	c, err := st.URLhausCandidates(3, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range c {
		got[r.URL] = r.SHA256
	}
	if len(c) != 2 || got[epochURL] != "aa" || got[only] != "cc" {
		t.Fatalf("candidates = %v; want %s->aa and %s->cc", got, epochURL, only)
	}
	stats, err := st.URLhausSubmissionStats(3)
	if err != nil || stats.Pending != len(c) {
		t.Fatalf("pending = %d, %v; want %d", stats.Pending, err, len(c))
	}
}
