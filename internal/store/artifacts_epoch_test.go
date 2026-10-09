package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
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
