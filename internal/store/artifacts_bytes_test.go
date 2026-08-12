package store

import (
	"path/filepath"
	"testing"
	"time"
)

// insertFetched writes a fetched artifact row directly, so a test can create the
// many-rows-one-file shape the capture runner legitimately produces.
func insertFetched(t *testing.T, st *Store, url, path string, size int64) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := st.execWrite(
		`INSERT INTO artifacts (ts, url, local_path, sha256, size_bytes, origin, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, 'fetched', ?)`,
		now, url, path, "sha-"+path, size, "cowrie_download", now); err != nil {
		t.Fatal(err)
	}
}

// TestCaptureSummaryCountsEachFileOnce pins the fix for the "evidence on disk"
// tile, which read 6.5% high on the reference deployment (318,739,859 reported
// against 299,790,260 actually on disk).
//
// The cause is structural, not a bad row: the capture runner records an artifact
// per (url, session) sighting while the copy+hash is memoised by content, so one
// payload re-fetched by hundreds of sessions is hundreds of rows over a single
// file. Summing size_bytes per ROW bills those bytes once per sighting. The tile
// is a claim about bytes on disk, so it must group by local_path.
func TestCaptureSummaryCountsEachFileOnce(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}

	// One 1000-byte file, seen by three different URLs (the real shape: a
	// payload re-fetched across sessions dedups to one copy on disk).
	insertFetched(t, st, "http://a.example/x.sh", "/ev/aaa", 1000)
	insertFetched(t, st, "http://b.example/x.sh", "/ev/aaa", 1000)
	insertFetched(t, st, "http://c.example/x.sh", "/ev/aaa", 1000)
	// A genuinely distinct second file.
	insertFetched(t, st, "http://d.example/y.sh", "/ev/bbb", 500)

	sum, err := st.CaptureSummary()
	if err != nil {
		t.Fatal(err)
	}
	// 4 capture attempts, but only 1500 bytes exist on disk.
	if sum.Fetched != 4 {
		t.Errorf("Fetched = %d, want 4: the counts describe capture ATTEMPTS and stay per-row", sum.Fetched)
	}
	if sum.TotalBytes != 1500 {
		t.Errorf("TotalBytes = %d, want 1500; summing per row gives 3500 and bills the "+
			"same file three times under a label that claims bytes on disk", sum.TotalBytes)
	}
}

// TestCaptureSummaryIgnoresPathlessRows covers the rows that have no file to
// measure. A fetched row with no local_path has unattributable bytes: counting
// them would inflate a disk figure with something not on disk, and they cannot
// be deduped because there is no path to group by.
func TestCaptureSummaryIgnoresPathlessRows(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}

	insertFetched(t, st, "http://a.example/x.sh", "/ev/aaa", 1000)
	// NULL local_path (a manual edit or partial migration can produce this).
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := st.execWrite(
		`INSERT INTO artifacts (ts, url, size_bytes, origin, status, created_at)
		 VALUES (?, ?, ?, ?, 'fetched', ?)`,
		now, "test:null-path", 9999, "cowrie_download", now); err != nil {
		t.Fatal(err)
	}
	// Empty-string local_path (what RecordArtifact writes).
	insertFetched(t, st, "test:empty-path", "", 8888)

	sum, err := st.CaptureSummary()
	if err != nil {
		t.Fatalf("CaptureSummary must tolerate NULL/empty local_path: %v", err)
	}
	if sum.TotalBytes != 1000 {
		t.Errorf("TotalBytes = %d, want 1000: rows with no path have no file on disk to measure", sum.TotalBytes)
	}
	if sum.Fetched != 3 {
		t.Errorf("Fetched = %d, want 3: pathless rows are still capture attempts", sum.Fetched)
	}
}

// TestCaptureSummaryEmptyTable guards the aggregate on a fresh install: the
// grouped subquery must yield 0, not NULL (which would fail the int64 scan).
func TestCaptureSummaryEmptyTable(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}
	sum, err := st.CaptureSummary()
	if err != nil {
		t.Fatalf("empty artifacts table must not error: %v", err)
	}
	if sum.Total != 0 || sum.TotalBytes != 0 {
		t.Errorf("fresh install reported total=%d bytes=%d, want 0/0", sum.Total, sum.TotalBytes)
	}
}
