package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// v27 lets one URL own several artifact rows (one per distinct payload), so
// rotated binaries behind the same URL are each kept.
func TestV27ArtifactsKeyedByURLAndEpoch(t *testing.T) {
	st := newTestStore(t, "v27.db")
	if err := st.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}
	ins := `INSERT INTO artifacts(ts,url,origin,status,created_at,fetch_epoch,sha256) VALUES('2026-10-01T00:00:00Z',?, 'quarantine_fetch','fetched','2026-10-01T00:00:00Z',?,?)`
	if _, err := st.db.Exec(ins, "http://203.0.113.9/x", 0, "aa"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(ins, "http://203.0.113.9/x", 1, "bb"); err != nil {
		t.Fatalf("second epoch of one url refused: %v", err)
	}
	if _, err := st.db.Exec(ins, "http://203.0.113.9/x", 1, "cc"); err == nil {
		t.Fatal("duplicate (url, fetch_epoch) accepted")
	}
	var depth int
	var parent *string
	if err := st.db.QueryRow(`SELECT depth, parent_sha256 FROM artifacts WHERE sha256='aa'`).Scan(&depth, &parent); err != nil {
		t.Fatal(err)
	}
	if depth != 0 || parent != nil {
		t.Fatalf("defaults: depth=%d parent=%v", depth, parent)
	}
	if latestSnapshotSchema != 27 {
		t.Fatalf("latestSnapshotSchema = %d", latestSnapshotSchema)
	}
}

// The rebuild keeps every row, its id and the AUTOINCREMENT high-water mark,
// and recreates the indexes the queries rely on.
func TestV27RebuildPreservesRowsIDsAndIndexes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v25.db")
	buildReleasedDB(t, "schema-v25-campaigns-rc1.sql", path)
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for i, u := range []string{"http://198.51.100.1/a", "cowrie-download:abc", "cowrie-event:42"} {
		if _, err := raw.Exec(`INSERT INTO artifacts(id,ts,url,origin,status,created_at,attempt_count) VALUES(?,?,?,?,?,?,1)`,
			100+i, "2026-09-01T00:00:00Z", u, "quarantine_fetch", "fetched", "2026-09-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	// A purged newest row: the sequence sits above MAX(id) and must survive.
	if _, err := raw.Exec(`UPDATE sqlite_sequence SET seq=150 WHERE name='artifacts'`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var n, maxID, seq int
	if err := st.db.QueryRow(`SELECT COUNT(*), MAX(id) FROM artifacts`).Scan(&n, &maxID); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT seq FROM sqlite_sequence WHERE name='artifacts'`).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	if n != 3 || maxID != 102 || seq != 150 {
		t.Fatalf("rows=%d max=%d seq=%d", n, maxID, seq)
	}
	var leftovers int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM sqlite_sequence WHERE name='artifacts_v27'`).Scan(&leftovers); err != nil || leftovers != 0 {
		t.Fatalf("artifacts_v27 sequence rows=%d err=%v", leftovers, err)
	}
	for _, idx := range []string{"idx_artifacts_url_epoch", "idx_artifacts_capture_due", "idx_artifacts_sha256", "idx_artifacts_session", "idx_artifacts_created", "idx_refetch_due"} {
		var c int
		if err := st.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&c); err != nil {
			t.Fatal(err)
		}
		if c != 1 {
			t.Fatalf("index %s missing after v27", idx)
		}
	}
	var auto int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='sqlite_autoindex_artifacts_1'`).Scan(&auto); err != nil {
		t.Fatal(err)
	}
	if auto != 0 {
		t.Fatal("UNIQUE(url) survived the rebuild")
	}
	// A new row continues above the carried high-water mark.
	res, err := st.db.Exec(`INSERT INTO artifacts(ts,url,origin,status,created_at) VALUES('2026-10-01T00:00:00Z','http://198.51.100.2/b','quarantine_fetch','pending','2026-10-01T00:00:00Z')`)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := res.LastInsertId(); id != 151 {
		t.Fatalf("next id = %d, want 151", id)
	}
}
