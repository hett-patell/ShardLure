package store

import (
	"path/filepath"
	"testing"
	"time"
)

// TestListArtifactsToleratesNullColumns guards the COALESCE hardening: a row
// with NULL in the nullable text columns (which a manual DB edit, a future
// writer, or a partial migration could produce) must not abort the whole
// listing with "converting NULL to string is unsupported".
func TestListArtifactsToleratesNullColumns(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}

	// Insert a row with NULL src_ip/session_id/actor_id/local_path/sha256/detail
	// directly (bypassing RecordArtifact, which would write '').
	if _, err := st.execWrite(
		`INSERT INTO artifacts (ts, url, origin, status, created_at) VALUES (?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339Nano), "test:null-row", "cowrie_download", "fetched",
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	// Before the COALESCE fix this errored on the NULL->string scan.
	rows, err := st.ListArtifactsSince(time.Now().Add(-time.Hour), 50)
	if err != nil {
		t.Fatalf("ListArtifactsSince must tolerate NULL columns, got: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(rows))
	}
	if rows[0].SrcIP != "" || rows[0].SHA256 != "" {
		t.Fatalf("NULL columns should read as empty string, got srcip=%q sha=%q", rows[0].SrcIP, rows[0].SHA256)
	}
}
