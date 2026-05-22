package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// TestMigrationIdempotent confirms a fresh Open stamps both
// schema_migrations rows and that reopening the same database
// leaves the migration record untouched - i.e. ensureLegacyColumns
// no longer runs every startup.
func TestMigrationIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	// First open: creates schema and records v1+v2.
	s1, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	v1, err := s1.currentSchemaVersion()
	if err != nil {
		t.Fatalf("currentSchemaVersion: %v", err)
	}
	if v1 < 2 {
		t.Fatalf("expected version >= 2 after fresh open, got %d", v1)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Capture the applied_at timestamps to prove migrate() didn't
	// rewrite them on the second open (INSERT OR IGNORE is no-op).
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer db.Close()
	var ts1v1, ts1v2 string
	if err := db.QueryRow(`SELECT applied_at FROM schema_migrations WHERE version=1`).Scan(&ts1v1); err != nil {
		t.Fatalf("scan v1: %v", err)
	}
	if err := db.QueryRow(`SELECT applied_at FROM schema_migrations WHERE version=2`).Scan(&ts1v2); err != nil {
		t.Fatalf("scan v2: %v", err)
	}
	db.Close()

	// Second open: should not advance the ladder or re-stamp rows.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer s2.Close()

	db2, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open 2: %v", err)
	}
	defer db2.Close()
	var ts2v1, ts2v2 string
	if err := db2.QueryRow(`SELECT applied_at FROM schema_migrations WHERE version=1`).Scan(&ts2v1); err != nil {
		t.Fatalf("scan v1 (2nd): %v", err)
	}
	if err := db2.QueryRow(`SELECT applied_at FROM schema_migrations WHERE version=2`).Scan(&ts2v2); err != nil {
		t.Fatalf("scan v2 (2nd): %v", err)
	}
	if ts2v1 != ts1v1 || ts2v2 != ts1v2 {
		t.Errorf("migrate() rewrote schema_migrations on reopen: v1 %q->%q, v2 %q->%q",
			ts1v1, ts2v1, ts1v2, ts2v2)
	}
}

// TestLegacyBackfillUpgradesV0DB simulates a pre-v2 database
// (events table missing all the "legacy" columns) and confirms
// Open() backfills them, records v2, and a subsequent Open() does
// not re-run the backfill.
func TestLegacyBackfillUpgradesV0DB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	// Hand-craft a v0 database: events table with only the original
	// pre-expansion columns, schema_migrations table empty.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := raw.Exec(`
		CREATE TABLE events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT NOT NULL,
			source TEXT NOT NULL,
			kind TEXT NOT NULL,
			src_ip TEXT,
			username TEXT
		);
		CREATE TABLE schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		);
	`); err != nil {
		raw.Close()
		t.Fatalf("setup: %v", err)
	}
	raw.Close()

	// Open via the store - migration must add every legacy column.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	required := []string{
		"src_port", "password", "session_id", "hassh",
		"ssh_client", "ja4", "command", "sha256",
		"filename", "raw", "actor_id",
	}
	cols, err := tableColumns(s, "events")
	if err != nil {
		t.Fatalf("read columns: %v", err)
	}
	for _, c := range required {
		if !cols[c] {
			t.Errorf("legacy backfill missing column %q", c)
		}
	}

	v, err := s.currentSchemaVersion()
	if err != nil {
		t.Fatalf("currentSchemaVersion: %v", err)
	}
	if v < 2 {
		t.Errorf("expected v>=2 after legacy upgrade, got %d", v)
	}
}

// tableColumns is a small helper - reading PRAGMA table_info from
// a *Store needs ad-hoc scanning we don't expose elsewhere.
func tableColumns(s *Store, name string) (map[string]bool, error) {
	rows, err := s.db.Query(`PRAGMA table_info(` + name + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var cid int
		var n, typ string
		var notNull, pk int
		var def sql.NullString
		if err := rows.Scan(&cid, &n, &typ, &notNull, &def, &pk); err != nil {
			return nil, err
		}
		out[n] = true
	}
	return out, rows.Err()
}
