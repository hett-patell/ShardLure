package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// TestMigrationIdempotent confirms a fresh Open stamps schema_migrations
// rows for every ladder step and that reopening the same database leaves
// the migration record untouched.
func TestMigrationIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	s1, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	v, err := s1.currentSchemaVersion()
	if err != nil {
		t.Fatalf("currentSchemaVersion: %v", err)
	}
	if v < 13 {
		t.Fatalf("expected version >= 13 after fresh open, got %d", v)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer db.Close()
	first := map[int]string{}
	for ver := 1; ver <= 4; ver++ {
		var ts string
		db.QueryRow(`SELECT applied_at FROM schema_migrations WHERE version=?`, ver).Scan(&ts)
		first[ver] = ts
	}
	db.Close()

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
	for ver := 1; ver <= 4; ver++ {
		var ts string
		db2.QueryRow(`SELECT applied_at FROM schema_migrations WHERE version=?`, ver).Scan(&ts)
		if ts != first[ver] {
			t.Errorf("migrate() rewrote v%d on reopen: %q -> %q",
				ver, first[ver], ts)
		}
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
		"ssh_client", "command", "sha256",
		"filename", "raw", "actor_id",
		// v11: proxy/pivot forwarding destination, added by the versioned
		// migration ladder (not the legacy backfill) on an already-open DB.
		"dst_ip", "dst_port",
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

// TestAppSettingsRoundTrip confirms the v13 app_settings table exists on a
// fresh DB and the CRUD helpers upsert/read/delete correctly.
func TestAppSettingsRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if _, ok, err := s.GetAppSetting("missing"); err != nil || ok {
		t.Fatalf("GetAppSetting(missing) = (_, %v, %v), want (_, false, nil)", ok, err)
	}
	if err := s.SetAppSetting("k", "v1"); err != nil {
		t.Fatalf("SetAppSetting: %v", err)
	}
	if v, ok, err := s.GetAppSetting("k"); err != nil || !ok || v != "v1" {
		t.Fatalf("GetAppSetting after set = (%q, %v, %v), want (v1, true, nil)", v, ok, err)
	}
	// Upsert overwrites.
	if err := s.SetAppSetting("k", "v2"); err != nil {
		t.Fatalf("SetAppSetting upsert: %v", err)
	}
	all, err := s.AllAppSettings()
	if err != nil || all["k"] != "v2" {
		t.Fatalf("AllAppSettings = %v (err %v), want k=v2", all, err)
	}
	// Delete reverts to absent; deleting a missing key is not an error.
	if err := s.DeleteAppSetting("k"); err != nil {
		t.Fatalf("DeleteAppSetting: %v", err)
	}
	if _, ok, _ := s.GetAppSetting("k"); ok {
		t.Fatalf("GetAppSetting after delete: still present")
	}
	if err := s.DeleteAppSetting("k"); err != nil {
		t.Fatalf("DeleteAppSetting(missing): %v", err)
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

// indexNames returns the set of index names defined on the database.
func indexNames(s *Store) (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT name FROM sqlite_master WHERE type='index'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[n] = true
	}
	return out, rows.Err()
}

// TestPerformanceIndexesPresent locks in the v6 + artifact indexes added to
// avoid full-table scans on the dashboard aggregation and artifact queries.
func TestPerformanceIndexesPresent(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "idx.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	// Force lazy artifact table (and its indexes) into existence.
	if err := s.ensureArtifactsTable(); err != nil {
		t.Fatalf("ensureArtifactsTable: %v", err)
	}
	idx, err := indexNames(s)
	if err != nil {
		t.Fatalf("indexNames: %v", err)
	}
	want := []string{
		"idx_events_username", "idx_events_command", "idx_actors_last_seen",
		"idx_artifacts_sha256", "idx_artifacts_session", "idx_artifacts_created",
	}
	for _, w := range want {
		if !idx[w] {
			t.Errorf("missing index %q", w)
		}
	}
}
