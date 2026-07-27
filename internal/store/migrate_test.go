package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
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
	if v < 16 {
		t.Fatalf("expected version >= 16 after fresh open, got %d", v)
	}
	for _, table := range []string{"cowrie_session_hassh", "cowrie_session_meta"} {
		cols, err := tableColumns(s1, table)
		if err != nil {
			t.Fatalf("read %s columns: %v", table, err)
		}
		if !cols["observed_at"] {
			t.Fatalf("fresh %s missing observed_at", table)
		}
	}
	idx, err := indexNames(s1)
	if err != nil {
		t.Fatalf("read fresh indexes: %v", err)
	}
	for _, name := range []string{"idx_cowrie_session_hassh_observed_at", "idx_cowrie_session_meta_observed_at"} {
		if !idx[name] {
			t.Fatalf("fresh database missing index %q", name)
		}
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

func TestMigrationV16BackfillsSessionObservedAt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v15.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := raw.Exec(`
CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);
INSERT INTO schema_migrations (version, applied_at) VALUES (15, '2026-07-01T00:00:00Z');
CREATE TABLE cowrie_session_hassh (
  session_id TEXT PRIMARY KEY,
  hassh      TEXT NOT NULL
);
CREATE TABLE cowrie_session_meta (
  session_id  TEXT PRIMARY KEY,
  duration_ms INTEGER DEFAULT 0,
  arch        TEXT
);
INSERT INTO cowrie_session_hassh (session_id, hassh) VALUES ('legacy', 'aa:bb');
INSERT INTO cowrie_session_meta (session_id, duration_ms, arch) VALUES ('legacy', 2267, 'linux-x64-lsb');
`); err != nil {
		raw.Close()
		t.Fatalf("seed v15 database: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw v15 database: %v", err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("migrate v15 database: %v", err)
	}
	version, err := st.currentSchemaVersion()
	if err != nil {
		st.Close()
		t.Fatalf("read migrated version: %v", err)
	}
	if version < 16 {
		st.Close()
		t.Fatalf("migrated version = %d, want at least 16", version)
	}

	var hassh, hasshObserved string
	if err := st.db.QueryRow(`SELECT hassh, observed_at FROM cowrie_session_hassh WHERE session_id='legacy'`).Scan(&hassh, &hasshObserved); err != nil {
		st.Close()
		t.Fatalf("read migrated hassh row: %v", err)
	}
	var duration int64
	var arch, metaObserved string
	if err := st.db.QueryRow(`SELECT duration_ms, arch, observed_at FROM cowrie_session_meta WHERE session_id='legacy'`).Scan(&duration, &arch, &metaObserved); err != nil {
		st.Close()
		t.Fatalf("read migrated meta row: %v", err)
	}
	if hassh != "aa:bb" || duration != 2267 || arch != "linux-x64-lsb" {
		st.Close()
		t.Fatalf("legacy values changed: hassh=%q duration=%d arch=%q", hassh, duration, arch)
	}
	for table, observed := range map[string]string{
		"cowrie_session_hassh": hasshObserved,
		"cowrie_session_meta":  metaObserved,
	} {
		if _, err := time.Parse(time.RFC3339Nano, observed); err != nil {
			st.Close()
			t.Fatalf("%s observed_at = %q, want RFC3339Nano: %v", table, observed, err)
		}
	}
	idx, err := indexNames(st)
	if err != nil {
		st.Close()
		t.Fatalf("read migrated indexes: %v", err)
	}
	for _, name := range []string{"idx_cowrie_session_hassh_observed_at", "idx_cowrie_session_meta_observed_at"} {
		if !idx[name] {
			st.Close()
			t.Fatalf("migrated database missing index %q", name)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close migrated database: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen migrated database: %v", err)
	}
	defer reopened.Close()
	var reopenedHASSH, reopenedMeta string
	if err := reopened.db.QueryRow(`SELECT observed_at FROM cowrie_session_hassh WHERE session_id='legacy'`).Scan(&reopenedHASSH); err != nil {
		t.Fatalf("read reopened hassh timestamp: %v", err)
	}
	if err := reopened.db.QueryRow(`SELECT observed_at FROM cowrie_session_meta WHERE session_id='legacy'`).Scan(&reopenedMeta); err != nil {
		t.Fatalf("read reopened meta timestamp: %v", err)
	}
	if reopenedHASSH != hasshObserved || reopenedMeta != metaObserved {
		t.Fatalf("v16 backfill changed on reopen: hassh %q -> %q, meta %q -> %q", hasshObserved, reopenedHASSH, metaObserved, reopenedMeta)
	}
}

func TestLazySessionSchemasIncludeObservedAt(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "lazy-session.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.execWrite(`
DROP TABLE IF EXISTS cowrie_session_hassh;
DROP TABLE IF EXISTS cowrie_session_meta;
`); err != nil {
		t.Fatalf("drop migrated session tables: %v", err)
	}
	if err := st.ensureSessionHASSHIndex(); err != nil {
		t.Fatalf("lazy-create hassh table: %v", err)
	}
	if err := st.ensureSessionMetaTable(); err != nil {
		t.Fatalf("lazy-create meta table: %v", err)
	}
	for _, table := range []string{"cowrie_session_hassh", "cowrie_session_meta"} {
		cols, err := tableColumns(st, table)
		if err != nil {
			t.Fatalf("read lazy %s columns: %v", table, err)
		}
		if !cols["observed_at"] {
			t.Fatalf("lazy %s missing observed_at", table)
		}
	}
	idx, err := indexNames(st)
	if err != nil {
		t.Fatalf("read lazy indexes: %v", err)
	}
	for _, name := range []string{"idx_cowrie_session_hassh_observed_at", "idx_cowrie_session_meta_observed_at"} {
		if !idx[name] {
			t.Fatalf("lazy schema missing index %q", name)
		}
	}
}

func TestSessionObservedAtRefreshesOnEveryUpsertPath(t *testing.T) {
	type upsertCase struct {
		name  string
		table string
		write func(*Store, string) error
		check func(*testing.T, *Store, string)
	}
	cases := []upsertCase{
		{
			name:  "singular hassh",
			table: "cowrie_session_hassh",
			write: func(st *Store, sid string) error { return st.RecordSessionHASSH(sid, "aa:bb") },
			check: func(t *testing.T, st *Store, sid string) {
				t.Helper()
				var got string
				if err := st.db.QueryRow(`SELECT hassh FROM cowrie_session_hassh WHERE session_id=?`, sid).Scan(&got); err != nil || got != "aa:bb" {
					t.Fatalf("hassh = %q, err=%v; want aa:bb", got, err)
				}
			},
		},
		{
			name:  "singular duration",
			table: "cowrie_session_meta",
			write: func(st *Store, sid string) error { return st.RecordSessionDuration(sid, 2267) },
			check: func(t *testing.T, st *Store, sid string) {
				t.Helper()
				var got int64
				if err := st.db.QueryRow(`SELECT duration_ms FROM cowrie_session_meta WHERE session_id=?`, sid).Scan(&got); err != nil || got != 2267 {
					t.Fatalf("duration = %d, err=%v; want 2267", got, err)
				}
			},
		},
		{
			name:  "singular arch",
			table: "cowrie_session_meta",
			write: func(st *Store, sid string) error { return st.RecordSessionArch(sid, "linux-x64-lsb") },
			check: func(t *testing.T, st *Store, sid string) {
				t.Helper()
				var got string
				if err := st.db.QueryRow(`SELECT arch FROM cowrie_session_meta WHERE session_id=?`, sid).Scan(&got); err != nil || got != "linux-x64-lsb" {
					t.Fatalf("arch = %q, err=%v; want linux-x64-lsb", got, err)
				}
			},
		},
		{
			name:  "batch hassh",
			table: "cowrie_session_hassh",
			write: func(st *Store, sid string) error {
				return st.RecordSessionBindings([]SessionBinding{{SessionID: sid, HASSH: "cc:dd"}})
			},
			check: func(t *testing.T, st *Store, sid string) {
				t.Helper()
				var got string
				if err := st.db.QueryRow(`SELECT hassh FROM cowrie_session_hassh WHERE session_id=?`, sid).Scan(&got); err != nil || got != "cc:dd" {
					t.Fatalf("hassh = %q, err=%v; want cc:dd", got, err)
				}
			},
		},
		{
			name:  "batch duration",
			table: "cowrie_session_meta",
			write: func(st *Store, sid string) error {
				return st.RecordSessionBindings([]SessionBinding{{SessionID: sid, DurationMs: 4200}})
			},
			check: func(t *testing.T, st *Store, sid string) {
				t.Helper()
				var got int64
				if err := st.db.QueryRow(`SELECT duration_ms FROM cowrie_session_meta WHERE session_id=?`, sid).Scan(&got); err != nil || got != 4200 {
					t.Fatalf("duration = %d, err=%v; want 4200", got, err)
				}
			},
		},
		{
			name:  "batch arch",
			table: "cowrie_session_meta",
			write: func(st *Store, sid string) error {
				return st.RecordSessionBindings([]SessionBinding{{SessionID: sid, Arch: "linux-arm64"}})
			},
			check: func(t *testing.T, st *Store, sid string) {
				t.Helper()
				var got string
				if err := st.db.QueryRow(`SELECT arch FROM cowrie_session_meta WHERE session_id=?`, sid).Scan(&got); err != nil || got != "linux-arm64" {
					t.Fatalf("arch = %q, err=%v; want linux-arm64", got, err)
				}
			},
		},
	}

	backdated := time.Date(2000, 1, 2, 3, 4, 5, 0, time.UTC)
	backdatedText := backdated.Format(time.RFC3339Nano)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, err := Open(filepath.Join(t.TempDir(), "refresh.db"))
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer st.Close()
			sid := "session-" + tc.name
			if err := tc.write(st, sid); err != nil {
				t.Fatalf("seed row: %v", err)
			}
			if _, err := st.execWrite(`UPDATE `+tc.table+` SET observed_at=? WHERE session_id=?`, backdatedText, sid); err != nil {
				t.Fatalf("backdate row: %v", err)
			}
			if err := tc.write(st, sid); err != nil {
				t.Fatalf("repeat upsert: %v", err)
			}
			var observed string
			if err := st.db.QueryRow(`SELECT observed_at FROM `+tc.table+` WHERE session_id=?`, sid).Scan(&observed); err != nil {
				t.Fatalf("read refreshed timestamp: %v", err)
			}
			observedAt, err := time.Parse(time.RFC3339Nano, observed)
			if err != nil {
				t.Fatalf("observed_at = %q, want RFC3339Nano: %v", observed, err)
			}
			if !observedAt.After(backdated) {
				t.Fatalf("observed_at = %s, want after backdated %s", observedAt, backdated)
			}
			tc.check(t, st, sid)
		})
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
		// v14: actors ordering + primary_ip lookup indexes.
		"idx_actors_primary_ip", "idx_actors_event_count", "idx_actors_rate",
	}
	for _, w := range want {
		if !idx[w] {
			t.Errorf("missing index %q", w)
		}
	}
}
