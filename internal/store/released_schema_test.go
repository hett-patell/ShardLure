package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// releasedSchemas are the sqlite_master dumps of databases created by shipped
// builds (testdata/*.sql, each dumped from that build's own store.Open). Every
// store test otherwise creates a fresh database, so an amendment to an
// already-shipped DDL constant is invisible to go test: the campaigns rc1
// shipped schema v25 to production, and the carry table later appended to the
// v25 DDL was never created there (C1 of the fix-all review). These tests open
// each released shape with the current binary and demand the latest schema.
var releasedSchemas = []struct {
	file    string
	version int
}{
	{"schema-v24-v2.8.0.sql", 24},
	{"schema-v25-campaigns-rc1.sql", 25},
}

// buildReleasedDB creates a database file with exactly the released schema:
// the fixture's DDL and its schema_migrations rows, nothing from the current
// binary.
func buildReleasedDB(t *testing.T, fixture, path string) {
	t.Helper()
	script, err := os.ReadFile(filepath.Join("testdata", fixture))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, stmt := range splitSQLStatements(string(script)) {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("%s: %v\n%s", fixture, err, stmt)
		}
	}
}

// splitSQLStatements splits the fixture on statement-terminating semicolons at
// line ends. The dumps carry SQL comments inside CREATE TABLE bodies, so the
// split is on ";\n" only, never on every ";".
func splitSQLStatements(script string) []string {
	var out []string
	for _, part := range strings.Split(script, ";\n") {
		var keep []string
		for _, line := range strings.Split(part, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "--") && !strings.Contains(line, "CREATE") {
				continue
			}
			keep = append(keep, line)
		}
		stmt := strings.TrimSpace(strings.Join(keep, "\n"))
		if stmt != "" {
			out = append(out, stmt)
		}
	}
	return out
}

// schemaObjects lists (type, name) of every application table and index, and
// the column names of every table, as the current binary sees them.
func schemaObjects(t *testing.T, db *sql.DB) (map[string]bool, map[string]map[string]bool) {
	t.Helper()
	objects := map[string]bool{}
	columns := map[string]map[string]bool{}
	rows, err := db.Query(`SELECT type, name FROM sqlite_master WHERE type IN ('table','index','trigger') AND name NOT LIKE 'sqlite_%' ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var typ, name string
		if err := rows.Scan(&typ, &name); err != nil {
			t.Fatal(err)
		}
		objects[typ+" "+name] = true
		if typ == "table" {
			tables = append(tables, name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		cols, err := db.Query(`PRAGMA table_info(` + table + `)`)
		if err != nil {
			t.Fatal(err)
		}
		columns[table] = map[string]bool{}
		for cols.Next() {
			var cid, notnull, pk int
			var name, ctype string
			var dflt sql.NullString
			if err := cols.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
				cols.Close()
				t.Fatal(err)
			}
			columns[table][name] = true
		}
		cols.Close()
	}
	return objects, columns
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestReleasedSchemasMigrateToLatest opens each shipped schema with the current
// store and checks the result has every table, index, trigger and column a
// fresh database has, stamped at the latest version.
func TestReleasedSchemasMigrateToLatest(t *testing.T) {
	fresh := newTestStore(t, "fresh.db")
	wantObjects, wantColumns := schemaObjects(t, fresh.db)
	var latest int
	if err := fresh.db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&latest); err != nil {
		t.Fatal(err)
	}
	if latest != latestSnapshotSchema {
		t.Fatalf("fresh database is at schema %d, snapshot code expects %d", latest, latestSnapshotSchema)
	}
	for _, rel := range releasedSchemas {
		t.Run(rel.file, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "released.db")
			buildReleasedDB(t, rel.file, path)
			st, err := Open(path)
			if err != nil {
				t.Fatalf("open released v%d: %v", rel.version, err)
			}
			defer st.Close()
			var got int
			if err := st.db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&got); err != nil || got != latest {
				t.Fatalf("migrated to schema %d (%v), want %d", got, err, latest)
			}
			gotObjects, gotColumns := schemaObjects(t, st.db)
			for _, obj := range sortedKeys(wantObjects) {
				if !gotObjects[obj] {
					t.Errorf("released v%d migrated: missing %s", rel.version, obj)
				}
			}
			tables := make([]string, 0, len(wantColumns))
			for table := range wantColumns {
				tables = append(tables, table)
			}
			sort.Strings(tables)
			for _, table := range tables {
				if gotColumns[table] == nil {
					continue // reported above
				}
				for _, col := range sortedKeys(wantColumns[table]) {
					if !gotColumns[table][col] {
						t.Errorf("released v%d migrated: table %s missing column %s", rel.version, table, col)
					}
				}
			}
		})
	}
}

// TestReleasedV25FirstWorkerTick is the production upgrade in miniature: the
// rc1 database holds settled scripts and a recorder cursor, and the current
// binary's first campaign tick must run its store calls through (the version
// reset first, which snapshots the old fingerprints into script_version_carry,
// a table rc1 never created). Before the v26 rung created it, this failed with
// "no such table: script_version_carry" and the worker was dead from its first
// tick.
func TestReleasedV25FirstWorkerTick(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rc1.db")
	buildReleasedDB(t, "schema-v25-campaigns-rc1.sql", path)
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	stamp := "2026-09-20T10:00:00.000000000Z"
	seed := []string{
		`INSERT INTO events(ts,ts_unix_ns,source,kind,session_id,src_ip,command,actor_id) VALUES('` + stamp + `',1758362400000000000,'cowrie','command','s1','198.51.100.7','uname -a; cat /proc/cpuinfo','cowrie:h1')`,
		`INSERT INTO session_script_lines(session_id,event_id,line) VALUES('s1',1,'uname|-a')`,
		`INSERT INTO session_scripts(session_id,actor_id,src_ip,line_count,bytes,first_seen,last_seen,updated_at,settled_at,fingerprint)
VALUES('s1','cowrie:h1','198.51.100.7',1,8,'` + stamp + `','` + stamp + `','` + stamp + `','` + stamp + `','` + strings.Repeat("a", 64) + `')`,
		`INSERT INTO scripts(fingerprint,normalized,display,command_count,distinctive,first_seen,last_seen) VALUES('` + strings.Repeat("a", 64) + `','uname|-a','uname -a',1,0,'` + stamp + `','` + stamp + `')`,
		`INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES('campaign','evidence-v1',0,1,'','` + stamp + `')`,
	}
	for _, q := range seed {
		if _, err := raw.Exec(q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	raw.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	reset, err := st.ResetScriptsForVersion(ctx, 3)
	if err != nil {
		t.Fatalf("first tick's version reset on the rc1 database: %v", err)
	}
	if !reset {
		t.Fatal("rc1 rows carried no version: the reset must rebuild them")
	}
	var carried int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM script_version_carry`).Scan(&carried); err != nil || carried != 1 {
		t.Fatalf("carry snapshot = %d, %v; want the settled rc1 session", carried, err)
	}
	if held, err := st.ScriptRebuildHold(ctx, time.Now()); err != nil || !held {
		t.Fatalf("hold after reset = %v, %v; want held", held, err)
	}
	res, err := st.RecordCampaignEvidence(ctx, 5000)
	if err != nil || !res.Done {
		t.Fatalf("record = %+v, %v", res, err)
	}
	if _, err := st.SettleSessionScripts(ctx, time.Now().Add(time.Hour), 2000); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if _, err := st.AssignScriptFamilies(ctx, 500); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if err := st.PruneOrphanScripts(ctx); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if _, err := st.ListScriptFamilies(ctx, 50); err != nil {
		t.Fatalf("list families: %v", err)
	}
	if _, err := st.ListCampaigns(ctx, 50); err != nil {
		t.Fatalf("list campaigns: %v", err)
	}
	status, err := st.ScriptRebuildHoldStatus(ctx)
	if err != nil || !status.Held {
		t.Fatalf("hold status = %+v, %v", status, err)
	}
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM session_scripts WHERE fingerprint<>''`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("re-settled sessions = %d, %v; want 1", n, err)
	}
}
