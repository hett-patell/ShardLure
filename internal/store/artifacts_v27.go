package store

import (
	"database/sql"
	"strings"
)

// v27 (payload yield Phase C): one URL may own several artifact rows, one per
// distinct payload it served, so a re-fetch that finds a rotated binary keeps
// both. UNIQUE(url) lived in the table definition, so the rung rebuilds the
// table; (url, fetch_epoch) is the new key. Epoch 0 is the first-sight row:
// it alone carries the capture retry state, and every URL-keyed statement
// targets it (fetch_epoch=0). Rotated payloads are inserted with the next
// epoch, already terminal. parent_sha256/depth record second-stage URLs
// harvested from a fetched script (depth 0 = seen in a command or by Cowrie).
//
// INSERT OR IGNORE writers that omit fetch_epoch get the default 0, so the
// (url, fetch_epoch) unique index keeps deduplicating first sightings exactly
// as UNIQUE(url) did.
const artifactsV27Table = `CREATE TABLE artifacts_v27 (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  src_ip TEXT,
  session_id TEXT,
  actor_id TEXT,
  url TEXT NOT NULL,
  local_path TEXT,
  sha256 TEXT,
  size_bytes INTEGER DEFAULT 0,
  origin TEXT NOT NULL,
  status TEXT NOT NULL,
  detail TEXT,
  created_at TEXT NOT NULL,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT,
  first_observed_at TEXT,
  last_seen_at TEXT,
  last_fetch_attempt_at TEXT,
  last_successful_fetch_at TEXT,
  lease_until TEXT,
  fetch_epoch INTEGER NOT NULL DEFAULT 0,
  parent_sha256 TEXT,
  depth INTEGER NOT NULL DEFAULT 0
)`

// artifactsTableDDL is the same shape under the real name, for
// ensureArtifactsTable. The ladder normally creates the table (v17) and
// rebuilds it (v27) first, so this only ever runs as a no-op guard.
var artifactsTableDDL = mustRenameDDL(artifactsV27Table, "CREATE TABLE artifacts_v27", "CREATE TABLE IF NOT EXISTS artifacts")

// mustRenameDDL panics at package init when the prefix is absent. A silent
// no-op Replace would leave ensureArtifactsTable running
// "CREATE TABLE artifacts_v27" (no IF NOT EXISTS) the moment someone rewords
// artifactsV27Table; failing every test binary is the loud alternative.
func mustRenameDDL(ddl, from, to string) string {
	if !strings.HasPrefix(ddl, from+" (") {
		panic("store: artifacts DDL does not start with " + from)
	}
	return to + strings.TrimPrefix(ddl, from)
}

const artifactsV27Columns = `id,ts,src_ip,session_id,actor_id,url,local_path,sha256,size_bytes,origin,status,detail,created_at,attempt_count,next_attempt_at,first_observed_at,last_seen_at,last_fetch_attempt_at,last_successful_fetch_at,lease_until`

// The schedule for re-fetching a quarantine URL that has served a payload:
// hourly for 24 h after first sighting, every 6 h to day 7, daily once
// offline (6 consecutive failures), never after day 10 (MalwareBazaar's
// freshness window). One row per URL; the worker leases it like a capture.
const refetchScheduleTable = `CREATE TABLE IF NOT EXISTS refetch_schedule (
  url TEXT PRIMARY KEY,
  first_seen_at TEXT NOT NULL,
  next_check_at TEXT NOT NULL,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL CHECK (state IN ('active','offline','done')),
  checks INTEGER NOT NULL DEFAULT 0,
  last_sha256 TEXT,
  last_check_at TEXT,
  lease_until TEXT
)`

const artifactsURLEpochIndex = `CREATE UNIQUE INDEX IF NOT EXISTS idx_artifacts_url_epoch ON artifacts(url, fetch_epoch)`

// artifactsLazyIndexes are the indexes ensureArtifactsTable owns. One
// spelling, shared by it and the v27 rung, so fresh and migrated databases
// carry identical index SQL (released_schema_test compares sqlite_master).
var artifactsLazyIndexes = []string{
	`CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256)`,
	`CREATE INDEX IF NOT EXISTS idx_artifacts_session ON artifacts(session_id)`,
	`CREATE INDEX IF NOT EXISTS idx_artifacts_created ON artifacts(created_at)`,
}

func artifactsV27Indexes() []string {
	out := []string{
		artifactsURLEpochIndex,
		// Same DDL as the v17 rung; DROP TABLE removed it.
		`CREATE INDEX IF NOT EXISTS idx_artifacts_capture_due ON artifacts(origin, status, next_attempt_at)`,
	}
	// The lazy indexes ensureArtifactsTable creates; DROP TABLE removed them.
	out = append(out, artifactsLazyIndexes...)
	return append(out, `CREATE INDEX IF NOT EXISTS idx_refetch_due ON refetch_schedule(state, next_check_at)`)
}

// migrateArtifactsV27 rebuilds artifacts without UNIQUE(url), keeping every
// row with its id. AUTOINCREMENT's high-water mark is carried over
// explicitly: copying explicit ids only advances the new table's sequence
// to MAX(id), and the old sequence may be higher (deleted newest rows), so
// without the carry a purged id could be handed out again.
//
// The rung is safe to re-run: a database stamped below 27 whose artifacts
// table already has fetch_epoch (a v27 build's output with the stamp removed,
// as the intermediate-v26 tests construct) skips the rebuild. Copying only the
// 20 pre-v27 columns would otherwise drop fetch_epoch/parent_sha256/depth and,
// with two epochs of one URL, fail on the new unique key so Open refuses.
// refetch_schedule and the indexes are still asserted (IF NOT EXISTS).
func migrateArtifactsV27(tx *sql.Tx, now string) error {
	rebuilt, err := columnExistsIn(tx, "artifacts", "fetch_epoch")
	if err != nil {
		return err
	}
	if rebuilt {
		for _, q := range append([]string{refetchScheduleTable}, artifactsV27Indexes()...) {
			if _, err := tx.Exec(q); err != nil {
				return err
			}
		}
		_, err := tx.Exec(`INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(27,?)`, now)
		return err
	}
	var oldSeq int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(seq),0) FROM sqlite_sequence WHERE name='artifacts'`).Scan(&oldSeq); err != nil {
		return err
	}
	stmts := []string{
		`DROP TABLE IF EXISTS artifacts_v27`,
		artifactsV27Table,
		`INSERT INTO artifacts_v27(` + artifactsV27Columns + `) SELECT ` + artifactsV27Columns + ` FROM artifacts`,
		// A view or trigger on artifacts makes the DROP/RENAME fail (the
		// transaction rolls back and Open refuses); acceptable, ShardLure creates none.
		`DROP TABLE artifacts`,
		`ALTER TABLE artifacts_v27 RENAME TO artifacts`,
		refetchScheduleTable,
	}
	stmts = append(stmts, artifactsV27Indexes()...)
	for _, q := range stmts {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	var newSeq int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(seq),0) FROM sqlite_sequence WHERE name='artifacts'`).Scan(&newSeq); err != nil {
		return err
	}
	if oldSeq > newSeq {
		if _, err := tx.Exec(`DELETE FROM sqlite_sequence WHERE name='artifacts'`); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO sqlite_sequence(name,seq) VALUES('artifacts',?)`, oldSeq); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(27,?)`, now)
	return err
}
