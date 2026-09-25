package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
	_ "modernc.org/sqlite"
)

type Store struct {
	observerMu     sync.RWMutex
	ingestObserver func(models.Source, int, error)
	db             *sql.DB
	path           string // canonical database name; never a retention target
	// writeMu serializes WRITES at the application layer. SQLite allows only
	// one writer, and live mode has several writer goroutines (journal tail,
	// cowrie ticker, retention purge) plus the web server sharing this db; with
	// the default pool they'd race the write lock and the loser would hit a
	// busy_timeout error that callers only log-and-continue (a silently dropped
	// batch). Serializing writes here avoids that WITHOUT capping the pool to a
	// single connection — so concurrent READS still run in parallel under WAL
	// (a 1-connection pool would make a slow analytics query block ingest).
	writeMu       sync.Mutex
	captureMu     sync.Mutex
	capturePolicy CaptureRetentionPolicy

	// Lazy-table creation guards. The artifacts / enrichment / bazaar / tty
	// tables are created on first use (CREATE TABLE IF NOT EXISTS), but the
	// ensure* helpers were called on EVERY read and write — each running a DDL
	// statement under writeMu, adding pointless lock contention on hot paths.
	// A sync.Once per table runs the DDL exactly once; subsequent calls are a
	// cheap atomic check with no lock.
	onceArtifacts    sync.Once
	onceEnrich       sync.Once
	onceBazaar       sync.Once
	onceTTY          sync.Once
	onceSessHASSH    sync.Once
	onceSessMeta     sync.Once
	onceAbuseReport  sync.Once
	onceURLhaus      sync.Once
	onceThreatFox    sync.Once
	oncePayloadIntel sync.Once
	onceFileCapture  sync.Once
	// errs from the once-bodies, so a failed creation still surfaces.
	errArtifacts    error
	errEnrich       error
	errBazaar       error
	errTTY          error
	errSessHASSH    error
	errSessMeta     error
	errAbuseReport  error
	errURLhaus      error
	errThreatFox    error
	errPayloadIntel error
	errFileCapture  error
}

type sqlExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

type sqlRowExecer interface {
	sqlExecer
	QueryRow(query string, args ...any) *sql.Row
}

type sqlQueryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

func Open(path string) (*Store, error) {
	return openWithOwnerCheck(path, CheckDatabaseOwner)
}

func openWithOwnerCheck(path string, checkOwner func(string) error) (*Store, error) {
	if err := checkOwner(path); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrDatabaseUnsafe
	}
	path = abs
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, ErrDatabaseAccess
	}
	if err := checkOwner(path); err != nil {
		return nil, err
	}
	dsn, err := sqliteFileURI(path, url.Values{"_pragma": []string{"journal_mode(WAL)", "busy_timeout(5000)"}})
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Allow a few connections so WAL readers run concurrently with the single
	// writer (writes are serialized by writeMu, not by the pool size). A 1-conn
	// pool would throw away WAL's reader/writer concurrency and let one slow
	// dashboard query stall live ingest.
	db.SetMaxOpenConns(8)
	// Keep idle connections warm. The default MaxIdleConns of 2 let the pool
	// churn open/close under the mixed read/write load (journal tail + cowrie
	// ticker + several dashboard readers), so keep enough idle to cover the
	// concurrent readers. ConnMaxLifetime bounds a single long-lived conn's
	// staleness without forcing constant reconnects.
	db.SetMaxIdleConns(8)
	db.SetConnMaxLifetime(time.Hour)
	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	// This schema is heavily index-plan-dependent (see the migration ladder and
	// the ts-IN-not-source workaround in events_dedup.go). Without stats the
	// planner works off defaults and can pick a full scan over an index; run
	// optimize once after migrate so those documented plans hold on an existing
	// DB. Cheap on a fresh DB (nothing to analyze), best-effort — a planner-hint
	// failure must never block startup.
	if _, err := db.Exec(`PRAGMA optimize`); err != nil {
		// non-fatal: stale stats degrade plans, they don't break correctness
		_ = err
	}
	// Honeypot DBs can contain attacker-supplied passwords; restrict to owner.
	if err := checkOwner(path); err != nil {
		db.Close()
		return nil, err
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Stat(p); err == nil {
			if err := os.Chmod(p, 0o600); err != nil {
				db.Close()
				return nil, ErrDatabaseAccess
			}
		} else if !os.IsNotExist(err) {
			db.Close()
			return nil, ErrDatabaseAccess
		}
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// execWrite runs a write statement under the write mutex, so all writes are
// serialized (SQLite's single-writer model) while reads stay concurrent.
func (s *Store) execWrite(query string, args ...any) (sql.Result, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.db.Exec(query, args...)
}

func (s *Store) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  -- Fixed-width RFC3339 UTC text plus exact epoch nanoseconds. ts remains for
  -- compatibility/export; ts_unix_ns drives chronological v20+ reads.
  ts TEXT NOT NULL,
  ts_unix_ns INTEGER,
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  src_ip TEXT,
  src_port INTEGER DEFAULT 0,
  username TEXT,
  -- Honeypot passwords are attacker-supplied telemetry and can still be sensitive.
  password TEXT,
  session_id TEXT,
  hassh TEXT,
  ssh_client TEXT,
  command TEXT,
  sha256 TEXT,
  filename TEXT,
  dst_ip TEXT,
  dst_port INTEGER DEFAULT 0,
  raw TEXT,
  actor_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);
-- Indexes on columns added by the legacy-column backfill are created
-- *after* ensureLegacyColumns runs (see migrate()). Putting them here
-- would fail on databases that predate those columns.

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actors (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  primary_ip TEXT,
  playbook TEXT,
  intent TEXT,
  confidence INTEGER,
  first_seen TEXT,
  last_seen TEXT,
  event_count INTEGER,
  unique_users INTEGER,
  attempts_per_hour REAL,
  hassh TEXT,
  ssh_client TEXT,
  username_hash TEXT,
  campaigns TEXT,
  probe_score INTEGER,
  notes TEXT
);

CREATE TABLE IF NOT EXISTS actor_ips (
  actor_id TEXT,
  ip TEXT,
  first_seen TEXT,
  last_seen TEXT,
  count INTEGER,
  PRIMARY KEY (actor_id, ip)
);

CREATE TABLE IF NOT EXISTS actor_users (
  actor_id TEXT,
  username TEXT,
  count INTEGER,
  PRIMARY KEY (actor_id, username)
);

CREATE TABLE IF NOT EXISTS ingest_state (
  source TEXT NOT NULL,
  path TEXT NOT NULL,
  inode INTEGER NOT NULL DEFAULT 0,
  offset INTEGER NOT NULL DEFAULT 0,
  -- head_sig fingerprints the file's first bytes to detect copytruncate-style
  -- in-place rotation (same inode, replaced content) and reset the offset.
  head_sig TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (source, path)
);

CREATE TABLE IF NOT EXISTS app_settings (
  -- Operator-editable runtime key/value store backing the dashboard Settings
  -- panel (API keys, AbuseIPDB reporting knobs, geo/home). Values are plaintext
  -- in an already-0600 DB; see internal/store/app_settings.go for the rationale.
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cowrie_session_hassh (
  session_id  TEXT PRIMARY KEY,
  hassh       TEXT NOT NULL,
  observed_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS cowrie_session_meta (
  session_id  TEXT PRIMARY KEY,
  duration_ms INTEGER DEFAULT 0,
  arch        TEXT,
  observed_at TEXT NOT NULL DEFAULT ''
);
`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	// Drop the historical raw-column index; it was high-cost and unused.
	if _, err := s.db.Exec(`DROP INDEX IF EXISTS idx_events_raw`); err != nil {
		return err
	}

	// Migration ladder. Each step runs at most once per database
	// lifetime - we check the recorded max version before executing
	// it, then stamp the new version on success. Open() therefore
	// becomes a cheap no-op on already-migrated stores instead of
	// re-scanning PRAGMA table_info every startup.
	current, err := s.currentSchemaVersion()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)

	// v1: base schema marker. Legacy installs may already have this.
	if current < 1 {
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (1, ?)`, now); err != nil {
			return err
		}
	}

	// v2: backfill columns added after the initial release. Fresh
	// installs hit this with the base CREATE TABLE already containing
	// every column, so ensureLegacyColumns is a no-op for them and
	// only does meaningful work on databases predating those columns.
	// Either way we record v2 so subsequent Opens skip the PRAGMA
	// table_info scan entirely.
	if current < 2 {
		if err := s.ensureLegacyColumns(); err != nil {
			return err
		}
		// Create indexes that touch backfilled columns now that the
		// columns are guaranteed to exist on this database.
		// (idx_events_identity — a 7-column covering index — used to be
		// created here too; v9 drops it, so fresh installs skip it.)
		if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor_id)`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (2, ?)`, now); err != nil {
			return err
		}
	}

	// v3: scrub the Command column on cowrie events that aren't shell
	// input or file download. Earlier versions of the cowrie ingest
	// fell back to r.Message when r.Input was empty, which pushed
	// banner strings ("Remote SSH version: ...") and login-attempt
	// summaries into the command column and poisoned the Top
	// Commands widget. This is a one-shot fix-up of already-persisted
	// rows; live ingest now refuses to set the column for those
	// event kinds at all.
	if current < 3 {
		// Set the column to the empty string rather than NULL: the
		// rest of the codebase scans events.command into a Go
		// string, and modernc.org/sqlite refuses to coerce NULL
		// into a non-nullable scan target. Empty string filters the
		// same way for Top Commands and IOC harvest while staying
		// compatible with existing scan sites.
		if _, err := s.db.Exec(`
UPDATE events
SET command = ''
WHERE source = 'cowrie'
  AND command IS NOT NULL
  AND command != ''
  AND kind NOT IN ('command', 'file_upload', 'file_download')
`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (3, ?)`, now); err != nil {
			return err
		}
	}

	// v4: index additions that were overlooked in earlier schema
	// revisions — session_id-leading index for SessionEvents /
	// shell-session lookups and a standalone ip index for the
	// actor_ips table (the compound PK starts with actor_id, which
	// cannot serve reverse lookups keyed only by IP).
	if current < 4 {
		const v4Idx = `
CREATE INDEX IF NOT EXISTS idx_events_session ON events(source, session_id, ts);
CREATE INDEX IF NOT EXISTS idx_actor_ips_ip ON actor_ips(ip);
`
		if _, err := s.db.Exec(v4Idx); err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (4, ?)`, now); err != nil {
			return err
		}
	}

	// v5: bazaar_uploads. Tracks which captured artifacts have been
	// submitted to abuse.ch/MalwareBazaar. sha256 is the natural key
	// because that's what MalwareBazaar dedupes on server-side; we
	// store it as the primary key so re-submission is a no-op on the
	// client too. uploaded_at lets us answer "what did we ship this
	// week" without re-querying the API. response_status carries the
	// abuse.ch query_status (e.g. "inserted", "file_already_known").
	// uploaded_at uses the same RFC3339 TEXT format as every other
	// timestamp column in this schema so dashboard queries can join
	// on it without coercion.
	if current < 5 {
		const v5Schema = `
CREATE TABLE IF NOT EXISTS bazaar_uploads (
  sha256          TEXT PRIMARY KEY,
  uploaded_at     TEXT NOT NULL,
  response_status TEXT NOT NULL,
  mb_url          TEXT
);
CREATE INDEX IF NOT EXISTS idx_bazaar_uploads_ts ON bazaar_uploads(uploaded_at);
`
		if _, err := s.db.Exec(v5Schema); err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (5, ?)`, now); err != nil {
			return err
		}
	}

	// v6: indexes for dashboard aggregation queries that previously
	// full-scanned the events/actors tables on every render:
	//   - TopUsernames GROUP BY username  -> idx_events_username
	//   - TopCommands  GROUP BY command   -> idx_events_command
	//   - ListActors / actor retention ORDER BY last_seen -> idx_actors_last_seen
	// (TopSourceIPs already had idx_events_ip.) These touch tables created
	// in the base schema, so they belong in the migration ladder; the
	// artifacts indexes live in ensureArtifactsTable since that table is
	// created lazily.
	if current < 6 {
		const v6Idx = `
CREATE INDEX IF NOT EXISTS idx_events_username ON events(username);
CREATE INDEX IF NOT EXISTS idx_events_command ON events(command);
CREATE INDEX IF NOT EXISTS idx_actors_last_seen ON actors(last_seen);
`
		if _, err := s.db.Exec(v6Idx); err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (6, ?)`, now); err != nil {
			return err
		}
	}

	// v7: (kind, ts) composite index. The capture runner calls
	// RecentCommandEvents and RecentFileDownloadEvents on every 5s tick; both
	// filter `WHERE kind=? ORDER BY ts DESC`. With no kind-leading index SQLite
	// scanned the whole table down idx_events_ts until it found enough matches
	// — on a brute-force-dominated honeypot those kinds are rare, so it was a
	// full scan twice per tick. This index makes them indexed range searches.
	if current < 7 {
		if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_kind_ts ON events(kind, ts)`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (7, ?)`, now); err != nil {
			return err
		}
	}

	// v8: add ingest_state.head_sig (copytruncate detection). A fresh DB already
	// has the column from the CREATE TABLE above, so guard the ALTER on a
	// PRAGMA check to stay idempotent — ADD COLUMN errors if it exists.
	if current < 8 {
		has, err := s.columnExists("ingest_state", "head_sig")
		if err != nil {
			return err
		}
		if !has {
			if _, err := s.db.Exec(`ALTER TABLE ingest_state ADD COLUMN head_sig TEXT`); err != nil {
				return err
			}
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (8, ?)`, now); err != nil {
			return err
		}
	}

	// v9: drop idx_events_identity. The 7-column covering index (including
	// the attacker-controlled username/command columns) had exactly one
	// designed reader — Store.EventExists — which was replaced by the
	// batched ts-IN dedup and then removed. Both dedup paths deliberately
	// avoid the index (its source= prefix triggers a full-source scan;
	// see batchDedupCowrie), so the only thing it did was amplify every
	// event INSERT, the hottest write in the system.
	if current < 9 {
		if _, err := s.db.Exec(`DROP INDEX IF EXISTS idx_events_identity`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (9, ?)`, now); err != nil {
			return err
		}
	}

	// v10: replace the single-column idx_events_actor with a composite
	// (actor_id, ts). IterateEventsByActorIDs runs `WHERE actor_id IN (...)
	// ORDER BY ts ASC` on every 5s live tick; with the single-column index
	// SQLite re-sorted each touched actor's FULL history through a temp
	// B-tree per tick (verified via EXPLAIN QUERY PLAN). The composite
	// serves rows pre-sorted, and turns LastCommandByActor's LIMIT 1 into
	// a backwards index walk instead of a sort-everything.
	if current < 10 {
		if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_actor_ts ON events(actor_id, ts)`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`DROP INDEX IF EXISTS idx_events_actor`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (10, ?)`, now); err != nil {
			return err
		}
	}

	// v11: dst_ip/dst_port on events — the forwarding destination on cowrie
	// direct-tcpip (proxy/pivot) events. Fresh DBs already have them from the
	// base CREATE TABLE; guard each ADD COLUMN on a PRAGMA check so it's
	// idempotent (ADD COLUMN errors if the column exists).
	if current < 11 {
		for _, c := range []struct{ name, ddl string }{
			{"dst_ip", `ALTER TABLE events ADD COLUMN dst_ip TEXT`},
			{"dst_port", `ALTER TABLE events ADD COLUMN dst_port INTEGER DEFAULT 0`},
		} {
			has, err := s.columnExists("events", c.name)
			if err != nil {
				return err
			}
			if !has {
				if _, err := s.db.Exec(c.ddl); err != nil {
					return err
				}
			}
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (11, ?)`, now); err != nil {
			return err
		}
	}

	// v12: abuseipdb_reports — the dedup/audit ledger for outbound AbuseIPDB
	// reporting (identity-shaped, NOT purged by MaintenancePurge). Also created
	// lazily via ensureAbuseReportsTable for hot DBs where this write contends;
	// creating it here keeps a freshly-migrated DB consistent with the ladder.
	if current < 12 {
		if _, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS abuseipdb_reports (
  ip          TEXT PRIMARY KEY,
  reported_at TEXT NOT NULL,
  status      TEXT NOT NULL,
  categories  TEXT,
  abuse_score INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_abuseipdb_reports_ts ON abuseipdb_reports(reported_at);`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (12, ?)`, now); err != nil {
			return err
		}
	}

	// v13: app_settings — operator-editable runtime key/value store backing the
	// dashboard Settings panel (API keys, AbuseIPDB reporting knobs, geo/home).
	// Plaintext values in an already-0600 DB; see internal/store/app_settings.go.
	// Fresh DBs already have it from the base CREATE TABLE block above.
	if current < 13 {
		if _, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS app_settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL
);`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (13, ?)`, now); err != nil {
			return err
		}
	}

	// v14: actors indexes for the hot dashboard/intel orderings and the
	// primary_ip lookups. Before this, actors had only idx_actors_last_seen, so
	// TopActorsByEvents (ORDER BY event_count), TopActorsByRate (ORDER BY
	// attempts_per_hour), and GetActorByPrimaryIP/GetReportableActorByIP
	// (WHERE primary_ip=?) each did a full table scan + transient sort on every
	// 5s poll — and report-all calls the primary_ip lookup in a loop over up to
	// 1000 actors. On a busy honeypot the actors table can reach 10^5+ rows.
	if current < 14 {
		if _, err := s.db.Exec(`
CREATE INDEX IF NOT EXISTS idx_actors_primary_ip ON actors(primary_ip);
CREATE INDEX IF NOT EXISTS idx_actors_event_count ON actors(event_count);
CREATE INDEX IF NOT EXISTS idx_actors_rate ON actors(attempts_per_hour);`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (14, ?)`, now); err != nil {
			return err
		}
	}

	// v15: index events(sha256) for the bazaar sharing panel. Its upload list
	// (polled at limit=1000 every 30s) backfills each sample's source IP from
	// events matched by sha256; without this index that subquery full-scanned
	// the whole events table on every poll (the same per-poll-GROUP-BY cost the
	// v14/0ccb048 work removed elsewhere). Partial index keeps it small: only
	// rows that actually carry a sha256 are relevant to that lookup.
	if current < 15 {
		if _, err := s.db.Exec(`
CREATE INDEX IF NOT EXISTS idx_events_sha256 ON events(sha256) WHERE sha256 != '';`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (15, ?)`, now); err != nil {
			return err
		}
	}

	// v16: session side-channel retention. HASSH and session metadata are
	// unbounded session-keyed tables, so give each row an observation time and
	// an index that MaintenancePurge can use. Existing v15 rows have no source
	// timestamp; backfill them to migration time so upgrading cannot
	// immediately discard still-useful bindings. The transaction plus guarded
	// ALTERs makes a retry safe while preserving all payload columns.
	if current < 16 {
		if err := s.WithTx(func(tx *sql.Tx) error {
			if _, err := tx.Exec(`
CREATE TABLE IF NOT EXISTS cowrie_session_hassh (
  session_id  TEXT PRIMARY KEY,
  hassh       TEXT NOT NULL,
  observed_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS cowrie_session_meta (
  session_id  TEXT PRIMARY KEY,
  duration_ms INTEGER DEFAULT 0,
  arch        TEXT,
  observed_at TEXT NOT NULL DEFAULT ''
);`); err != nil {
				return err
			}
			for _, table := range []string{"cowrie_session_hassh", "cowrie_session_meta"} {
				has, err := columnExistsIn(tx, table, "observed_at")
				if err != nil {
					return err
				}
				if !has {
					if _, err := tx.Exec(`ALTER TABLE ` + table + ` ADD COLUMN observed_at TEXT NOT NULL DEFAULT ''`); err != nil {
						return err
					}
				}
				if _, err := tx.Exec(`UPDATE `+table+` SET observed_at=? WHERE observed_at IS NULL OR observed_at=''`, now); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(`
CREATE INDEX IF NOT EXISTS idx_cowrie_session_hassh_observed_at ON cowrie_session_hassh(observed_at);
CREATE INDEX IF NOT EXISTS idx_cowrie_session_meta_observed_at ON cowrie_session_meta(observed_at);`); err != nil {
				return err
			}
			_, err := tx.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (16, ?)`, now)
			return err
		}); err != nil {
			return err
		}
	}

	// v17: artifact retry with durable attempt tracking and lease-based
	// claiming. Adds attempt_count for retry budget, next_attempt_at for
	// backoff scheduling, and an index for the due-artifacts polling query.
	// Backfills existing terminal rows (fetched/blocked) with attempt_count=1
	// so the worker never retries already-completed captures.
	if current < 17 {
		if err := s.WithTx(func(tx *sql.Tx) error {
			// Ensure the artifacts table exists — it is lazily created by
			// ensureArtifactsTable, but the migration needs it now.
			if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS artifacts (
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
  UNIQUE(url)
)`); err != nil {
				return err
			}
			for _, ddl := range []struct{ col, stmt string }{
				{"attempt_count", `ALTER TABLE artifacts ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0`},
				{"next_attempt_at", `ALTER TABLE artifacts ADD COLUMN next_attempt_at TEXT`},
			} {
				has, err := columnExistsIn(tx, "artifacts", ddl.col)
				if err != nil {
					return err
				}
				if !has {
					if _, err := tx.Exec(ddl.stmt); err != nil {
						return err
					}
				}
			}
			// Backfill terminal rows so the worker never retries them.
			if _, err := tx.Exec(`UPDATE artifacts SET attempt_count=1 WHERE status IN ('fetched','blocked') AND attempt_count=0`); err != nil {
				return err
			}
			if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_artifacts_capture_due ON artifacts(origin, status, next_attempt_at)`); err != nil {
				return err
			}
			_, err := tx.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (17, ?)`, now)
			return err
		}); err != nil {
			return err
		}
	}

	// v18: actors.flags — the event-mix bitmask (models.ActorFlag*). Persisting
	// it lets ingest fold fresh events into the stored aggregate instead of
	// re-scanning every event the actor ever produced. Legacy rows keep 0 and
	// are repaired by a one-shot full re-aggregation on their next touch.
	if current < 18 {
		has, err := s.columnExists("actors", "flags")
		if err != nil {
			return err
		}
		if !has {
			if _, err := s.db.Exec(`ALTER TABLE actors ADD COLUMN flags INTEGER NOT NULL DEFAULT 0`); err != nil {
				return err
			}
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (18, ?)`, now); err != nil {
			return err
		}
	}
	if current < 19 {
		if err := s.migrateCaptureEvidence(now); err != nil {
			return err
		}
	}
	// v20: exact event instants. The column is intentionally nullable and this
	// migration is schema-only: rewriting a multi-million-row events table while
	// Open holds startup would create a large WAL and delay the live daemon. New
	// writes populate it immediately; a bounded ID-cursor worker backfills legacy
	// rows after startup.
	if current < 20 {
		has, err := s.columnExists("events", "ts_unix_ns")
		if err != nil {
			return err
		}
		if !has {
			if _, err := s.db.Exec(`ALTER TABLE events ADD COLUMN ts_unix_ns INTEGER`); err != nil {
				return err
			}
		}
		if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_unix_ns ON events(ts_unix_ns, id) WHERE ts_unix_ns IS NOT NULL`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (20, ?)`, now); err != nil {
			return err
		}
	}
	// v21: isolate unconverted timestamps. A migrated database pays no
	// full-table scan to check for legacy rows, and backfill shrinks this index.
	if current < 21 {
		if err := s.WithTx(func(tx *sql.Tx) error {
			if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_events_legacy_ts ON events(ts,id) WHERE ts_unix_ns IS NULL`); err != nil {
				return err
			}
			_, err := tx.Exec(`INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(21,?)`, now)
			return err
		}); err != nil {
			return err
		}
	}
	// v22 is schema-only: keep original submission/dedup records intact and
	// repair exact ordering keys in bounded background transactions.
	if current < 22 {
		if err := s.migrateLedgerTimes(now); err != nil {
			return err
		}
	}
	if current < 23 {
		if err := s.migrateJournalSummaries(now); err != nil {
			return err
		}
	}
	if current < 24 {
		if err := s.migrateFileCaptures(now); err != nil {
			return err
		}
	}
	return nil
}

// columnExists reports whether a table has a given column (via PRAGMA
// table_info). Used by migrations that ADD COLUMN idempotently.
func (s *Store) columnExists(table, column string) (bool, error) {
	return columnExistsIn(s.db, table, column)
}

func columnExistsIn(q sqlQueryer, table, column string) (bool, error) {
	rows, err := q.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid         int
			name, ctype string
			notnull, pk int
			dflt        sql.NullString
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// currentSchemaVersion returns the highest applied migration version
// recorded in schema_migrations, or 0 if the table is empty (which
// is the case on a brand-new database where CREATE TABLE IF NOT
// EXISTS just ran for the first time).
func (s *Store) currentSchemaVersion() (int, error) {
	var v sql.NullInt64
	row := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`)
	if err := row.Scan(&v); err != nil {
		return 0, err
	}
	return int(v.Int64), nil
}

func (s *Store) ensureLegacyColumns() error {
	rows, err := s.db.Query(`PRAGMA table_info(events)`)
	if err != nil {
		return err
	}
	defer rows.Close()

	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	legacyColumns := []struct {
		name string
		ddl  string
	}{
		{"src_port", `ALTER TABLE events ADD COLUMN src_port INTEGER DEFAULT 0`},
		{"password", `ALTER TABLE events ADD COLUMN password TEXT`},
		{"session_id", `ALTER TABLE events ADD COLUMN session_id TEXT`},
		{"hassh", `ALTER TABLE events ADD COLUMN hassh TEXT`},
		{"ssh_client", `ALTER TABLE events ADD COLUMN ssh_client TEXT`},
		{"command", `ALTER TABLE events ADD COLUMN command TEXT`},
		{"sha256", `ALTER TABLE events ADD COLUMN sha256 TEXT`},
		{"filename", `ALTER TABLE events ADD COLUMN filename TEXT`},
		{"raw", `ALTER TABLE events ADD COLUMN raw TEXT`},
		{"actor_id", `ALTER TABLE events ADD COLUMN actor_id TEXT`},
	}
	for _, col := range legacyColumns {
		if !cols[col.name] {
			if _, err := s.db.Exec(col.ddl); err != nil {
				return err
			}
		}
	}
	return nil
}

// QueryRows runs a parameterized query and invokes scan on each row.
// It is exposed so ingest helpers (e.g. batchDedupJournal) can issue
// ad-hoc IN-list queries without re-implementing rows.Close handling.
func (s *Store) QueryRows(query string, args []any, scan func(scan func(...any) error) error) error {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows.Scan); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *Store) InsertEvent(e *models.Event) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return insertEvent(s.db, e)
}

func insertEvent(db sqlExecer, e *models.Event) error {
	res, err := db.Exec(`
INSERT INTO events (ts, ts_unix_ns, source, kind, src_ip, src_port, username, password, session_id, hassh, ssh_client, command, sha256, filename, dst_ip, dst_port, raw, actor_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		formatFixedUTC(e.TS), e.TS.UnixNano(), e.Source, e.Kind, e.SrcIP, e.SrcPort,
		e.Username, e.Password, e.SessionID, e.HASSH, e.SSHClient,
		e.Command, e.SHA256, e.Filename, e.DstIP, e.DstPort, e.Raw, e.ActorID)
	if err != nil {
		return err
	}
	if id, err := res.LastInsertId(); err == nil {
		e.ID = id
	}
	return nil
}

func (s *Store) UpsertActor(a *models.Actor) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return upsertActor(s.db, a)
}

func upsertActor(db sqlExecer, a *models.Actor) error {
	_, err := db.Exec(`
INSERT INTO actors (id, source, primary_ip, playbook, intent, confidence, first_seen, last_seen, event_count, unique_users, attempts_per_hour, hassh, ssh_client, username_hash, campaigns, probe_score, notes, flags, generated_notes)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  primary_ip=excluded.primary_ip, playbook=excluded.playbook, intent=excluded.intent,
  confidence=excluded.confidence, first_seen=excluded.first_seen, last_seen=excluded.last_seen,
  event_count=excluded.event_count,
  unique_users=excluded.unique_users, attempts_per_hour=excluded.attempts_per_hour,
  hassh=excluded.hassh, ssh_client=excluded.ssh_client, username_hash=excluded.username_hash,
  probe_score=excluded.probe_score,
  flags=excluded.flags, generated_notes=excluded.generated_notes`,
		a.ID, a.Source, a.PrimaryIP, a.Playbook, a.Intent, a.Confidence,
		a.FirstSeen.UTC().Format(time.RFC3339Nano), a.LastSeen.UTC().Format(time.RFC3339Nano),
		a.EventCount, a.UniqueUsers, a.AttemptsPerHour, a.HASSH, a.SSHClient,
		a.UsernameHash, a.Campaigns, a.ProbeScore, a.Notes, a.Flags, a.GeneratedNotes)
	return err
}

func upsertActorIP(db sqlRowExecer, actorID, ip string, firstSeen, lastSeen time.Time, count int) error {
	var storedFirst, storedLast sql.NullString
	err := db.QueryRow("SELECT first_seen,last_seen FROM actor_ips WHERE actor_id=? AND ip=?", actorID, ip).
		Scan(&storedFirst, &storedLast)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = db.Exec("INSERT INTO actor_ips (actor_id, ip, first_seen, last_seen, count) VALUES (?, ?, ?, ?, ?)",
			actorID, ip, formatFixedUTC(firstSeen), formatFixedUTC(lastSeen), count)
		return err
	}
	if err != nil {
		return err
	}

	mergedFirst, mergedLast := firstSeen, lastSeen
	if storedFirst.Valid && storedFirst.String != "" {
		parsed, err := time.Parse(time.RFC3339Nano, storedFirst.String)
		if err != nil {
			return fmt.Errorf("actor_ips %s/%s first_seen: %w", actorID, ip, err)
		}
		if parsed.Before(mergedFirst) {
			mergedFirst = parsed
		}
	}
	if storedLast.Valid && storedLast.String != "" {
		parsed, err := time.Parse(time.RFC3339Nano, storedLast.String)
		if err != nil {
			return fmt.Errorf("actor_ips %s/%s last_seen: %w", actorID, ip, err)
		}
		if parsed.After(mergedLast) {
			mergedLast = parsed
		}
	}
	_, err = db.Exec("UPDATE actor_ips SET first_seen=?,last_seen=?,count=? WHERE actor_id=? AND ip=?",
		formatFixedUTC(mergedFirst), formatFixedUTC(mergedLast), count, actorID, ip)
	return err
}

func formatFixedUTC(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

// CanonicalEventTime is the exact text representation used by event writes and
// identity probes. Keeping this single-site prevents append dedup from drifting
// when the storage format changes.
func CanonicalEventTime(t time.Time) string { return formatFixedUTC(t) }

func upsertActorUser(db sqlExecer, actorID, user string, count int) error {
	_, err := db.Exec(`
INSERT INTO actor_users (actor_id, username, count) VALUES (?, ?, ?)
ON CONFLICT(actor_id, username) DO UPDATE SET count=excluded.count`,
		actorID, user, count)
	return err
}

// actorColumns is the canonical SELECT list for an actors row. Kept in
// one place so ListActors / GetActor / GetActorByPrimaryIP stay in sync
// with scanActorRow below.
const actorColumns = `id, source, primary_ip, playbook, intent, confidence, first_seen, last_seen, event_count, unique_users, attempts_per_hour, hassh, ssh_client, username_hash, campaigns, probe_score, notes, flags, generated_notes, (` + journalDerivedStateSQL + `)='current',` + journalDerivedStateSQL

// rowScan is satisfied by both *sql.Row and *sql.Rows so the same
// scan code can be used for single-row QueryRow and Query iteration.
// (Different from rowScanner in dashboard.go which models the full
// *sql.Rows iterator surface.)
type rowScan interface {
	Scan(dest ...any) error
}

// scanActorRow populates a models.Actor from a single sql row in the
// order defined by actorColumns. Timestamps stored as RFC3339Nano text
// are decoded via parseTime so a malformed value is surfaced rather
// than silently zeroed (fix #13).
func scanActorRow(r rowScan, a *models.Actor) error {
	var fs, ls string
	var derivedStatus string
	if err := r.Scan(&a.ID, &a.Source, &a.PrimaryIP, &a.Playbook, &a.Intent, &a.Confidence,
		&fs, &ls, &a.EventCount, &a.UniqueUsers, &a.AttemptsPerHour, &a.HASSH, &a.SSHClient,
		&a.UsernameHash, &a.Campaigns, &a.ProbeScore, &a.Notes, &a.Flags, &a.GeneratedNotes, &a.DerivedCurrent, &derivedStatus); err != nil {
		return err
	}
	var err error
	if a.FirstSeen, err = parseTime(fs); err != nil {
		return fmt.Errorf("actor %s first_seen: %w", a.ID, err)
	}
	if a.LastSeen, err = parseTime(ls); err != nil {
		return fmt.Errorf("actor %s last_seen: %w", a.ID, err)
	}
	if a.Source == models.SourceJournal && !a.DerivedCurrent {
		a.UsernameHash, a.Confidence, a.ProbeScore = "", 0, 0
		if derivedStatus == "unknown_history" {
			a.Playbook, a.GeneratedNotes = "unknown_history", "Historical username coverage is unverified"
		} else {
			a.Playbook, a.GeneratedNotes = "pending", "Journal profile derivation is pending"
		}
	}
	return nil
}

// parseTime decodes a RFC3339Nano timestamp from the DB. An empty string
// is treated as the zero time (legacy rows may have NULL first/last seen).
func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, s)
}

// queryActors runs a `SELECT <actorColumns> FROM actors ...` query and scans
// the rows. Shared by the three list variants below so a future actor-column
// change stays single-site.
func (s *Store) queryActors(q string, args ...any) ([]models.Actor, error) {
	return s.queryActorsContext(context.Background(), q, args...)
}

// queryActorsContext is the cancellable counterpart to queryActors. Reporting
// candidates can require scanning a large actor table; request/CLI shutdown
// must be able to interrupt that read instead of waiting for the full query.
func (s *Store) queryActorsContext(ctx context.Context, q string, args ...any) ([]models.Actor, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Actor
	for rows.Next() {
		var a models.Actor
		if err := scanActorRow(rows, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) ListActors(limit int) ([]models.Actor, error) {
	q := `SELECT ` + actorColumns + ` FROM actors ORDER BY last_seen DESC`
	if limit > 0 {
		return s.queryActors(q+" LIMIT ?", limit)
	}
	return s.queryActors(q)
}

// TopActorsByEvents returns actors ordered by total event_count — the actual
// "top actors" by volume. The globe's actor list is ordered by last_seen (for
// the live globe arcs), so a client-side slice of it showed recent actors, not
// the highest-volume ones (the 64k-event top attacker was absent because it
// wasn't recently active).
func (s *Store) TopActorsByEvents(limit int) ([]models.Actor, error) {
	if limit <= 0 {
		limit = 14
	}
	return s.queryActors(`SELECT `+actorColumns+`
FROM actors ORDER BY event_count DESC LIMIT ?`, limit)
}

// TopActorsByRate returns the actors with the highest attempts_per_hour. The
// Brute-Force Radar needs the most AGGRESSIVE actors, but ListActors orders by
// last_seen (most recent), so the radar — fed from that recent slice — was
// missing the true high-rate attackers (e.g. showing 171/h when the real top
// was 3113/h). This orders by rate so the radar reflects the actual peak.
func (s *Store) TopActorsByRate(limit int) ([]models.Actor, error) {
	if limit <= 0 {
		limit = 8
	}
	return s.queryActors(`SELECT `+actorColumns+`
FROM actors WHERE attempts_per_hour > 0
ORDER BY attempts_per_hour DESC LIMIT ?`, limit)
}

func (s *Store) GetActor(id string) (*models.Actor, error) {
	row := s.db.QueryRow(`SELECT `+actorColumns+` FROM actors WHERE id=?`, id)
	var a models.Actor
	if err := scanActorRow(row, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// ActorState is the persisted aggregate for one actor: the actor row plus its
// full per-username and per-IP roll-ups. This is everything the ingest fold
// needs to continue an actor's aggregate without re-scanning its events.
type ActorState struct {
	Actor *models.Actor
	Users map[string]int
	IPs   map[string]models.IPStat
}

// ActorStatesForIDs loads the persisted aggregates for the given actor IDs in
// three batched queries (actors, actor_users, actor_ips). It exists so the
// cowrie ingest fold reads O(usernames + IPs) per touched actor instead of
// O(events): on the reference deployment the per-tick full event re-scan of a
// 300k-event actor was 98.5% of lifetime allocations (13.8 TB, ~1.4 GC/sec).
// Missing IDs are simply absent from the result (brand-new actors).
func (s *Store) ActorStatesForIDs(ids []string) (map[string]*ActorState, error) {
	return actorStatesForIDs(s.db, ids)
}

// The transaction form keeps reconciliation's reads and writes in one snapshot.
func actorStatesForIDs(db sqlQueryer, ids []string) (map[string]*ActorState, error) {
	out := make(map[string]*ActorState, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, 0, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args = append(args, id)
	}
	in := strings.Join(placeholders, ",")

	rows, err := db.Query(`SELECT `+actorColumns+` FROM actors WHERE id IN (`+in+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a models.Actor
		if err := scanActorRow(rows, &a); err != nil {
			return nil, err
		}
		out[a.ID] = &ActorState{Actor: &a, Users: map[string]int{}, IPs: map[string]models.IPStat{}}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}

	urows, err := db.Query(`SELECT actor_id, username, count FROM actor_users WHERE actor_id IN (`+in+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer urows.Close()
	for urows.Next() {
		var id, u string
		var c int
		if err := urows.Scan(&id, &u, &c); err != nil {
			return nil, err
		}
		if st, ok := out[id]; ok {
			st.Users[u] = c
		}
	}
	if err := urows.Err(); err != nil {
		return nil, err
	}

	iprows, err := db.Query(`SELECT actor_id, ip, first_seen, last_seen, count FROM actor_ips WHERE actor_id IN (`+in+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer iprows.Close()
	for iprows.Next() {
		var id, ip, fs, ls string
		var c int
		if err := iprows.Scan(&id, &ip, &fs, &ls, &c); err != nil {
			return nil, err
		}
		st, ok := out[id]
		if !ok {
			continue
		}
		first, err := parseTime(fs)
		if err != nil {
			return nil, fmt.Errorf("actor_ips %s first_seen: %w", id, err)
		}
		last, err := parseTime(ls)
		if err != nil {
			return nil, fmt.Errorf("actor_ips %s last_seen: %w", id, err)
		}
		st.IPs[ip] = models.IPStat{Count: c, First: first, Last: last}
	}
	return out, iprows.Err()
}

func (s *Store) ActorUsers(id string) ([]models.ActorUser, error) {
	return s.ActorUsersLimit(id, 30)
}

// ActorUsersForActors returns the top-N usernames per actor for a batch of
// actor IDs in ONE query. The /api/intel handler previously issued one
// ActorUsersLimit query per listed actor (80 point queries per poll).
// The window function needs SQLite 3.25+; modernc.org/sqlite bundles 3.4x.
func (s *Store) ActorUsersForActors(ids []string, perActor int) (map[string][]models.ActorUser, error) {
	if len(ids) == 0 {
		return map[string][]models.ActorUser{}, nil
	}
	if perActor <= 0 {
		perActor = 8
	}
	placeholders := make([]string, len(ids))
	args := make([]any, 0, len(ids)+1)
	for i, id := range ids {
		placeholders[i] = "?"
		args = append(args, id)
	}
	args = append(args, perActor)
	q := `
SELECT actor_id, username, count FROM (
  SELECT actor_id, username, count,
         ROW_NUMBER() OVER (PARTITION BY actor_id ORDER BY count DESC, username) AS rn
  FROM actor_users WHERE actor_id IN (` + strings.Join(placeholders, ",") + `)
) WHERE rn <= ? ORDER BY actor_id, count DESC`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string][]models.ActorUser, len(ids))
	for rows.Next() {
		var u models.ActorUser
		if err := rows.Scan(&u.ActorID, &u.Username, &u.Count); err != nil {
			return nil, err
		}
		out[u.ActorID] = append(out[u.ActorID], u)
	}
	return out, rows.Err()
}

func (s *Store) ActorUsersLimit(id string, limit int) ([]models.ActorUser, error) {
	q := `SELECT actor_id, username, count FROM actor_users WHERE actor_id=? ORDER BY count DESC`
	var rows *sql.Rows
	var err error
	if limit > 0 {
		rows, err = s.db.Query(q+` LIMIT ?`, id, limit)
	} else {
		rows, err = s.db.Query(q, id)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ActorUser
	for rows.Next() {
		var u models.ActorUser
		if err := rows.Scan(&u.ActorID, &u.Username, &u.Count); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// RecentEvents returns a SUMMARY of the most recent events: only the
// columns needed by the TUI live-feed and the web dashboard recent list
// (id, ts, source, kind, src_ip, username, command, actor_id, raw).
// Fields not selected (src_port, password, session_id, hassh, ssh_client,
// sha256, filename) are left at their zero value. If you need full event
// rows use EventsSince or IterateEventsBySource instead.
func (s *Store) RecentEvents(limit int) ([]models.Event, error) {
	rows, err := s.db.Query(`
SELECT id, ts, source, kind, COALESCE(src_ip,''), COALESCE(username,''), COALESCE(command,''), COALESCE(actor_id,''), COALESCE(raw,'') FROM events ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Event
	for rows.Next() {
		var e models.Event
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Source, &e.Kind, &e.SrcIP, &e.Username, &e.Command, &e.ActorID, &e.Raw); err != nil {
			return nil, err
		}
		if e.TS, err = parseTime(ts); err != nil {
			return nil, fmt.Errorf("event %d ts: %w", e.ID, err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) GetActorByPrimaryIP(ip string) (*models.Actor, error) {
	row := s.db.QueryRow(`SELECT `+actorColumns+` FROM actors WHERE primary_ip=? ORDER BY last_seen DESC LIMIT 1`, ip)
	var a models.Actor
	if err := scanActorRow(row, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// GetReportableActorByIP returns the BEST actor row for reporting an IP, not
// just the most-recent one. A single IP can have two actor rows — one per
// source (cowrie vs journal) — because the two ingest paths cluster
// independently. GetActorByPrimaryIP picks by last_seen, which can return a
// low-signal "unknown" cowrie row while a journal row for the SAME IP is a
// confirmed brute-forcer. Reporting is about the IP, so pick the row most
// likely to pass the report vet: highest probe_score, then most events. This
// is the resolver the report/suggestions paths use so the widget's eligibility
// and the report action agree on the same evidence.
func (s *Store) GetReportableActorByIP(ip string) (*models.Actor, error) {
	row := s.db.QueryRow(`SELECT `+actorColumns+`
FROM actors WHERE primary_ip=?
ORDER BY probe_score DESC, event_count DESC, last_seen DESC
LIMIT 1`, ip)
	var a models.Actor
	if err := scanActorRow(row, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) EventCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n)
	return n, err
}

func (s *Store) ActorCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM actors`).Scan(&n)
	return n, err
}

// LatestEventTime returns the timestamp of the most recent event, or zero time
// if there are no events. Used by the Settings health strip to show how fresh
// ingest is ("last event 3s ago" vs a stalled feed).
func (s *Store) LatestEventTime() (time.Time, error) {
	return latestEventTime(context.Background(), s.db)
}

// MaintenancePurge deletes rows older than retentionDays from the
// unbounded-growth tables: events, artifacts, ip_enrichment,
// cowrie_tty_index, cowrie_session_hassh, and cowrie_session_meta.
// Actor identity tables (actors, actor_ips,
// actor_users) are not pruned — their upper bound is the distinct
// attacker set, not time. Runs as a single quick transaction so a
// crash mid-purge won't leave partial state. Pass 0 to skip.
//
// The smaller retention tables are all created
// lazily by their respective writers (ensureArtifactsTable etc.)
// so a brand-new install would fail this purge with "no such
// table" until the first artifact/enrichment/cowrie download
// happens. Pre-create them here so the very first purge call
// against a fresh DB is a clean no-op rather than an error.
func (s *Store) MaintenancePurge(retentionDays int) error {
	if retentionDays <= 0 {
		return nil
	}
	if err := s.EnsureEnrichmentTable(); err != nil {
		return err
	}
	if err := s.ensureCowrieTTYIndex(); err != nil {
		return err
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return err
	}
	if err := s.ensureSessionHASSHIndex(); err != nil {
		return err
	}
	if err := s.ensureSessionMetaTable(); err != nil {
		return err
	}
	// payload_intel is a CACHE of third-party payload verdicts, so it ages out
	// with everything else. Note the deliberate asymmetry: bazaar_uploads and
	// urlhaus_submissions are NOT purged — they are dedup ledgers, and dropping
	// a row there would make us re-submit the same sample/URL upstream.
	if err := s.ensurePayloadIntelTable(); err != nil {
		return err
	}
	cutoffTime := time.Now().AddDate(0, 0, -retentionDays).UTC()
	// A corrupt event has no chronological meaning. Refuse retention before any
	// table is mutated rather than letting text order delete or retain it by
	// accident.
	var badEventID int64
	var badEventTS string
	err := s.db.QueryRow(`SELECT id,ts FROM events WHERE ts_unix_ns IS NULL AND julianday(ts) IS NULL LIMIT 1`).
		Scan(&badEventID, &badEventTS)
	if err == nil {
		return fmt.Errorf("event %d ts: invalid timestamp %q", badEventID, badEventTS)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	if err := s.ensureFileCaptureTable(); err != nil {
		return err
	}
	// Keep optional-cache validation ahead of artifact retention. Artifact
	// cleanup itself uses bounded pages and an explicit filesystem policy.
	if err := func() error {
		s.captureMu.Lock()
		defer s.captureMu.Unlock()
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		for _, target := range []struct{ table, column string }{
			{"ip_enrichment", "fetched_at"},
			{"cowrie_tty_index", "ts"},
			{"cowrie_session_hassh", "observed_at"},
			{"cowrie_session_meta", "observed_at"},
			{"payload_intel", "fetched_at"},
		} {
			if err := purgeTextTimeRows(tx, target.table, target.column, cutoffTime); err != nil {
				return err
			}
		}

		return tx.Commit()
	}(); err != nil {
		return err
	}
	if err := s.purgeArtifacts(cutoffTime); err != nil {
		return err
	}

	// Events — the largest table. Delete in bounded chunks, each its own
	// transaction, releasing writeMu between chunks. A single DELETE of the
	// whole expired backlog (millions of rows × 7 indexes) on the first purge
	// of an aged DB held writeMu for minutes, stalling the ingest tick, journal
	// tail, and capture runner, and ballooned the WAL.
	const purgeChunk = 5000
	legacyCeiling := formatFixedUTC(cutoffTime.Add(15 * time.Hour))
	var eventCursor int64
	for {
		rows, err := s.db.Query(`SELECT id,ts FROM events
WHERE id>? AND (ts_unix_ns < ? OR (ts_unix_ns IS NULL AND ts < ?))
ORDER BY id LIMIT ?`, eventCursor, cutoffTime.UnixNano(), legacyCeiling, purgeChunk)
		if err != nil {
			return err
		}
		var scanned int
		var expiredEventIDs []int64
		for rows.Next() {
			var id int64
			var ts string
			if err := rows.Scan(&id, &ts); err != nil {
				rows.Close()
				return err
			}
			scanned++
			eventCursor = id
			parsed, err := time.Parse(time.RFC3339Nano, ts)
			if err != nil {
				rows.Close()
				return fmt.Errorf("event %d ts: %w", id, err)
			}
			if parsed.Before(cutoffTime) {
				expiredEventIDs = append(expiredEventIDs, id)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if len(expiredEventIDs) > 0 {
			if err := func() error {
				s.captureMu.Lock()
				defer s.captureMu.Unlock()
				return s.WithTx(func(tx *sql.Tx) error {
					ceiling, err := s.captureEventCeilingTx(tx)
					if err != nil {
						return err
					}
					eligible := expiredEventIDs[:0]
					for _, id := range expiredEventIDs {
						if id <= ceiling {
							eligible = append(eligible, id)
						}
					}
					return deleteRowsByID(tx, "events", eligible)
				})
			}(); err != nil {
				return err
			}
		}
		if scanned < purgeChunk {
			break
		}
	}

	// Actors are DERIVED from events, so an actor whose every event the sweep
	// above deleted has no evidence left behind it. Those orphans kept a stale
	// event_count, a playbook frozen at whatever the classifier said months
	// ago, and inflated the dashboard's actor total with attackers nothing can
	// corroborate — and `reclassify` could never re-derive them, because there
	// is nothing left to re-scan (prod: 103 such rows, 102 of them reading
	// "unknown", which was the entire residual unknown population).
	//
	// Three guards keep this from deleting anything real:
	//   - last_seen < cutoff, so an actor the ingest tick created moments ago
	//     (its events not yet visible to this transaction) is never raced away;
	//   - no surviving events, an index probe on the (actor_id, ts) composite;
	//   - no operator annotation (see isOperatorNote: builder text left in the
	//     legacy notes column before v23 is not one).
	//
	// Unlike events this is NOT chunked: actors is bounded by the number of
	// distinct attacker identities (thousands, against a million events), so
	// one transaction holds writeMu for a fraction of a single event chunk.
	// The predicate is stable across the three statements because deleting the
	// child rows cannot change which actors match it.
	if err := func() error {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		rows, err := tx.Query(`SELECT id,last_seen,COALESCE(notes,'') FROM actors
WHERE COALESCE(campaigns,'')=''
  AND NOT EXISTS (SELECT 1 FROM events e WHERE e.actor_id=actors.id)`)
		if err != nil {
			return err
		}
		var orphanIDs []string
		for rows.Next() {
			var id, lastSeen, notes string
			if err := rows.Scan(&id, &lastSeen, &notes); err != nil {
				rows.Close()
				return err
			}
			if isOperatorNote(notes) {
				continue
			}
			parsed, err := time.Parse(time.RFC3339Nano, lastSeen)
			if err != nil {
				rows.Close()
				return fmt.Errorf("actor %s last_seen: %w", id, err)
			}
			if parsed.Before(cutoffTime) {
				orphanIDs = append(orphanIDs, id)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, child := range []string{"actor_ips", "actor_users"} {
			if err := deleteStringRowsByKey(tx, child, "actor_id", orphanIDs); err != nil {
				return err
			}
		}
		if err := deleteStringRowsByKey(tx, "actors", "id", orphanIDs); err != nil {
			return err
		}
		return tx.Commit()
	}(); err != nil {
		return err
	}

	if err := s.purgeCaptureDiagnostics(cutoffTime); err != nil {
		return err
	}

	// Reclaim WAL space the chunked deletes accumulated, then refresh the query
	// planner's stats. A large purge changes table/index cardinality enough to
	// flip a plan; running optimize here (on the same 24h maintenance cadence)
	// keeps the documented index plans valid as the DB grows and shrinks.
	func() {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
		_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		_, _ = s.db.Exec(`PRAGMA optimize`)
	}()

	return nil
}

func deleteRowsByID(tx *sql.Tx, table string, ids []int64) error {
	if table != "events" && table != "artifacts" {
		return fmt.Errorf("unsupported purge table %q", table)
	}
	const chunk = 400
	for start := 0; start < len(ids); start += chunk {
		end := start + chunk
		if end > len(ids) {
			end = len(ids)
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", end-start), ",")
		args := make([]any, 0, end-start)
		for _, id := range ids[start:end] {
			args = append(args, id)
		}
		if _, err := tx.Exec("DELETE FROM "+table+" WHERE id IN ("+placeholders+")", args...); err != nil {
			return err
		}
	}
	return nil
}

func purgeTextTimeRows(tx *sql.Tx, table, column string, cutoff time.Time) error {
	valid := (table == "ip_enrichment" && column == "fetched_at") ||
		(table == "cowrie_tty_index" && column == "ts") ||
		((table == "cowrie_session_hassh" || table == "cowrie_session_meta") && column == "observed_at") ||
		(table == "payload_intel" && column == "fetched_at")
	if !valid {
		return fmt.Errorf("unsupported retention timestamp %s.%s", table, column)
	}
	rows, err := tx.Query("SELECT rowid," + column + " FROM " + table)
	if err != nil {
		return err
	}
	var expired []int64
	for rows.Next() {
		var rowID int64
		var text string
		if err := rows.Scan(&rowID, &text); err != nil {
			rows.Close()
			return err
		}
		parsed, err := time.Parse(time.RFC3339Nano, text)
		if err != nil {
			rows.Close()
			return fmt.Errorf("%s row %d %s: %w", table, rowID, column, err)
		}
		if parsed.Before(cutoff) {
			expired = append(expired, rowID)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	return deleteRowsByRowID(tx, table, expired)
}

func deleteRowsByRowID(tx *sql.Tx, table string, ids []int64) error {
	switch table {
	case "ip_enrichment", "cowrie_tty_index", "cowrie_session_hassh", "cowrie_session_meta", "payload_intel":
	default:
		return fmt.Errorf("unsupported rowid purge table %q", table)
	}
	const chunk = 400
	for start := 0; start < len(ids); start += chunk {
		end := start + chunk
		if end > len(ids) {
			end = len(ids)
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", end-start), ",")
		args := make([]any, 0, end-start)
		for _, id := range ids[start:end] {
			args = append(args, id)
		}
		if _, err := tx.Exec("DELETE FROM "+table+" WHERE rowid IN ("+placeholders+")", args...); err != nil {
			return err
		}
	}
	return nil
}

func deleteStringRowsByKey(tx *sql.Tx, table, column string, values []string) error {
	valid := (table == "actors" && column == "id") ||
		((table == "actor_ips" || table == "actor_users") && column == "actor_id")
	if !valid {
		return fmt.Errorf("unsupported purge target %s.%s", table, column)
	}
	const chunk = 400
	for start := 0; start < len(values); start += chunk {
		end := start + chunk
		if end > len(values) {
			end = len(values)
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", end-start), ",")
		args := make([]any, 0, end-start)
		for _, value := range values[start:end] {
			args = append(args, value)
		}
		if _, err := tx.Exec("DELETE FROM "+table+" WHERE "+column+" IN ("+placeholders+")", args...); err != nil {
			return err
		}
	}
	return nil
}
