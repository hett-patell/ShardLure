package store

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
	// writeMu serializes WRITES at the application layer. SQLite allows only
	// one writer, and live mode has several writer goroutines (journal tail,
	// cowrie ticker, retention purge) plus the web server sharing this db; with
	// the default pool they'd race the write lock and the loser would hit a
	// busy_timeout error that callers only log-and-continue (a silently dropped
	// batch). Serializing writes here avoids that WITHOUT capping the pool to a
	// single connection — so concurrent READS still run in parallel under WAL
	// (a 1-connection pool would make a slow analytics query block ingest).
	writeMu sync.Mutex

	// Lazy-table creation guards. The artifacts / enrichment / bazaar / tty
	// tables are created on first use (CREATE TABLE IF NOT EXISTS), but the
	// ensure* helpers were called on EVERY read and write — each running a DDL
	// statement under writeMu, adding pointless lock contention on hot paths.
	// A sync.Once per table runs the DDL exactly once; subsequent calls are a
	// cheap atomic check with no lock.
	onceArtifacts   sync.Once
	onceEnrich      sync.Once
	onceBazaar      sync.Once
	onceTTY         sync.Once
	onceSessHASSH   sync.Once
	onceSessMeta    sync.Once
	onceAbuseReport sync.Once
	// errs from the once-bodies, so a failed creation still surfaces.
	errArtifacts   error
	errEnrich      error
	errBazaar      error
	errTTY         error
	errSessHASSH   error
	errSessMeta    error
	errAbuseReport error
}

type sqlExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	// Allow a few connections so WAL readers run concurrently with the single
	// writer (writes are serialized by writeMu, not by the pool size). A 1-conn
	// pool would throw away WAL's reader/writer concurrency and let one slow
	// dashboard query stall live ingest.
	db.SetMaxOpenConns(8)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	// Honeypot DBs can contain attacker-supplied passwords; restrict to owner.
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Stat(p); err == nil {
			_ = os.Chmod(p, 0o600)
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
  -- RFC3339Nano UTC text; dashboard hourly aggregation relies on ISO prefix ordering.
  ts TEXT NOT NULL,
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
	// is useless for ip-only scans such as LoadJournalIPStats).
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
	return nil
}

// columnExists reports whether a table has a given column (via PRAGMA
// table_info). Used by migrations that ADD COLUMN idempotently.
func (s *Store) columnExists(table, column string) (bool, error) {
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
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
INSERT INTO events (ts, source, kind, src_ip, src_port, username, password, session_id, hassh, ssh_client, command, sha256, filename, dst_ip, dst_port, raw, actor_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TS.UTC().Format(time.RFC3339Nano), e.Source, e.Kind, e.SrcIP, e.SrcPort,
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
INSERT INTO actors (id, source, primary_ip, playbook, intent, confidence, first_seen, last_seen, event_count, unique_users, attempts_per_hour, hassh, ssh_client, username_hash, campaigns, probe_score, notes)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  primary_ip=excluded.primary_ip, playbook=excluded.playbook, intent=excluded.intent,
  confidence=excluded.confidence, first_seen=excluded.first_seen, last_seen=excluded.last_seen,
  event_count=excluded.event_count,
  unique_users=excluded.unique_users, attempts_per_hour=excluded.attempts_per_hour,
  hassh=excluded.hassh, ssh_client=excluded.ssh_client, username_hash=excluded.username_hash,
  campaigns=excluded.campaigns, probe_score=excluded.probe_score, notes=excluded.notes`,
		a.ID, a.Source, a.PrimaryIP, a.Playbook, a.Intent, a.Confidence,
		a.FirstSeen.UTC().Format(time.RFC3339Nano), a.LastSeen.UTC().Format(time.RFC3339Nano),
		a.EventCount, a.UniqueUsers, a.AttemptsPerHour, a.HASSH, a.SSHClient,
		a.UsernameHash, a.Campaigns, a.ProbeScore, a.Notes)
	return err
}

func upsertActorIP(db sqlExecer, actorID, ip string, firstSeen, lastSeen time.Time, count int) error {
	_, err := db.Exec(`
INSERT INTO actor_ips (actor_id, ip, first_seen, last_seen, count) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(actor_id, ip) DO UPDATE SET
  first_seen=CASE WHEN excluded.first_seen < first_seen THEN excluded.first_seen ELSE first_seen END,
  last_seen=CASE WHEN excluded.last_seen > last_seen THEN excluded.last_seen ELSE last_seen END,
  count=excluded.count`,
		actorID, ip, firstSeen.UTC().Format(time.RFC3339Nano), lastSeen.UTC().Format(time.RFC3339Nano), count)
	return err
}

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
const actorColumns = `id, source, primary_ip, playbook, intent, confidence, first_seen, last_seen, event_count, unique_users, attempts_per_hour, hassh, ssh_client, username_hash, campaigns, probe_score, notes`

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
	if err := r.Scan(&a.ID, &a.Source, &a.PrimaryIP, &a.Playbook, &a.Intent, &a.Confidence,
		&fs, &ls, &a.EventCount, &a.UniqueUsers, &a.AttemptsPerHour, &a.HASSH, &a.SSHClient,
		&a.UsernameHash, &a.Campaigns, &a.ProbeScore, &a.Notes); err != nil {
		return err
	}
	var err error
	if a.FirstSeen, err = parseTime(fs); err != nil {
		return fmt.Errorf("actor %s first_seen: %w", a.ID, err)
	}
	if a.LastSeen, err = parseTime(ls); err != nil {
		return fmt.Errorf("actor %s last_seen: %w", a.ID, err)
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
	rows, err := s.db.Query(q, args...)
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
SELECT id, ts, source, kind, src_ip, username, command, actor_id, raw FROM events ORDER BY ts DESC LIMIT ?`, limit)
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
	var ts sql.NullString
	if err := s.db.QueryRow(`SELECT MAX(ts) FROM events`).Scan(&ts); err != nil {
		return time.Time{}, err
	}
	if !ts.Valid || ts.String == "" {
		return time.Time{}, nil
	}
	t, _ := parseTime(ts.String)
	return t, nil
}

// MaintenancePurge deletes rows older than retentionDays from the
// four unbounded-growth tables: events, artifacts, ip_enrichment,
// and cowrie_tty_index. Actor identity tables (actors, actor_ips,
// actor_users) are not pruned — their upper bound is the distinct
// attacker set, not time. Runs as a single quick transaction so a
// crash mid-purge won't leave partial state. Pass 0 to skip.
//
// artifacts, ip_enrichment and cowrie_tty_index are all created
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
	cutoff := time.Now().AddDate(0, 0, -retentionDays).UTC().Format(time.RFC3339Nano)

	// Collect the on-disk evidence files belonging to artifacts we're about to
	// delete, so we can unlink them AFTER the row deletion commits. Without
	// this the evidence/ dir grew without bound (the purge deleted only rows),
	// eventually filling the disk and stopping all telemetry. local_path is
	// always a path WE wrote (filepath.Join(EvidenceDir, ...)), never attacker
	// input, so it is safe to remove directly.
	var artifactFiles []string
	func() {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
		rows, err := s.db.Query(
			`SELECT local_path FROM artifacts WHERE COALESCE(ts, created_at) < ? AND local_path IS NOT NULL AND local_path != ''`,
			cutoff)
		if err != nil {
			// If we can't enumerate the files, their rows still get deleted
			// below — log so the orphaned evidence files are noticed (a later
			// purge won't see them once the rows are gone).
			log.Printf("store: purge could not list artifact files (will orphan on disk): %v", err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var p string
			if err := rows.Scan(&p); err == nil && p != "" {
				artifactFiles = append(artifactFiles, p)
			}
		}
	}()

	// Small reference tables: delete in one short transaction. Children first
	// so application-level references don't dangle.
	if err := func() error {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		// Enrichment cache — column is fetched_at (see enrichment.go).
		if _, err := tx.Exec(`DELETE FROM ip_enrichment WHERE fetched_at < ?`, cutoff); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM cowrie_tty_index WHERE ts < ?`, cutoff); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM artifacts WHERE COALESCE(ts, created_at) < ?`, cutoff); err != nil {
			return err
		}
		return tx.Commit()
	}(); err != nil {
		return err
	}

	// Events — the largest table. Delete in bounded chunks, each its own
	// transaction, releasing writeMu between chunks. A single DELETE of the
	// whole expired backlog (millions of rows × 7 indexes) on the first purge
	// of an aged DB held writeMu for minutes, stalling the ingest tick, journal
	// tail, and capture runner, and ballooned the WAL.
	const purgeChunk = 5000
	for {
		var affected int64
		if err := func() error {
			s.writeMu.Lock()
			defer s.writeMu.Unlock()
			res, err := s.db.Exec(
				`DELETE FROM events WHERE rowid IN (SELECT rowid FROM events WHERE ts < ? LIMIT ?)`,
				cutoff, purgeChunk)
			if err != nil {
				return err
			}
			affected, _ = res.RowsAffected()
			return nil
		}(); err != nil {
			return err
		}
		if affected < purgeChunk {
			break
		}
	}

	// Reclaim WAL space the chunked deletes accumulated.
	func() {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
		_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	}()

	// Unlink the evidence files now that their rows are gone. Best-effort: an
	// unremovable file is logged-by-omission (a later run / quota sweep retries)
	// rather than failing the purge. The ".txt" sibling is the rendered TTY
	// transcript written next to the raw capture.
	for _, p := range artifactFiles {
		_ = os.Remove(p)
		_ = os.Remove(p + ".txt")
	}
	return nil
}
