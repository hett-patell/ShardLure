package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
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
  ja4 TEXT,
  command TEXT,
  sha256 TEXT,
  filename TEXT,
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
  updated_at TEXT NOT NULL,
  PRIMARY KEY (source, path)
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
		const postIdx = `
CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor_id);
CREATE INDEX IF NOT EXISTS idx_events_identity ON events(source, kind, ts, src_ip, session_id, username, command);
`
		if _, err := s.db.Exec(postIdx); err != nil {
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
	return nil
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
		{"ja4", `ALTER TABLE events ADD COLUMN ja4 TEXT`},
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
INSERT INTO events (ts, source, kind, src_ip, src_port, username, password, session_id, hassh, ssh_client, ja4, command, sha256, filename, raw, actor_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TS.UTC().Format(time.RFC3339Nano), e.Source, e.Kind, e.SrcIP, e.SrcPort,
		e.Username, e.Password, e.SessionID, e.HASSH, e.SSHClient, e.JA4,
		e.Command, e.SHA256, e.Filename, e.Raw, e.ActorID)
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

func (s *Store) UpsertActorIP(actorID, ip string, firstSeen, lastSeen time.Time, count int) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return upsertActorIP(s.db, actorID, ip, firstSeen, lastSeen, count)
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

func (s *Store) UpsertActorUser(actorID, user string, count int) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return upsertActorUser(s.db, actorID, user, count)
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

func (s *Store) ListActors(limit int) ([]models.Actor, error) {
	q := `SELECT ` + actorColumns + ` FROM actors ORDER BY last_seen DESC`
	var rows *sql.Rows
	var err error
	if limit > 0 {
		rows, err = s.db.Query(q+" LIMIT ?", limit)
	} else {
		rows, err = s.db.Query(q)
	}
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

// TopActorsByEvents returns actors ordered by total event_count — the actual
// "top actors" by volume. The globe's actor list is ordered by last_seen (for
// the live globe arcs), so a client-side slice of it showed recent actors, not
// the highest-volume ones (the 64k-event top attacker was absent because it
// wasn't recently active).
func (s *Store) TopActorsByEvents(limit int) ([]models.Actor, error) {
	if limit <= 0 {
		limit = 14
	}
	rows, err := s.db.Query(`SELECT `+actorColumns+`
FROM actors ORDER BY event_count DESC LIMIT ?`, limit)
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

// TopActorsByRate returns the actors with the highest attempts_per_hour. The
// Brute-Force Radar needs the most AGGRESSIVE actors, but ListActors orders by
// last_seen (most recent), so the radar — fed from that recent slice — was
// missing the true high-rate attackers (e.g. showing 171/h when the real top
// was 3113/h). This orders by rate so the radar reflects the actual peak.
func (s *Store) TopActorsByRate(limit int) ([]models.Actor, error) {
	if limit <= 0 {
		limit = 8
	}
	rows, err := s.db.Query(`SELECT `+actorColumns+`
FROM actors WHERE attempts_per_hour > 0
ORDER BY attempts_per_hour DESC LIMIT ?`, limit)
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
// ja4, sha256, filename) are left at their zero value. If you need a
// full event row use EventsByIP or EventsBySource instead.
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
	// Serialize the purge transaction with all other writers (ensure* calls
	// above already took/released writeMu via execWrite; lock here, not earlier,
	// because writeMu is not reentrant).
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Order: children first so foreign-key or application-level
	// references don't dangle. Each DELETE is bounded by the
	// cutoff; none of these scan the full table.

	// 1. Enrichment cache — references IPs that appear in events.
	//    Column is fetched_at (see enrichment.go); the earlier
	//    queried_at name was wrong and made this DELETE fail every
	//    24h on the live system.
	if _, err := tx.Exec(`DELETE FROM ip_enrichment WHERE fetched_at < ?`, cutoff); err != nil {
		return err
	}

	// 2. TTY transcript index — references sessions from events.
	if _, err := tx.Exec(`DELETE FROM cowrie_tty_index WHERE ts < ?`, cutoff); err != nil {
		return err
	}

	// 3. Artifact rows — independent time-based cutoff.
	if _, err := tx.Exec(`DELETE FROM artifacts WHERE COALESCE(ts, created_at) < ?`, cutoff); err != nil {
		return err
	}

	// 4. Events — the root table and typically the largest.
	if _, err := tx.Exec(`DELETE FROM events WHERE ts < ?`, cutoff); err != nil {
		return err
	}

	return tx.Commit()
}
