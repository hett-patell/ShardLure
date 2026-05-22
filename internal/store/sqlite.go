package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
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
		if _, err := s.db.Exec(`
UPDATE events
SET command = NULL
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
	return upsertActor(s.db, a)
}

func upsertActor(db sqlExecer, a *models.Actor) error {
	_, err := db.Exec(`
INSERT INTO actors (id, source, primary_ip, playbook, intent, confidence, first_seen, last_seen, event_count, unique_users, attempts_per_hour, hassh, ssh_client, username_hash, campaigns, probe_score, notes)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  primary_ip=excluded.primary_ip, playbook=excluded.playbook, intent=excluded.intent,
  confidence=excluded.confidence, last_seen=excluded.last_seen, event_count=excluded.event_count,
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
