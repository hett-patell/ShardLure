package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
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
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
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
CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor_id);
CREATE INDEX IF NOT EXISTS idx_events_raw ON events(raw);
CREATE INDEX IF NOT EXISTS idx_events_identity ON events(source, kind, ts, src_ip, session_id, username, command);

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
`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	if err := s.ensureLegacyColumns(); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (1, ?)`, time.Now().UTC().Format(time.RFC3339Nano))
	return err
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
	for name, ddl := range map[string]string{
		"src_port":  `ALTER TABLE events ADD COLUMN src_port INTEGER DEFAULT 0`,
		"password":  `ALTER TABLE events ADD COLUMN password TEXT`,
		"session_id": `ALTER TABLE events ADD COLUMN session_id TEXT`,
		"hassh":     `ALTER TABLE events ADD COLUMN hassh TEXT`,
		"ssh_client": `ALTER TABLE events ADD COLUMN ssh_client TEXT`,
		"ja4":       `ALTER TABLE events ADD COLUMN ja4 TEXT`,
		"command":   `ALTER TABLE events ADD COLUMN command TEXT`,
		"sha256":    `ALTER TABLE events ADD COLUMN sha256 TEXT`,
		"filename":  `ALTER TABLE events ADD COLUMN filename TEXT`,
		"raw":       `ALTER TABLE events ADD COLUMN raw TEXT`,
		"actor_id":  `ALTER TABLE events ADD COLUMN actor_id TEXT`,
	} {
		if !cols[name] {
			if _, err := s.db.Exec(ddl); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) InsertEvent(e *models.Event) error {
	_, err := s.db.Exec(`
INSERT INTO events (ts, source, kind, src_ip, src_port, username, password, session_id, hassh, ssh_client, ja4, command, sha256, filename, raw, actor_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TS.UTC().Format(time.RFC3339Nano), e.Source, e.Kind, e.SrcIP, e.SrcPort,
		e.Username, e.Password, e.SessionID, e.HASSH, e.SSHClient, e.JA4,
		e.Command, e.SHA256, e.Filename, e.Raw, e.ActorID)
	return err
}

func (s *Store) UpsertActor(a *models.Actor) error {
	_, err := s.db.Exec(`
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
	_, err := s.db.Exec(`
INSERT INTO actor_ips (actor_id, ip, first_seen, last_seen, count) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(actor_id, ip) DO UPDATE SET
  first_seen=CASE WHEN excluded.first_seen < first_seen THEN excluded.first_seen ELSE first_seen END,
  last_seen=CASE WHEN excluded.last_seen > last_seen THEN excluded.last_seen ELSE last_seen END,
  count=excluded.count`,
		actorID, ip, firstSeen.UTC().Format(time.RFC3339Nano), lastSeen.UTC().Format(time.RFC3339Nano), count)
	return err
}

func (s *Store) UpsertActorUser(actorID, user string, count int) error {
	_, err := s.db.Exec(`
INSERT INTO actor_users (actor_id, username, count) VALUES (?, ?, ?)
ON CONFLICT(actor_id, username) DO UPDATE SET count=excluded.count`,
		actorID, user, count)
	return err
}

func (s *Store) ListActors(limit int) ([]models.Actor, error) {
	q := `SELECT id, source, primary_ip, playbook, intent, confidence, first_seen, last_seen, event_count, unique_users, attempts_per_hour, hassh, ssh_client, username_hash, campaigns, probe_score, notes FROM actors ORDER BY last_seen DESC`
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
		var fs, ls string
		if err := rows.Scan(&a.ID, &a.Source, &a.PrimaryIP, &a.Playbook, &a.Intent, &a.Confidence,
			&fs, &ls, &a.EventCount, &a.UniqueUsers, &a.AttemptsPerHour, &a.HASSH, &a.SSHClient,
			&a.UsernameHash, &a.Campaigns, &a.ProbeScore, &a.Notes); err != nil {
			return nil, err
		}
		a.FirstSeen, _ = time.Parse(time.RFC3339Nano, fs)
		a.LastSeen, _ = time.Parse(time.RFC3339Nano, ls)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetActor(id string) (*models.Actor, error) {
	row := s.db.QueryRow(`
SELECT id, source, primary_ip, playbook, intent, confidence, first_seen, last_seen, event_count, unique_users, attempts_per_hour, hassh, ssh_client, username_hash, campaigns, probe_score, notes
FROM actors WHERE id=?`, id)
	var a models.Actor
	var fs, ls string
	if err := row.Scan(&a.ID, &a.Source, &a.PrimaryIP, &a.Playbook, &a.Intent, &a.Confidence,
		&fs, &ls, &a.EventCount, &a.UniqueUsers, &a.AttemptsPerHour, &a.HASSH, &a.SSHClient,
		&a.UsernameHash, &a.Campaigns, &a.ProbeScore, &a.Notes); err != nil {
		return nil, err
	}
	a.FirstSeen, _ = time.Parse(time.RFC3339Nano, fs)
	a.LastSeen, _ = time.Parse(time.RFC3339Nano, ls)
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
		e.TS, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) GetActorByPrimaryIP(ip string) (*models.Actor, error) {
	row := s.db.QueryRow(`
SELECT id, source, primary_ip, playbook, intent, confidence, first_seen, last_seen, event_count, unique_users, attempts_per_hour, hassh, ssh_client, username_hash, campaigns, probe_score, notes
FROM actors WHERE primary_ip=? ORDER BY last_seen DESC LIMIT 1`, ip)
	var a models.Actor
	var fs, ls string
	if err := row.Scan(&a.ID, &a.Source, &a.PrimaryIP, &a.Playbook, &a.Intent, &a.Confidence,
		&fs, &ls, &a.EventCount, &a.UniqueUsers, &a.AttemptsPerHour, &a.HASSH, &a.SSHClient,
		&a.UsernameHash, &a.Campaigns, &a.ProbeScore, &a.Notes); err != nil {
		return nil, err
	}
	a.FirstSeen, _ = time.Parse(time.RFC3339Nano, fs)
	a.LastSeen, _ = time.Parse(time.RFC3339Nano, ls)
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

func (s *Store) ClearAll() error {
	for _, t := range []string{"events", "actors", "actor_ips", "actor_users"} {
		if _, err := s.db.Exec(`DELETE FROM ` + t); err != nil {
			return err
		}
	}
	return nil
}
