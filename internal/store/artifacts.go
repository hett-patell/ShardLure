package store

import (
	"database/sql"
	"strings"
	"time"
)

// Artifact is a quarantined payload linked to attacker activity.
type Artifact struct {
	ID        int64
	TS        time.Time
	CreatedAt time.Time
	SrcIP     string
	SessionID string
	ActorID   string
	URL       string
	LocalPath string
	SHA256    string
	SizeBytes int64
	Origin    string
	Status    string
	Detail    string
}

func (s *Store) ensureArtifactsTable() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS artifacts (
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
)`)
	return err
}

func (s *Store) ArtifactURLRecorded(url string) (bool, error) {
	if err := s.ensureArtifactsTable(); err != nil {
		return false, err
	}
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM artifacts WHERE url=?`, url).Scan(&n)
	return n > 0, err
}

func (s *Store) UpsertArtifact(a Artifact) error {
	if err := s.ensureArtifactsTable(); err != nil {
		return err
	}
	ts := a.TS.UTC().Format(time.RFC3339Nano)
	if a.TS.IsZero() {
		ts = time.Now().UTC().Format(time.RFC3339Nano)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(`
INSERT INTO artifacts (ts, src_ip, session_id, actor_id, url, local_path, sha256, size_bytes, origin, status, detail, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(url) DO UPDATE SET
  ts=excluded.ts,
  src_ip=excluded.src_ip,
  session_id=excluded.session_id,
  actor_id=excluded.actor_id,
  local_path=excluded.local_path,
  sha256=excluded.sha256,
  size_bytes=excluded.size_bytes,
  origin=excluded.origin,
  status=excluded.status,
  detail=excluded.detail,
  created_at=artifacts.created_at`,
		ts, a.SrcIP, a.SessionID, a.ActorID, a.URL, a.LocalPath, a.SHA256, a.SizeBytes,
		a.Origin, a.Status, a.Detail, now)
	return err
}

// RecordArtifact inserts a new artifact row (no update on conflict).
func (s *Store) RecordArtifact(a Artifact) error {
	if err := s.ensureArtifactsTable(); err != nil {
		return err
	}
	ts := a.TS.UTC().Format(time.RFC3339Nano)
	if a.TS.IsZero() {
		ts = time.Now().UTC().Format(time.RFC3339Nano)
	}
	_, err := s.db.Exec(`
INSERT OR IGNORE INTO artifacts (ts, src_ip, session_id, actor_id, url, local_path, sha256, size_bytes, origin, status, detail, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, a.SrcIP, a.SessionID, a.ActorID, a.URL, a.LocalPath, a.SHA256, a.SizeBytes,
		a.Origin, a.Status, a.Detail, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// CaptureSummary aggregates artifact capture state for the dashboard.
type CaptureSummary struct {
	Total      int
	Fetched    int
	Capturing  int
	Failed     int
	TotalBytes int64
	LastTS     time.Time
}

func (s *Store) CaptureSummary() (CaptureSummary, error) {
	var out CaptureSummary
	if err := s.ensureArtifactsTable(); err != nil {
		return out, err
	}
	row := s.db.QueryRow(`
SELECT
  COUNT(1),
  COALESCE(SUM(CASE WHEN status='fetched' THEN 1 ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN status='capturing' THEN 1 ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN status IN ('failed','blocked') THEN 1 ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN status='fetched' THEN size_bytes ELSE 0 END), 0),
  COALESCE(MAX(created_at), '')
FROM artifacts`)
	var last string
	if err := row.Scan(&out.Total, &out.Fetched, &out.Capturing, &out.Failed, &out.TotalBytes, &last); err != nil {
		return out, err
	}
	if last != "" {
		out.LastTS, _ = parseTime(last)
	}
	return out, nil
}

// ListArtifactsSince returns artifacts whose creation/touch timestamp
// falls within the window. limit caps the rows; pass 0 for default.
// Used by the payload library view to scope the UI to a meaningful
// recent slice rather than the entire artifact history.
func (s *Store) ListArtifactsSince(since time.Time, limit int) ([]Artifact, error) {
	if limit <= 0 {
		limit = 200
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`
SELECT id, ts, src_ip, session_id, actor_id, url, local_path, sha256, size_bytes, origin, status, detail, created_at
FROM artifacts
WHERE COALESCE(ts, created_at) >= ?
ORDER BY COALESCE(ts, created_at) DESC
LIMIT ?`, since.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Artifact
	for rows.Next() {
		var a Artifact
		var ts, created string
		if err := rows.Scan(&a.ID, &ts, &a.SrcIP, &a.SessionID, &a.ActorID, &a.URL, &a.LocalPath,
			&a.SHA256, &a.SizeBytes, &a.Origin, &a.Status, &a.Detail, &created); err != nil {
			return nil, err
		}
		a.TS, _ = parseTime(ts)
		a.CreatedAt, _ = parseTime(created)
		if a.CreatedAt.IsZero() {
			a.CreatedAt = a.TS
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetArtifactBySHA returns the most recent artifact matching the SHA-256.
// Multiple rows can share a hash if attackers re-host the same payload
// at different URLs; we return the most recently captured row.
func (s *Store) GetArtifactBySHA(sha256 string) (*Artifact, error) {
	if err := s.ensureArtifactsTable(); err != nil {
		return nil, err
	}
	row := s.db.QueryRow(`
SELECT id, ts, src_ip, session_id, actor_id, url, local_path, sha256, size_bytes, origin, status, detail, created_at
FROM artifacts
WHERE sha256=?
ORDER BY COALESCE(ts, created_at) DESC
LIMIT 1`, sha256)
	var a Artifact
	var ts, created string
	if err := row.Scan(&a.ID, &ts, &a.SrcIP, &a.SessionID, &a.ActorID, &a.URL, &a.LocalPath,
		&a.SHA256, &a.SizeBytes, &a.Origin, &a.Status, &a.Detail, &created); err != nil {
		return nil, err
	}
	a.TS, _ = parseTime(ts)
	a.CreatedAt, _ = parseTime(created)
	if a.CreatedAt.IsZero() {
		a.CreatedAt = a.TS
	}
	return &a, nil
}

// ensureCowrieTTYIndex creates the small lookup table that binds a
// closed cowrie ttylog (named by its sha256) to the session it
// belonged to. The table is populated incrementally by the cowrie
// ingest from `cowrie.log.closed` events; the capture pass uses it to
// stamp session_id onto the resulting artifact row.
func (s *Store) ensureCowrieTTYIndex() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS cowrie_tty_index (
  sha256     TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  ts         TEXT NOT NULL
)`)
	return err
}

// RecordCowrieTTYBinding inserts (or updates) a sha->session mapping
// for a closed Cowrie ttylog. Safe to call repeatedly with the same
// inputs.
func (s *Store) RecordCowrieTTYBinding(sha, sessionID string, ts time.Time) error {
	sha = strings.TrimSpace(strings.ToLower(sha))
	sessionID = strings.TrimSpace(sessionID)
	if sha == "" || sessionID == "" {
		return nil
	}
	if err := s.ensureCowrieTTYIndex(); err != nil {
		return err
	}
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	_, err := s.db.Exec(`
INSERT INTO cowrie_tty_index (sha256, session_id, ts)
VALUES (?, ?, ?)
ON CONFLICT(sha256) DO UPDATE SET
  session_id=excluded.session_id,
  ts=excluded.ts`,
		sha, sessionID, ts.UTC().Format(time.RFC3339Nano))
	return err
}

// SessionIDForCowrieTTYShasum returns the session id that owns the
// given cowrie ttylog sha256, or ("", nil) if no binding has been
// recorded yet.
func (s *Store) SessionIDForCowrieTTYShasum(sha string) (string, error) {
	sha = strings.TrimSpace(strings.ToLower(sha))
	if sha == "" {
		return "", nil
	}
	if err := s.ensureCowrieTTYIndex(); err != nil {
		return "", err
	}
	var sid string
	err := s.db.QueryRow(`SELECT session_id FROM cowrie_tty_index WHERE sha256=?`, sha).Scan(&sid)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return sid, err
}

// SetArtifactSessionByURL backfills the session_id of an existing
// artifact row by its (unique) URL key. Used by the cowrie TTY sync
// pass to bind a captured ttylog artifact to the session it belonged
// to, once we can match the shasum against an ingested cowrie event.
func (s *Store) SetArtifactSessionByURL(url, sessionID string) error {
	if url == "" || sessionID == "" {
		return nil
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE artifacts SET session_id=? WHERE url=? AND (session_id IS NULL OR session_id='')`, sessionID, url)
	return err
}

// CowrieTTYArtifactForSession returns the most recent cowrie-tty
// artifact attached to a session, if any. The intel session view uses
// this to surface the decoded transcript next to the event timeline.
func (s *Store) CowrieTTYArtifactForSession(sessionID string) (*Artifact, error) {
	if sessionID == "" {
		return nil, nil
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return nil, err
	}
	row := s.db.QueryRow(`
SELECT id, ts, src_ip, session_id, actor_id, url, local_path, sha256, size_bytes, origin, status, detail, created_at
FROM artifacts
WHERE session_id=? AND origin='cowrie_tty'
ORDER BY COALESCE(ts, created_at) DESC
LIMIT 1`, sessionID)
	var a Artifact
	var ts, created string
	if err := row.Scan(&a.ID, &ts, &a.SrcIP, &a.SessionID, &a.ActorID, &a.URL, &a.LocalPath,
		&a.SHA256, &a.SizeBytes, &a.Origin, &a.Status, &a.Detail, &created); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	a.TS, _ = parseTime(ts)
	a.CreatedAt, _ = parseTime(created)
	if a.CreatedAt.IsZero() {
		a.CreatedAt = a.TS
	}
	return &a, nil
}

func (s *Store) ListRecentArtifacts(limit int) ([]Artifact, error) {
	if limit <= 0 {
		limit = 40
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`
SELECT id, ts, src_ip, session_id, actor_id, url, local_path, sha256, size_bytes, origin, status, detail, created_at
FROM artifacts
ORDER BY created_at DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Artifact
	for rows.Next() {
		var a Artifact
		var ts, created string
		if err := rows.Scan(&a.ID, &ts, &a.SrcIP, &a.SessionID, &a.ActorID, &a.URL, &a.LocalPath,
			&a.SHA256, &a.SizeBytes, &a.Origin, &a.Status, &a.Detail, &created); err != nil {
			return nil, err
		}
		a.TS, _ = parseTime(ts)
		a.CreatedAt, _ = parseTime(created)
		if a.CreatedAt.IsZero() {
			a.CreatedAt = a.TS
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) RecentCommandEvents(limit int) ([]*EventRow, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.Query(`
SELECT id, ts, src_ip, session_id, actor_id, command
FROM events
WHERE kind='command' AND command != ''
ORDER BY ts DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEventRows(rows)
}

func (s *Store) RecentFileDownloadEvents(limit int) ([]*EventRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`
SELECT id, ts, src_ip, session_id, actor_id, command, filename, sha256
FROM events
WHERE kind='file_download'
ORDER BY ts DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	return scanEventRowsWithFile(rows)
}

// EventRow is a slim event view for capture processing.
type EventRow struct {
	ID        int64
	TS        time.Time
	SrcIP     string
	SessionID string
	ActorID   string
	Command   string
	Filename  string
	SHA256    string
}

// scanEventRows uses the package-level rowScanner interface declared
// in dashboard.go.
func scanEventRows(rows rowScanner) ([]*EventRow, error) {
	defer rows.Close()
	var out []*EventRow
	for rows.Next() {
		var e EventRow
		var ts, cmd string
		if err := rows.Scan(&e.ID, &ts, &e.SrcIP, &e.SessionID, &e.ActorID, &cmd); err != nil {
			return nil, err
		}
		e.TS, _ = parseTime(ts)
		e.Command = cmd
		out = append(out, &e)
	}
	return out, rows.Err()
}

// scanEventRowsWithFile is the file_download variant: same columns
// as scanEventRows plus filename and sha256. Kept separate (rather
// than overloaded with optional pointers) because database/sql Scan
// needs the exact column count.
func scanEventRowsWithFile(rows rowScanner) ([]*EventRow, error) {
	defer rows.Close()
	var out []*EventRow
	for rows.Next() {
		var e EventRow
		var ts, cmd, fn, sum string
		if err := rows.Scan(&e.ID, &ts, &e.SrcIP, &e.SessionID, &e.ActorID, &cmd, &fn, &sum); err != nil {
			return nil, err
		}
		e.TS, _ = parseTime(ts)
		e.Command = cmd
		e.Filename = fn
		e.SHA256 = sum
		out = append(out, &e)
	}
	return out, rows.Err()
}
