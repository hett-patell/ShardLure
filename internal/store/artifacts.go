package store

import (
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
		out.LastTS, _ = time.Parse(time.RFC3339Nano, last)
	}
	return out, nil
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
		a.TS, _ = time.Parse(time.RFC3339Nano, ts)
		a.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
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
	defer rows.Close()
	var out []*EventRow
	for rows.Next() {
		var e EventRow
		var ts, cmd, fn, sum string
		if err := rows.Scan(&e.ID, &ts, &e.SrcIP, &e.SessionID, &e.ActorID, &cmd, &fn, &sum); err != nil {
			return nil, err
		}
		e.TS, _ = time.Parse(time.RFC3339Nano, ts)
		e.Command = cmd
		e.Filename = fn
		e.SHA256 = sum
		out = append(out, &e)
	}
	return out, rows.Err()
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

func scanEventRows(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close() error
}) ([]*EventRow, error) {
	defer rows.Close()
	var out []*EventRow
	for rows.Next() {
		var e EventRow
		var ts, cmd string
		if err := rows.Scan(&e.ID, &ts, &e.SrcIP, &e.SessionID, &e.ActorID, &cmd); err != nil {
			return nil, err
		}
		e.TS, _ = time.Parse(time.RFC3339Nano, ts)
		e.Command = cmd
		out = append(out, &e)
	}
	return out, rows.Err()
}
