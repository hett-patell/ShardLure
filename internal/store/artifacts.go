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
	// Runs the DDL once; every later call is a cheap sync.Once check (no DDL,
	// no writeMu) instead of a CREATE-TABLE on every read/write.
	s.onceArtifacts.Do(func() {
		if _, err := s.execWrite(`
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
)`); err != nil {
			s.errArtifacts = err
			return
		}
		// Indexes for the hot artifact queries. Only UNIQUE(url) existed before,
		// so GetArtifactBySHA (WHERE sha256), CowrieTTYArtifactForSession
		// (WHERE session_id), the bazaar pending NOT-IN (WHERE sha256), and
		// ListRecentArtifacts / ArtifactsForShare (ORDER BY created_at) all
		// full-scanned the table. This function owns the table (lazily created),
		// so the indexes live here rather than in the migration ladder.
		_, s.errArtifacts = s.execWrite(`
CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256);
CREATE INDEX IF NOT EXISTS idx_artifacts_session ON artifacts(session_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_created ON artifacts(created_at);
`)
	})
	return s.errArtifacts
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
	_, err := s.execWrite(`
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
	_, err := s.execWrite(`
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

// ArtifactAggregate is one row of the payload library after collapsing
// duplicate captures by sha256. A single binary frequently arrives via
// many distinct URLs / IPs / sessions (attackers rotate CDNs and
// botnets); the UI is more useful when the operator sees one row per
// unique payload with delivery breadth surfaced as counters.
type ArtifactAggregate struct {
	SHA256       string
	SizeBytes    int64
	Origin       string // last-seen origin (kinds rarely mix per sha)
	Status       string // last-seen status
	FirstTS      time.Time
	LastTS       time.Time
	Occurrences  int    // total rows for this sha
	URLCount     int    // distinct URLs
	IPCount      int    // distinct src IPs
	ActorCount   int    // distinct actor_ids
	SessionCount int    // distinct sessions
	LastURL      string // most-recent URL
	LastSrcIP    string // most-recent src IP
	LastActor    string // most-recent actor_id
	LastSession  string // most-recent session_id
	HasLocal     bool   // at least one row has a local_path
}

// ListArtifactsAggregatedSince returns at most `limit` unique payloads
// (grouped by sha256) ingested since the given time. Rows with empty
// sha256 are skipped (they cannot be deduped meaningfully). Results
// are ordered by most-recent capture timestamp DESC.
// CountDistinctPayloadsSince returns the TRUE number of distinct payloads
// (by sha256) captured in the window — what the payload library should report
// as "N unique". ListArtifactsAggregatedSince applies a row LIMIT, so its
// len() is the page size, not the population; reporting that as the total made
// "1000 unique" appear regardless of how many actually existed. Uses the same
// window + non-empty-sha criteria as the aggregation.
func (s *Store) CountDistinctPayloadsSince(since time.Time) (int, error) {
	if err := s.ensureArtifactsTable(); err != nil {
		return 0, err
	}
	cutoff := since.UTC().Format(time.RFC3339Nano)
	var n int
	err := s.db.QueryRow(`
SELECT COUNT(DISTINCT sha256) FROM artifacts
WHERE COALESCE(ts, created_at) >= ?
  AND sha256 IS NOT NULL AND sha256 != ''`, cutoff).Scan(&n)
	return n, err
}

func (s *Store) ListArtifactsAggregatedSince(since time.Time, limit int) ([]ArtifactAggregate, error) {
	if limit <= 0 {
		limit = 200
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`
WITH win AS (
  SELECT id, ts, src_ip, session_id, actor_id, url, local_path,
         sha256, size_bytes, origin, status,
         COALESCE(ts, created_at) AS effective_ts
  FROM artifacts
  WHERE COALESCE(ts, created_at) >= ?
    AND sha256 IS NOT NULL AND sha256 != ''
),
grp AS (
  SELECT sha256,
    MAX(size_bytes) AS max_size,
    MIN(effective_ts) AS first_ts,
    MAX(effective_ts) AS last_ts,
    COUNT(*) AS occurrences,
    COUNT(DISTINCT url) AS url_count,
    COUNT(DISTINCT NULLIF(src_ip, '')) AS ip_count,
    COUNT(DISTINCT NULLIF(actor_id, '')) AS actor_count,
    COUNT(DISTINCT NULLIF(session_id, '')) AS session_count,
    MAX(CASE WHEN COALESCE(local_path, '') != '' THEN 1 ELSE 0 END) AS has_local
  FROM win
  GROUP BY sha256
),
ranked AS (
  SELECT w.*,
    ROW_NUMBER() OVER (PARTITION BY w.sha256 ORDER BY w.effective_ts DESC) AS rn
  FROM win w
)
SELECT
  g.sha256, g.max_size,
  r.origin, r.status, r.url, r.src_ip, r.actor_id, r.session_id,
  g.first_ts, g.last_ts, g.occurrences,
  g.url_count, g.ip_count, g.actor_count, g.session_count,
  g.has_local
FROM grp g
JOIN ranked r ON r.sha256 = g.sha256 AND r.rn = 1
ORDER BY g.last_ts DESC
LIMIT ?`, since.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ArtifactAggregate
	for rows.Next() {
		var a ArtifactAggregate
		var firstTS, lastTS string
		var hasLocal int
		var lastOrigin, lastStatus, lastURL, lastSrcIP, lastActor, lastSession sql.NullString
		if err := rows.Scan(&a.SHA256, &a.SizeBytes,
			&lastOrigin, &lastStatus, &lastURL, &lastSrcIP, &lastActor, &lastSession,
			&firstTS, &lastTS, &a.Occurrences,
			&a.URLCount, &a.IPCount, &a.ActorCount, &a.SessionCount,
			&hasLocal); err != nil {
			return nil, err
		}
		a.Origin = lastOrigin.String
		a.Status = lastStatus.String
		a.LastURL = lastURL.String
		a.LastSrcIP = lastSrcIP.String
		a.LastActor = lastActor.String
		a.LastSession = lastSession.String
		a.FirstTS, _ = parseTime(firstTS)
		a.LastTS, _ = parseTime(lastTS)
		a.HasLocal = hasLocal == 1
		out = append(out, a)
	}
	return out, rows.Err()
}

// ArtifactsForShare returns artifacts eligible for outbound sharing
// (currently to abuse.ch MalwareBazaar). Eligibility is intentionally
// strict — sharing leaks data publicly so we don't want to be loose:
//
//   - status='fetched'           (we actually have the bytes on disk)
//   - size_bytes > 1024          (skip empty + 1-byte SFTP sentinel
//     files that cowrie produces for some failed transfers)
//   - sha256 IS NOT NULL/empty   (needed for downstream dedup against
//     the bazaar_uploads table)
//   - origin LIKE '%download%'   (exclude cowrie-tty transcripts and
//     quarantine_fetch URLs that didn't resolve to a binary)
//   - created_at >= since        (abuse.ch fair-use: fresh samples only)
//
// Returns newest-first. The caller (share subcommand) bounds the
// result with --limit if needed. Duplicate sha256 across multiple URL
// rows is fine — the bazaar uploader dedupes on sha256 itself.
func (s *Store) ArtifactsForShare(since time.Time) ([]Artifact, error) {
	if err := s.ensureArtifactsTable(); err != nil {
		return nil, err
	}
	cutoff := since.UTC().Format(time.RFC3339Nano)
	rows, err := s.db.Query(`
SELECT id, COALESCE(ts, ''), COALESCE(src_ip, ''), COALESCE(session_id, ''), COALESCE(actor_id, ''),
       url, COALESCE(local_path, ''), COALESCE(sha256, ''), COALESCE(size_bytes, 0),
       origin, status, COALESCE(detail, ''), created_at
FROM artifacts
WHERE status='fetched'
  AND size_bytes > 1024
  AND sha256 IS NOT NULL AND sha256 != ''
  AND origin LIKE '%download%'
  AND COALESCE(created_at, ts) >= ?
ORDER BY COALESCE(created_at, ts) DESC`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Dedup on sha256 — multiple URL rows can point at the same
	// payload after attackers re-host. Keep the most-recent.
	seen := map[string]bool{}
	var out []Artifact
	for rows.Next() {
		var a Artifact
		var ts, created string
		if err := rows.Scan(&a.ID, &ts, &a.SrcIP, &a.SessionID, &a.ActorID, &a.URL, &a.LocalPath,
			&a.SHA256, &a.SizeBytes, &a.Origin, &a.Status, &a.Detail, &created); err != nil {
			return nil, err
		}
		if seen[a.SHA256] {
			continue
		}
		seen[a.SHA256] = true
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
	s.onceTTY.Do(func() {
		_, s.errTTY = s.execWrite(`
CREATE TABLE IF NOT EXISTS cowrie_tty_index (
  sha256     TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  ts         TEXT NOT NULL
)`)
	})
	return s.errTTY
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
	_, err := s.execWrite(`
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
	_, err := s.execWrite(`UPDATE artifacts SET session_id=? WHERE url=? AND (session_id IS NULL OR session_id='')`, sessionID, url)
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
