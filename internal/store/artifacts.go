package store

import (
	"database/sql"
	"errors"
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

// TouchArtifactTS advances an existing artifact row's ts to the given time
// when (and only when) it is newer than the stored value. It exists for the
// capture dedup paths: they skip the expensive copy+hash when the url-key is
// already recorded (the fix for GB/min write amplification), but that skip
// also froze the row's ts at first sight — an actively-redelivered payload
// aged out of the dashboard's "last N days" payload window and undercounted
// occurrences even though attackers were still dropping it.
//
// Read-before-write is deliberate: the capture tick re-examines the same
// recent events every 5s, so the steady-state case is "ts unchanged" and must
// stay a concurrent read — not a writeMu acquisition per artifact per tick.
// The stored ts is parsed and compared in Go because RFC3339Nano trims
// trailing zeros, making lexicographic comparison of timestamps unsafe.
func (s *Store) TouchArtifactTS(url string, ts time.Time) error {
	if err := s.ensureArtifactsTable(); err != nil {
		return err
	}
	if url == "" || ts.IsZero() {
		return nil
	}
	var cur sql.NullString
	err := s.db.QueryRow(`SELECT ts FROM artifacts WHERE url = ?`, url).Scan(&cur)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // no row to touch; caller's dedup check was stale
	}
	if err != nil {
		return err
	}
	if cur.Valid && cur.String != "" {
		if t, perr := time.Parse(time.RFC3339Nano, cur.String); perr == nil && !ts.After(t) {
			return nil // already at least as fresh — the hot path, write-free
		}
	}
	_, err = s.execWrite(`UPDATE artifacts SET ts = ? WHERE url = ?`,
		ts.UTC().Format(time.RFC3339Nano), url)
	return err
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
	Total     int
	Fetched   int
	Capturing int
	Failed    int
	// TotalBytes is the size of the evidence ON DISK: bytes are counted once
	// per distinct local_path, NOT once per artifact row.
	//
	// The dedup is load-bearing, not tidiness. Several rows legitimately point
	// at one file — the capture runner records an artifact per (url, session)
	// sighting while the copy+hash step is memoised by content, so a payload
	// re-fetched by 400 different sessions is 400 rows over one file on disk.
	// Summing per row therefore bills the same bytes repeatedly: measured on the
	// reference deployment at 318,739,859 across 1,195 fetched rows against
	// 299,790,260 actually on disk (747 distinct paths) — a 6.5% overstatement
	// under a label that reads "quarantine size", i.e. a claim about a
	// directory. Grouping by local_path lands within 0.13% of `du -sb`.
	//
	// Rows with an empty local_path contribute nothing: no path means no file to
	// measure, and their size_bytes would be unattributable.
	//
	// Known and accepted shortfall: the rendered ".txt" TTY transcript the
	// capture runner writes NEXT TO each raw capture has no artifact row of its
	// own (purge unlinks it via the path sibling, see MaintenancePurge), so it is
	// invisible here — 402,200 bytes across 385 files on the reference box, i.e.
	// the 0.13% by which this reads under `du -sb evidence`. Stat-ing every
	// sibling on a cached dashboard aggregate is not worth 0.13%; undercounting
	// slightly is also the safer direction for a figure an operator reads as a
	// disk-usage floor.
	TotalBytes int64
	LastTS     time.Time
}

func (s *Store) CaptureSummary() (CaptureSummary, error) {
	var out CaptureSummary
	if err := s.ensureArtifactsTable(); err != nil {
		return out, err
	}
	// Counts stay per-row (they describe capture ATTEMPTS, which is what the
	// tracked/fetched/failed tiles mean); only the byte total is per-file. The
	// subquery is a full scan of a table that holds ~1e3 rows and is already
	// scanned by the surrounding aggregate, so this costs nothing measurable —
	// and CaptureSummary is behind the dashboard TTL cache regardless.
	row := s.db.QueryRow(`
SELECT
  COUNT(1),
  COALESCE(SUM(CASE WHEN status='fetched' THEN 1 ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN status='capturing' THEN 1 ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN status IN ('failed','blocked') THEN 1 ELSE 0 END), 0),
  (SELECT COALESCE(SUM(sz), 0) FROM (
     SELECT MAX(size_bytes) AS sz
     FROM artifacts
     WHERE status='fetched' AND COALESCE(local_path,'') != ''
     GROUP BY local_path
   )),
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
// artifactColumns is the canonical SELECT list for an artifacts row,
// NULL-hardened with COALESCE. Kept in one place so every artifact query
// stays in sync with scanArtifact below — the NULL-hardening commit had to
// apply the identical COALESCE edit to four hand-written copies of this
// list, which is exactly the drift this removes.
const artifactColumns = `id, COALESCE(ts,''), COALESCE(src_ip,''), COALESCE(session_id,''), COALESCE(actor_id,''), url, COALESCE(local_path,''), COALESCE(sha256,''), COALESCE(size_bytes,0), origin, status, COALESCE(detail,''), COALESCE(created_at,'')`

// oneRowScanner abstracts *sql.Row / *sql.Rows for scanArtifact. (Distinct
// from dashboard.go's rowScanner, which is a full rows-iterator interface.)
type oneRowScanner interface {
	Scan(dest ...any) error
}

// scanArtifact reads one artifactColumns row. CreatedAt falls back to TS
// for legacy rows recorded before created_at existed.
func scanArtifact(r oneRowScanner) (Artifact, error) {
	var a Artifact
	var ts, created string
	if err := r.Scan(&a.ID, &ts, &a.SrcIP, &a.SessionID, &a.ActorID, &a.URL, &a.LocalPath,
		&a.SHA256, &a.SizeBytes, &a.Origin, &a.Status, &a.Detail, &created); err != nil {
		return Artifact{}, err
	}
	a.TS, _ = parseTime(ts)
	a.CreatedAt, _ = parseTime(created)
	if a.CreatedAt.IsZero() {
		a.CreatedAt = a.TS
	}
	return a, nil
}

func (s *Store) ListArtifactsSince(since time.Time, limit int) ([]Artifact, error) {
	if limit <= 0 {
		limit = 200
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`
SELECT `+artifactColumns+`
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
		a, err := scanArtifact(rows)
		if err != nil {
			return nil, err
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
	SHA256    string
	SizeBytes int64
	// Origin is the LAST-SEEN origin. Origins DO mix per sha (67 hashes on the
	// reference deployment): the same payload is often recorded once by the
	// cowrie download hook and again by our own quarantine fetch. So this field
	// describes one row, not the payload — never derive shareability from it,
	// use Shareable.
	Origin       string
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
	// Shareable reports whether ANY row in this group could reach the share
	// path — a group-level property, evaluated against the same SharePolicy
	// ArtifactsForShare uses. It exists because the dashboard used to re-derive
	// eligibility in JavaScript from Origin above, and a payload whose newest
	// row was a quarantine_fetch therefore lost its share button even though
	// the CLI would ship it. Two family-identified droppers (Traffmonetizer,
	// Komari) were hidden that way. Still only "may be considered": Vet decides.
	Shareable bool
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

// pol narrows which rows count toward the group's Shareable flag. Pass the
// same policy the share path uses (bazaar.MinSampleBytes / ShareableOrigins),
// or the zero value to mark nothing shareable.
func (s *Store) ListArtifactsAggregatedSince(since time.Time, limit int, pol SharePolicy) ([]ArtifactAggregate, error) {
	if limit <= 0 {
		limit = 200
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return nil, err
	}
	// shareable is computed per GROUP, not from the newest row: "can this
	// payload be shared" is a property of the payload, and the same sha is
	// commonly recorded by both the cowrie hook and our quarantine fetch.
	// Deriving it from the newest row (as the dashboard's JS used to) drops a
	// payload whose latest sighting happened to be the other origin.
	shareable := "0"
	args := []interface{}{since.UTC().Format(time.RFC3339Nano)}
	if len(pol.Origins) > 0 {
		ph := make([]string, len(pol.Origins))
		for i, o := range pol.Origins {
			ph[i] = "?"
			args = append(args, o)
		}
		args = append(args, pol.MinBytes)
		shareable = `MAX(CASE WHEN status='fetched'
                          AND origin IN (` + strings.Join(ph, ",") + `)
                          AND size_bytes >= ?
                          AND COALESCE(local_path,'') != ''
                     THEN 1 ELSE 0 END)`
	}
	args = append(args, limit)
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
    MAX(CASE WHEN COALESCE(local_path, '') != '' THEN 1 ELSE 0 END) AS has_local,
    `+shareable+` AS shareable
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
  g.has_local, g.shareable
FROM grp g
JOIN ranked r ON r.sha256 = g.sha256 AND r.rn = 1
ORDER BY g.last_ts DESC
LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ArtifactAggregate
	for rows.Next() {
		var a ArtifactAggregate
		var firstTS, lastTS string
		var hasLocal, shareableRow int
		var lastOrigin, lastStatus, lastURL, lastSrcIP, lastActor, lastSession sql.NullString
		if err := rows.Scan(&a.SHA256, &a.SizeBytes,
			&lastOrigin, &lastStatus, &lastURL, &lastSrcIP, &lastActor, &lastSession,
			&firstTS, &lastTS, &a.Occurrences,
			&a.URLCount, &a.IPCount, &a.ActorCount, &a.SessionCount,
			&hasLocal, &shareableRow); err != nil {
			return nil, err
		}
		a.Shareable = shareableRow == 1
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

// SharePolicy is the candidate-selection narrowing for ArtifactsForShare.
// The values come from the destination's own gate (bazaar.MinSampleBytes,
// bazaar.ShareableOrigins) rather than being restated here, so this query can
// never be stricter than the policy that ultimately judges the sample.
//
// It is a parameter and not a constant because store must not import
// intel/bazaar — the interfaces in the intel packages exist to keep that
// dependency pointing one way (see the UploadRecorder comment).
type SharePolicy struct {
	// MinBytes is inclusive: a sample of exactly MinBytes is selected.
	MinBytes int64
	// Origins is the allowlist of provenances. Empty means "no origin
	// restriction", which is never what the share path wants — the caller
	// passes bazaar.ShareableOrigins().
	Origins []string
}

// ArtifactsForShare returns artifacts eligible for outbound sharing
// (currently to abuse.ch MalwareBazaar). Eligibility is intentionally
// strict — sharing leaks data publicly so we don't want to be loose:
//
//   - status='fetched'           (we actually have the bytes on disk)
//   - size_bytes >= pol.MinBytes (skip empty + 1-byte SFTP sentinel
//     files that cowrie produces for some failed transfers)
//   - sha256 IS NOT NULL/empty   (needed for downstream dedup against
//     the bazaar_uploads table)
//   - origin IN pol.Origins      (excludes cowrie-tty transcripts)
//   - created_at >= since        (abuse.ch fair-use: fresh samples only)
//
// This is candidate SELECTION, not policy. It exists to keep the row count
// and the disk IO down; bazaar.Vet is what actually decides, and it re-checks
// size, origin, freshness and content on every candidate. So the rule here is
// that this query may never be TIGHTER than Vet — a sample rejected before Vet
// sees it is rejected by an invisible second policy with no stated reason.
//
// It was tighter, twice, and both hid real samples on the reference
// deployment: `size_bytes > 1024` against Vet's 64 B floor (13 payloads), and
// `origin LIKE '%download%'`, which silently excludes "quarantine_fetch" —
// the capture runner's own fetches (10 payloads, 18.6 MB, all unshared).
//
// Returns newest-first. Duplicate sha256 across multiple URL rows is fine —
// the bazaar uploader dedupes on sha256 itself.
func (s *Store) ArtifactsForShare(since time.Time, pol SharePolicy) ([]Artifact, error) {
	if err := s.ensureArtifactsTable(); err != nil {
		return nil, err
	}
	cutoff := since.UTC().Format(time.RFC3339Nano)
	args := []interface{}{pol.MinBytes}
	// Origins is interpolated as bound placeholders, never as literal text.
	originClause := ""
	if len(pol.Origins) > 0 {
		ph := make([]string, len(pol.Origins))
		for i, o := range pol.Origins {
			ph[i] = "?"
			args = append(args, o)
		}
		originClause = "\n  AND origin IN (" + strings.Join(ph, ",") + ")"
	}
	args = append(args, cutoff)
	rows, err := s.db.Query(`
SELECT `+artifactColumns+`
FROM artifacts
WHERE status='fetched'
  AND size_bytes >= ?
  AND sha256 IS NOT NULL AND sha256 != ''`+originClause+`
  AND COALESCE(created_at, ts) >= ?
ORDER BY COALESCE(created_at, ts) DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Dedup on sha256 — multiple URL rows can point at the same
	// payload after attackers re-host. Keep the most-recent.
	seen := map[string]bool{}
	var out []Artifact
	for rows.Next() {
		a, err := scanArtifact(rows)
		if err != nil {
			return nil, err
		}
		if seen[a.SHA256] {
			continue
		}
		seen[a.SHA256] = true
		out = append(out, a)
	}
	return out, rows.Err()
}

// PayloadShareable reports whether ANY artifact row for this sha256 satisfies
// the share policy — the same group-level question ListArtifactsAggregatedSince
// answers per page, for callers that hold a single hash (the payload detail
// modal, which resolves its row via GetArtifactBySHA and would otherwise judge
// shareability from the newest sighting alone).
//
// Unwindowed on purpose: this asks "could this payload be shared at all", and
// bazaar.Vet applies the freshness ceiling. A zero-value policy (no Origins)
// answers false rather than "everything", matching the aggregate.
func (s *Store) PayloadShareable(sha256 string, pol SharePolicy) (bool, error) {
	if sha256 == "" || len(pol.Origins) == 0 {
		return false, nil
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return false, err
	}
	args := []interface{}{sha256, pol.MinBytes}
	ph := make([]string, len(pol.Origins))
	for i, o := range pol.Origins {
		ph[i] = "?"
		args = append(args, o)
	}
	var n int
	err := s.db.QueryRow(`
SELECT COUNT(*) FROM artifacts
WHERE sha256=?
  AND status='fetched'
  AND size_bytes >= ?
  AND COALESCE(local_path,'') != ''
  AND origin IN (`+strings.Join(ph, ",")+`)`, args...).Scan(&n)
	return n > 0, err
}

// GetArtifactBySHA returns the most recent artifact matching the SHA-256.
// Multiple rows can share a hash if attackers re-host the same payload
// at different URLs; we return the most recently captured row.
func (s *Store) GetArtifactBySHA(sha256 string) (*Artifact, error) {
	if err := s.ensureArtifactsTable(); err != nil {
		return nil, err
	}
	row := s.db.QueryRow(`
SELECT `+artifactColumns+`
FROM artifacts
WHERE sha256=?
ORDER BY COALESCE(ts, created_at) DESC
LIMIT 1`, sha256)
	a, err := scanArtifact(row)
	if err != nil {
		return nil, err
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
SELECT `+artifactColumns+`
FROM artifacts
WHERE session_id=? AND origin='cowrie_tty'
ORDER BY COALESCE(ts, created_at) DESC
LIMIT 1`, sessionID)
	a, err := scanArtifact(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
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
SELECT `+artifactColumns+`
FROM artifacts
ORDER BY created_at DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Artifact
	for rows.Next() {
		a, err := scanArtifact(rows)
		if err != nil {
			return nil, err
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

// DueArtifactCaptures returns up to limit artifact URLs that are eligible for
// a capture attempt: status is "capturing" with no in-progress lease (the
// previous attempt crashed or timed out) OR status is retryable ("failed")
// with attempt_count < maxAttempts and next_attempt_at in the past.
// Terminal rows ("fetched", "blocked") are excluded by the backfill in
// migration v17 (attempt_count >= 1).
func (s *Store) DueArtifactCaptures(now time.Time, limit, maxAttempts int) ([]string, error) {
	if err := s.ensureArtifactsTable(); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`
SELECT url FROM artifacts
WHERE status IN ('capturing','failed')
  AND attempt_count < ?
  AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
ORDER BY created_at ASC
LIMIT ?`, maxAttempts, now.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var urls []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		urls = append(urls, u)
	}
	return urls, rows.Err()
}

// ClaimArtifactCapture marks a capturing artifact with a lease expiry so the
// worker can detect stale claims. Succeeds only if the row still matches
// expectedAttempt (optimistic concurrency — prevents two workers from
// claiming the same artifact). Returns store.ErrClaimStale if the attempt
// count moved underneath us.
func (s *Store) ClaimArtifactCapture(url string, now, leaseUntil time.Time, expectedAttempt int) error {
	if err := s.ensureArtifactsTable(); err != nil {
		return err
	}
	res, err := s.execWrite(`
UPDATE artifacts
SET status='capturing', next_attempt_at=?
WHERE url=? AND attempt_count=?`,
		leaseUntil.UTC().Format(time.RFC3339Nano), url, expectedAttempt)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrClaimStale
	}
	return nil
}

// ErrClaimStale is returned by ClaimArtifactCapture when another worker
// already claimed or completed the artifact.
var ErrClaimStale = errors.New("artifact claim stale")

// CompleteArtifactCapture records the outcome of a capture attempt. On
// success the status is set to "fetched" (terminal). On failure the
// attempt_count is bumped and next_attempt_at is set for exponential backoff;
// if the attempt budget is exhausted the status becomes "failed_permanently"
// (terminal). Returns ErrClaimStale if the row's attempt_count moved.
func (s *Store) CompleteArtifactCapture(url string, attempt int, status, detail, localPath, sha256 string, sizeBytes int64, nextAttempt *time.Time) error {
	if err := s.ensureArtifactsTable(); err != nil {
		return err
	}
	var nextTS sql.NullString
	if nextAttempt != nil {
		nextTS.String = nextAttempt.UTC().Format(time.RFC3339Nano)
		nextTS.Valid = true
	}
	if status == "fetched" {
		// Terminal success: stamp final fields, clear lease.
		res, err := s.execWrite(`
UPDATE artifacts
SET status='fetched', detail=?, local_path=?, sha256=?, size_bytes=?,
    attempt_count=?, next_attempt_at=NULL
WHERE url=? AND attempt_count=?`,
			detail, localPath, sha256, sizeBytes, attempt, url, attempt-1)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrClaimStale
		}
		return nil
	}
	// Retryable failure: bump attempt, schedule next retry.
	res, err := s.execWrite(`
UPDATE artifacts
SET status='failed', detail=?, attempt_count=?, next_attempt_at=?
WHERE url=? AND attempt_count=?`,
		detail, attempt, nextTS, url, attempt-1)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrClaimStale
	}
	return nil
}

// ArtifactAttemptCount reads the attempt_count for a single artifact URL.
// Used by the worker to know the current attempt before claiming.
func (s *Store) ArtifactAttemptCount(url string, count *int) error {
	if err := s.ensureArtifactsTable(); err != nil {
		return err
	}
	return s.db.QueryRow(`SELECT attempt_count FROM artifacts WHERE url=?`, url).Scan(count)
}
