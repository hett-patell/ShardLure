package store

import (
	"database/sql"
	"log"
	"time"
)

// URLhausSubmission records a single URL submitted to abuse.ch URLhaus.
// The URL is the natural key: URLhaus dedupes on it, and the artifacts table is
// already UNIQUE(url), so one row per URL matches both sides.
type URLhausSubmission struct {
	URL         string
	SubmittedAt time.Time
	Status      string
}

// ensureURLhausTable creates the submissions table on first use. Same lazy
// sync.Once pattern as the other side tables so the DDL never runs under
// writeMu on a hot path.
func (s *Store) ensureURLhausTable() error {
	s.onceURLhaus.Do(func() {
		s.errURLhaus = s.WithTx(func(tx *sql.Tx) error { return ensureLedgerTimeSchema(tx, urlhausLedger) })
	})
	return s.errURLhaus
}

// URLhausSubmitted reports whether we already submitted this URL, so a repeat
// run doesn't re-POST it. Satisfies urlhaus.SubmitRecorder.
func (s *Store) URLhausSubmitted(url string) (bool, error) {
	if url == "" {
		return false, nil
	}
	if err := s.ensureURLhausTable(); err != nil {
		return false, err
	}
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM urlhaus_submissions WHERE url=?`, url).Scan(&n)
	return n > 0, err
}

// RecordURLhausSubmission upserts the row for a submitted URL. Only successful
// submissions are recorded — network failures and auth rejections are left
// unrecorded so the next run retries them, matching RecordBazaarUpload.
func (s *Store) RecordURLhausSubmission(url, status string, at time.Time) error {
	if url == "" {
		return nil
	}
	if err := s.ensureURLhausTable(); err != nil {
		return err
	}
	if at.IsZero() {
		at = time.Now()
	}
	ts := at.UTC().Format(time.RFC3339Nano)
	if _, err := parseLedgerTimestamp(ts); err != nil {
		return err
	}
	_, err := s.execWrite(`
INSERT INTO urlhaus_submissions (url, submitted_at, status, submitted_at_key)
VALUES (?, ?, ?, ?)
ON CONFLICT(url) DO UPDATE SET
  submitted_at=excluded.submitted_at,
  submitted_at_key=excluded.submitted_at_key,
  status=excluded.status`,
		url, ts, status, formatFixedUTC(at))
	return err
}

// URLhausStats holds aggregate counts for the URLhaus sharing widget.
type URLhausStats struct {
	TotalSubmitted  int
	Pending         int
	LastSubmittedAt time.Time
}

// URLhausSubmissionStats returns aggregate sharing metrics.
//
// Pending counts artifacts that would plausibly pass the vetting gate but
// haven't been submitted. It deliberately mirrors only the cheap, SQL-able
// parts of urlhaus.Vet (real fetched URL, has a payload, big enough, recent) —
// the authoritative decision stays in Vet. Treat this as an upper bound for
// the UI, not a promise.
func (s *Store) URLhausSubmissionStats(activeDays int) (URLhausStats, error) {
	if err := s.ensureURLhausTable(); err != nil {
		return URLhausStats{}, err
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return URLhausStats{}, err
	}
	var st URLhausStats
	var lastTS sql.NullString
	if err := s.db.QueryRow("SELECT COUNT(*), ("+latestLedgerTimeSQL(urlhausLedger)+") FROM urlhaus_submissions").Scan(&st.TotalSubmitted, &lastTS); err != nil {
		return st, err
	}
	if lastTS.Valid {
		var err error
		if st.LastSubmittedAt, err = parseLedgerTimestamp(lastTS.String); err != nil {
			return st, err
		}
	}
	if activeDays <= 0 {
		activeDays = 3
	}
	cutoff := time.Now().UTC().Add(-time.Duration(activeDays) * 24 * time.Hour).Format(time.RFC3339Nano)
	if err := s.db.QueryRow(`
SELECT COUNT(*)
FROM artifacts a
WHERE a.origin = 'quarantine_fetch'
  AND a.status = 'fetched'
  AND a.sha256 IS NOT NULL AND a.sha256 != ''
  AND a.size_bytes >= 64
  AND (a.url LIKE 'http://%' OR a.url LIKE 'https://%')
  AND julianday(a.last_successful_fetch_at) >= julianday(?)
  AND a.url NOT IN (SELECT url FROM urlhaus_submissions)`, cutoff).Scan(&st.Pending); err != nil {
		log.Printf("urlhaus pending count: %v (defaulting to 0)", err)
	}
	return st, nil
}

// ListURLhausSubmissions returns recorded submissions, newest first.
// Bounded by limit; pass 0 for no cap.
func (s *Store) ListURLhausSubmissions(limit int) ([]URLhausSubmission, error) {
	if err := s.ensureURLhausTable(); err != nil {
		return nil, err
	}
	q, args := orderedLedgerQuery(urlhausLedger, "url,submitted_at,status", limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []URLhausSubmission
	for rows.Next() {
		var u URLhausSubmission
		var ts, key string
		if err := rows.Scan(&u.URL, &ts, &u.Status, &key); err != nil {
			return nil, err
		}
		if u.SubmittedAt, err = parseLedgerRowTimestamp(ts, key); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// URLhausCandidateRow is an artifact considered for URL submission, shaped for
// the urlhaus.Candidate conversion done by the caller (cmd/web). Keeping the
// query here and the struct conversion in the caller preserves the rule that
// intel packages never import store.
type URLhausCandidateRow struct {
	URL       string
	SHA256    string
	SizeBytes int64
	Origin    string
	Status    string
	FetchedAt time.Time
	LocalPath string
}

// URLhausCandidates returns artifacts that could be submitted, newest first.
// The SQL applies only the cheap structural filters; urlhaus.Vet remains the
// authoritative policy gate (it also needs the classifier's file kind, which
// requires reading the file off disk).
//
// The WHERE clause is kept deliberately IDENTICAL to the Pending subquery in
// URLhausSubmissionStats — including the size floor, which mirrors
// urlhaus.minPayloadBytes. When the two drifted apart, the UI reported a
// pending count that didn't match the list the CLI would actually offer.
func (s *Store) URLhausCandidates(activeDays, limit int) ([]URLhausCandidateRow, error) {
	if err := s.ensureURLhausTable(); err != nil {
		return nil, err
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return nil, err
	}
	if activeDays <= 0 {
		activeDays = 3
	}
	cutoff := time.Now().UTC().Add(-time.Duration(activeDays) * 24 * time.Hour).Format(time.RFC3339Nano)
	q := `
SELECT a.url, COALESCE(a.sha256,''), COALESCE(a.size_bytes,0), a.origin, a.status,
       a.last_successful_fetch_at, COALESCE(a.local_path,'')
FROM artifacts a
WHERE a.origin = 'quarantine_fetch'
  AND a.status = 'fetched'
  AND a.sha256 IS NOT NULL AND a.sha256 != ''
  AND a.size_bytes >= 64
  AND (a.url LIKE 'http://%' OR a.url LIKE 'https://%')
  AND julianday(a.last_successful_fetch_at) >= julianday(?)
  AND a.url NOT IN (SELECT url FROM urlhaus_submissions)
ORDER BY julianday(a.last_successful_fetch_at) DESC`
	args := []any{cutoff}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []URLhausCandidateRow
	for rows.Next() {
		var r URLhausCandidateRow
		var ts string
		if err := rows.Scan(&r.URL, &r.SHA256, &r.SizeBytes, &r.Origin, &r.Status, &ts, &r.LocalPath); err != nil {
			return nil, err
		}
		if t, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
			r.FetchedAt = t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
