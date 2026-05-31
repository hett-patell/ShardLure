package store

import (
	"database/sql"
	"log"
	"time"
)

// BazaarUpload records a single submission to abuse.ch MalwareBazaar.
// The sha256 is the natural key (and what MalwareBazaar dedupes on),
// so a successful or "file_already_known" response from MB is both
// recorded the same way: we know the sample is upstream.
type BazaarUpload struct {
	SHA256         string
	UploadedAt     time.Time
	ResponseStatus string
	MBURL          string
}

// ensureBazaarUploadsTable self-heals the v5-created table if a
// migration ran on a hot database whose write was contended by
// another writer (e.g. shardlure-live holding the WAL) and the
// CREATE TABLE silently failed to land. v1.1.1 added the same
// pattern for artifacts/ip_enrichment/cowrie_tty_index after the
// same class of bug, so this brings v5 in line.
func (s *Store) ensureBazaarUploadsTable() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS bazaar_uploads (
  sha256          TEXT PRIMARY KEY,
  uploaded_at     TEXT NOT NULL,
  response_status TEXT NOT NULL,
  mb_url          TEXT
);
CREATE INDEX IF NOT EXISTS idx_bazaar_uploads_ts ON bazaar_uploads(uploaded_at);
`)
	return err
}

// BazaarUploadRecorded reports whether we have a row for the given
// sha256 already. Used by the share subcommand to skip files we know
// MalwareBazaar has, without re-POSTing them on every run.
func (s *Store) BazaarUploadRecorded(sha string) (bool, error) {
	if sha == "" {
		return false, nil
	}
	if err := s.ensureBazaarUploadsTable(); err != nil {
		return false, err
	}
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM bazaar_uploads WHERE sha256=?`, sha).Scan(&n)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return n > 0, err
}

// RecordBazaarUpload upserts the row for a submission attempt. The
// caller writes this row regardless of whether the MB response was
// "inserted" or "file_already_known" — both mean the sample is on
// MalwareBazaar and we should not re-submit. Failure modes (network
// errors, http 5xx) are NOT recorded so the next run retries.
func (s *Store) RecordBazaarUpload(u BazaarUpload) error {
	if u.SHA256 == "" {
		return nil
	}
	if err := s.ensureBazaarUploadsTable(); err != nil {
		return err
	}
	ts := u.UploadedAt.UTC().Format(time.RFC3339Nano)
	if u.UploadedAt.IsZero() {
		ts = time.Now().UTC().Format(time.RFC3339Nano)
	}
	_, err := s.db.Exec(`
INSERT INTO bazaar_uploads (sha256, uploaded_at, response_status, mb_url)
VALUES (?, ?, ?, ?)
ON CONFLICT(sha256) DO UPDATE SET
  uploaded_at=excluded.uploaded_at,
  response_status=excluded.response_status,
  mb_url=excluded.mb_url`,
		u.SHA256, ts, u.ResponseStatus, u.MBURL)
	return err
}

// BazaarStats holds aggregate counts for the bazaar sharing widget.
type BazaarStats struct {
	TotalUploaded int
	Duplicates    int
	Pending       int
	LastUploadAt  time.Time
}

// BazaarUploadStats returns aggregate sharing metrics.
func (s *Store) BazaarUploadStats() (BazaarStats, error) {
	if err := s.ensureBazaarUploadsTable(); err != nil {
		return BazaarStats{}, err
	}
	var st BazaarStats
	var lastTS sql.NullString
	err := s.db.QueryRow(`
SELECT COUNT(*),
       COUNT(CASE WHEN response_status='file_already_known' THEN 1 END),
       MAX(uploaded_at)
FROM bazaar_uploads`).Scan(&st.TotalUploaded, &st.Duplicates, &lastTS)
	if err != nil {
		return st, err
	}
	if lastTS.Valid {
		if t, perr := time.Parse(time.RFC3339Nano, lastTS.String); perr == nil {
			st.LastUploadAt = t
		}
	}
	if err := s.db.QueryRow(`
SELECT COUNT(DISTINCT a.sha256)
FROM artifacts a
WHERE a.status='fetched'
  AND a.sha256 IS NOT NULL AND a.sha256 != ''
  AND a.size_bytes > 1024
  AND a.origin LIKE '%download%'
  AND a.sha256 NOT IN (SELECT sha256 FROM bazaar_uploads)`).Scan(&st.Pending); err != nil {
		log.Printf("bazaar pending count: %v (defaulting to 0)", err)
	}
	return st, nil
}

// ListBazaarUploads returns every recorded submission, newest first.
// Used by the share subcommand's --status flag and (eventually) the
// dashboard's intel-sharing view. Bounded by limit; pass 0 for no cap.
func (s *Store) ListBazaarUploads(limit int) ([]BazaarUpload, error) {
	if err := s.ensureBazaarUploadsTable(); err != nil {
		return nil, err
	}
	q := `SELECT sha256, uploaded_at, response_status, COALESCE(mb_url, '')
	      FROM bazaar_uploads ORDER BY uploaded_at DESC`
	args := []interface{}{}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BazaarUpload
	for rows.Next() {
		var u BazaarUpload
		var tsStr string
		if err := rows.Scan(&u.SHA256, &tsStr, &u.ResponseStatus, &u.MBURL); err != nil {
			return nil, err
		}
		if t, perr := time.Parse(time.RFC3339Nano, tsStr); perr == nil {
			u.UploadedAt = t
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
