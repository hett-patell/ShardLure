package store

import (
	"time"
)

// ThreatFox give-back ledger. ThreatFox is the IOC-level sibling of the
// MalwareBazaar (files) and URLhaus (URLs) channels, on the same abuse.ch key.
//
// Dedup is per-IOC VALUE, not per-artifact: one confirmed payload fetch yields
// several indicators (the url, an ip:port or domain, the sha256), each tracked
// independently so a re-fetch that surfaces one new indicator still submits it.
// The ledger is NEVER purged (like urlhaus_submissions) — a submitted IOC stays
// recorded so we never re-POST it even after the artifact ages out.

// ThreatFoxSubmission is one indicator submitted to ThreatFox.
type ThreatFoxSubmission struct {
	IOC         string
	IOCType     string
	Malware     string
	Status      string
	SubmittedAt time.Time
}

// ensureThreatFoxTable creates the ledger on first use (lazy sync.Once, same as
// the other side tables, so DDL never runs under writeMu on a hot path).
func (s *Store) ensureThreatFoxTable() error {
	s.onceThreatFox.Do(func() {
		_, s.errThreatFox = s.execWrite(`
CREATE TABLE IF NOT EXISTS threatfox_submissions (
  ioc          TEXT PRIMARY KEY,
  ioc_type     TEXT NOT NULL,
  malware      TEXT NOT NULL,
  submitted_at TEXT NOT NULL,
  status       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_threatfox_submissions_ts ON threatfox_submissions(submitted_at);
`)
	})
	return s.errThreatFox
}

// ThreatFoxSubmitted reports whether we already submitted this IOC value, so a
// repeat run doesn't re-POST it. Satisfies threatfox.SubmitRecorder.
func (s *Store) ThreatFoxSubmitted(ioc string) (bool, error) {
	if ioc == "" {
		return false, nil
	}
	if err := s.ensureThreatFoxTable(); err != nil {
		return false, err
	}
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM threatfox_submissions WHERE ioc=?`, ioc).Scan(&n)
	return n > 0, err
}

// RecordThreatFoxSubmission upserts the row for a submitted IOC. Only
// successful submissions are recorded — network failures and auth rejections
// are left unrecorded so the next run retries them, matching
// RecordURLhausSubmission. Satisfies threatfox.SubmitRecorder.
func (s *Store) RecordThreatFoxSubmission(ioc, iocType, malware, status string, at time.Time) error {
	if ioc == "" {
		return nil
	}
	if err := s.ensureThreatFoxTable(); err != nil {
		return err
	}
	if at.IsZero() {
		at = time.Now()
	}
	_, err := s.execWrite(`
INSERT INTO threatfox_submissions (ioc, ioc_type, malware, submitted_at, status)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(ioc) DO UPDATE SET
  ioc_type=excluded.ioc_type,
  malware=excluded.malware,
  submitted_at=excluded.submitted_at,
  status=excluded.status`,
		ioc, iocType, malware, at.UTC().Format(time.RFC3339Nano), status)
	return err
}

// ThreatFoxStats holds aggregate counts for the ThreatFox sharing widget.
type ThreatFoxStats struct {
	TotalSubmitted  int
	Pending         int
	LastSubmittedAt time.Time
}

// ThreatFoxSubmissionStats returns aggregate sharing metrics.
//
// Pending counts confirmed-fetch artifacts whose URL has not yet been
// submitted. It deliberately mirrors only the cheap, SQL-able part of
// threatfox.Vet (real fetched URL, has a payload, big enough, recent) — the
// authoritative decision, including the mandatory Malpedia-family resolution,
// stays in Vet, so this is an UPPER BOUND for the UI, not a promise. The WHERE
// clause is kept IDENTICAL to ThreatFoxCandidates (the urlhaus drift lesson).
func (s *Store) ThreatFoxSubmissionStats(activeDays int) (ThreatFoxStats, error) {
	if err := s.ensureThreatFoxTable(); err != nil {
		return ThreatFoxStats{}, err
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return ThreatFoxStats{}, err
	}
	var st ThreatFoxStats
	var lastTS *string
	if err := s.db.QueryRow(`SELECT COUNT(1), MAX(submitted_at) FROM threatfox_submissions`).Scan(&st.TotalSubmitted, &lastTS); err != nil {
		return st, err
	}
	if lastTS != nil {
		if t, perr := time.Parse(time.RFC3339Nano, *lastTS); perr == nil {
			st.LastSubmittedAt = t
		}
	}
	if activeDays <= 0 {
		activeDays = 3
	}
	cutoff := time.Now().UTC().Add(-time.Duration(activeDays) * 24 * time.Hour).Format(time.RFC3339Nano)
	if err := s.db.QueryRow(threatfoxPendingSQL, cutoff).Scan(&st.Pending); err != nil {
		return st, err
	}
	return st, nil
}

// threatfoxPendingSQL is the pending-count query, kept identical to the
// candidate SELECT's WHERE so the UI count and the CLI list never disagree.
const threatfoxPendingSQL = `
SELECT COUNT(1) FROM artifacts a
WHERE a.origin = 'quarantine_fetch'
  AND a.status = 'fetched'
  AND a.sha256 IS NOT NULL AND a.sha256 != ''
  AND a.size_bytes >= 64
  AND (a.url LIKE 'http://%' OR a.url LIKE 'https://%')
  AND COALESCE(a.ts, a.created_at) >= ?
  AND a.url NOT IN (SELECT ioc FROM threatfox_submissions)`

// ListThreatFoxSubmissions returns recorded submissions, newest first.
func (s *Store) ListThreatFoxSubmissions(limit int) ([]ThreatFoxSubmission, error) {
	if err := s.ensureThreatFoxTable(); err != nil {
		return nil, err
	}
	q := `SELECT ioc, ioc_type, malware, submitted_at, status
	      FROM threatfox_submissions ORDER BY submitted_at DESC`
	args := []any{}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ThreatFoxSubmission
	for rows.Next() {
		var r ThreatFoxSubmission
		var ts string
		if err := rows.Scan(&r.IOC, &r.IOCType, &r.Malware, &ts, &r.Status); err != nil {
			return nil, err
		}
		if t, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
			r.SubmittedAt = t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ThreatFoxCandidateRow is a confirmed-fetch artifact considered for IOC
// submission, shaped for the threatfox.Candidate conversion done by the caller
// (the caller adds Family via bazaar.Classify on LocalPath, preserving the rule
// that intel packages never import store and store never imports intel).
type ThreatFoxCandidateRow struct {
	URL       string
	SHA256    string
	SizeBytes int64
	Origin    string
	Status    string
	FetchedAt time.Time
	LocalPath string
}

// ThreatFoxCandidates returns artifacts that could be submitted, newest first.
// Cheap structural filters only; threatfox.Vet is the authoritative gate (it
// also needs the classifier's file kind AND malware family, both from reading
// the file off disk). The WHERE clause is IDENTICAL to threatfoxPendingSQL.
//
// `limit` is a coarse pool cap; the real submission budget is enforced in
// threatfox.Share AFTER the gate (never a pre-gate LIMIT — the D3 lesson).
func (s *Store) ThreatFoxCandidates(activeDays, limit int) ([]ThreatFoxCandidateRow, error) {
	if err := s.ensureThreatFoxTable(); err != nil {
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
       COALESCE(a.ts, a.created_at), COALESCE(a.local_path,'')
FROM artifacts a
WHERE a.origin = 'quarantine_fetch'
  AND a.status = 'fetched'
  AND a.sha256 IS NOT NULL AND a.sha256 != ''
  AND a.size_bytes >= 64
  AND (a.url LIKE 'http://%' OR a.url LIKE 'https://%')
  AND COALESCE(a.ts, a.created_at) >= ?
  AND a.url NOT IN (SELECT ioc FROM threatfox_submissions)
ORDER BY COALESCE(a.ts, a.created_at) DESC`
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
	var out []ThreatFoxCandidateRow
	for rows.Next() {
		var r ThreatFoxCandidateRow
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
