package store

import (
	"database/sql"
	"strconv"
	"strings"
	"time"
)

// AbuseReport records a single outbound submission to AbuseIPDB /report. The
// ip is the natural key: AbuseIPDB dedupes on the offender IP, and we suppress
// re-reporting within a configurable window (AbuseIPDB permits re-reporting
// after 15 min; ShardLure defaults to 24h). This table is the WRITE-side audit
// ledger — the enrichment /check reads are unrelated and uncached here.
type AbuseReport struct {
	IP         string
	ReportedAt time.Time
	Status     string
	Categories []int
	AbuseScore int
}

// ensureAbuseReportsTable self-heals the v12-created table if a migration ran
// on a hot database whose write was contended by another writer (the same
// class of bug that motivated the ensure* pattern for bazaar_uploads,
// artifacts, ip_enrichment). Idempotent via sync.Once.
func (s *Store) ensureAbuseReportsTable() error {
	s.onceAbuseReport.Do(func() {
		_, s.errAbuseReport = s.execWrite(`
CREATE TABLE IF NOT EXISTS abuseipdb_reports (
  ip          TEXT PRIMARY KEY,
  reported_at TEXT NOT NULL,
  status      TEXT NOT NULL,
  categories  TEXT,
  abuse_score INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_abuseipdb_reports_ts ON abuseipdb_reports(reported_at);
`)
	})
	return s.errAbuseReport
}

// AbuseIPDBReported reports whether ip was reported within the given window
// (measured back from now). This is deliberately TIME-WINDOWED, not permanent:
// a persistent brute-forcer should be re-reported on later runs so the feed
// stays current. A zero/negative window means "ever reported".
func (s *Store) AbuseIPDBReported(ip string, within time.Duration) (bool, error) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false, nil
	}
	if err := s.ensureAbuseReportsTable(); err != nil {
		return false, err
	}
	if within <= 0 {
		var n int
		err := s.db.QueryRow(`SELECT COUNT(1) FROM abuseipdb_reports WHERE ip=?`, ip).Scan(&n)
		return n > 0, err
	}
	cutoff := time.Now().Add(-within).UTC().Format(time.RFC3339Nano)
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM abuseipdb_reports WHERE ip=? AND reported_at >= ?`, ip, cutoff).Scan(&n)
	return n > 0, err
}

// RecordAbuseIPDBReport upserts the row for a submission. Categories are stored
// as a comma-joined string (the API's own wire format) so the audit row shows
// exactly what was sent. Only called on an accepted report, so the window
// dedup reflects real submissions.
func (s *Store) RecordAbuseIPDBReport(ip, status string, score int, categories []int, at time.Time) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil
	}
	if err := s.ensureAbuseReportsTable(); err != nil {
		return err
	}
	ts := at.UTC().Format(time.RFC3339Nano)
	if at.IsZero() {
		ts = time.Now().UTC().Format(time.RFC3339Nano)
	}
	_, err := s.execWrite(`
INSERT INTO abuseipdb_reports (ip, reported_at, status, categories, abuse_score)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(ip) DO UPDATE SET
  reported_at=excluded.reported_at,
  status=excluded.status,
  categories=excluded.categories,
  abuse_score=excluded.abuse_score`,
		ip, ts, status, joinCategories(categories), score)
	return err
}

// AbuseReportStats holds aggregate counts for the dashboard reporting widget.
type AbuseReportStats struct {
	TotalReported int
	LastReportAt  time.Time
}

// AbuseReportStats returns aggregate reporting metrics.
func (s *Store) AbuseReportStats() (AbuseReportStats, error) {
	if err := s.ensureAbuseReportsTable(); err != nil {
		return AbuseReportStats{}, err
	}
	var st AbuseReportStats
	var lastTS sql.NullString
	err := s.db.QueryRow(`SELECT COUNT(*), MAX(reported_at) FROM abuseipdb_reports`).Scan(&st.TotalReported, &lastTS)
	if err != nil {
		return st, err
	}
	if lastTS.Valid {
		if t, perr := time.Parse(time.RFC3339Nano, lastTS.String); perr == nil {
			st.LastReportAt = t
		}
	}
	return st, nil
}

// ListAbuseReports returns recorded reports, newest first. limit<=0 = no cap.
func (s *Store) ListAbuseReports(limit int) ([]AbuseReport, error) {
	if err := s.ensureAbuseReportsTable(); err != nil {
		return nil, err
	}
	q := `SELECT ip, reported_at, status, COALESCE(categories,''), COALESCE(abuse_score,0)
	      FROM abuseipdb_reports ORDER BY reported_at DESC`
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
	var out []AbuseReport
	for rows.Next() {
		var r AbuseReport
		var tsStr, cats string
		if err := rows.Scan(&r.IP, &tsStr, &r.Status, &cats, &r.AbuseScore); err != nil {
			return nil, err
		}
		if t, perr := time.Parse(time.RFC3339Nano, tsStr); perr == nil {
			r.ReportedAt = t
		}
		r.Categories = parseCategories(cats)
		out = append(out, r)
	}
	return out, rows.Err()
}

func joinCategories(cats []int) string {
	if len(cats) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cats))
	for _, c := range cats {
		parts = append(parts, strconv.Itoa(c))
	}
	return strings.Join(parts, ",")
}

func parseCategories(s string) []int {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []int
	for _, p := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			out = append(out, n)
		}
	}
	return out
}
