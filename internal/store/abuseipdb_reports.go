package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
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
	var reportedAt string
	err := s.db.QueryRow(`SELECT reported_at FROM abuseipdb_reports WHERE ip=?`, ip).Scan(&reportedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	parsed, err := time.Parse(time.RFC3339Nano, reportedAt)
	if err != nil {
		return false, fmt.Errorf("abuseipdb report %s reported_at: %w", ip, err)
	}
	return !parsed.Before(time.Now().Add(-within)), nil
}

// AbuseIPDBReportedIPsContext returns the subset of ips present in the report
// ledger inside the re-report window. Suggestions use this bulk form instead
// of issuing one SQLite query for every candidate that passes Vet.
func (s *Store) AbuseIPDBReportedIPsContext(ctx context.Context, ips []string, within time.Duration) (map[string]bool, error) {
	reported := make(map[string]bool)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.ensureAbuseReportsTable(); err != nil {
		return nil, err
	}

	unique := make([]string, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		unique = append(unique, ip)
	}
	if len(unique) == 0 {
		return reported, nil
	}

	const chunkSize = 400
	cutoff := time.Time{}
	if within > 0 {
		cutoff = time.Now().Add(-within)
	}
	for start := 0; start < len(unique); start += chunkSize {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		end := start + chunkSize
		if end > len(unique) {
			end = len(unique)
		}
		batch := unique[start:end]
		placeholders := make([]string, len(batch))
		args := make([]any, 0, len(batch))
		for i, ip := range batch {
			placeholders[i] = "?"
			args = append(args, ip)
		}
		query := `SELECT ip,reported_at FROM abuseipdb_reports WHERE ip IN (` + strings.Join(placeholders, ",") + `)`
		rows, err := s.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ip, reportedAt string
			if err := rows.Scan(&ip, &reportedAt); err != nil {
				rows.Close()
				return nil, err
			}
			if within > 0 {
				parsed, err := time.Parse(time.RFC3339Nano, reportedAt)
				if err != nil {
					rows.Close()
					return nil, fmt.Errorf("abuseipdb report %s reported_at: %w", ip, err)
				}
				if parsed.Before(cutoff) {
					continue
				}
			}
			reported[ip] = true
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return reported, nil
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
	ts := formatFixedUTC(at)
	if at.IsZero() {
		ts = formatFixedUTC(time.Now())
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
	rows, err := s.db.Query(`SELECT ip,reported_at FROM abuseipdb_reports`)
	if err != nil {
		return AbuseReportStats{}, err
	}
	defer rows.Close()
	var st AbuseReportStats
	for rows.Next() {
		var ip, reportedAt string
		if err := rows.Scan(&ip, &reportedAt); err != nil {
			return st, err
		}
		parsed, err := time.Parse(time.RFC3339Nano, reportedAt)
		if err != nil {
			return st, fmt.Errorf("abuseipdb report %s reported_at: %w", ip, err)
		}
		st.TotalReported++
		if st.LastReportAt.IsZero() || parsed.After(st.LastReportAt) {
			st.LastReportAt = parsed
		}
	}
	return st, rows.Err()
}

// ListAbuseReports returns recorded reports, newest first. limit<=0 = no cap.
func (s *Store) ListAbuseReports(limit int) ([]AbuseReport, error) {
	if err := s.ensureAbuseReportsTable(); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT ip, reported_at, status, COALESCE(categories,''), COALESCE(abuse_score,0)
	      FROM abuseipdb_reports`)
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
		parsed, err := time.Parse(time.RFC3339Nano, tsStr)
		if err != nil {
			return nil, fmt.Errorf("abuseipdb report %s reported_at: %w", r.IP, err)
		}
		r.ReportedAt = parsed
		r.Categories = parseCategories(cats)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ReportedAt.Equal(out[j].ReportedAt) {
			return out[i].ReportedAt.After(out[j].ReportedAt)
		}
		return out[i].IP < out[j].IP
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
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
