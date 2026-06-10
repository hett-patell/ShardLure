package store

import (
	"fmt"
	"time"
)

type CountRow struct {
	Key  string
	Hits int
}

type HourCount struct {
	Hour time.Time
	Hits int
}

// topCountsColumns whitelists the columns topCounts() may aggregate over.
// SQLite parameterized queries can't bind identifiers, so we splice the
// column name into the SQL string. Restricting it to this allowlist
// guarantees the splice is safe even if a future caller passes the
// wrong value.
var topCountsColumns = map[string]string{
	"src_ip":   "src_ip IS NOT NULL AND src_ip != ''",
	"username": "username IS NOT NULL AND username != '' AND username != '?'",
	"command":  "command IS NOT NULL AND command != ''",
}

func (s *Store) TopSourceIPs(limit int) ([]CountRow, error) { return s.topCounts("src_ip", limit) }

// CountryHit is a per-country event tally for the "Attack Geography" widget.
type CountryHit struct {
	CC      string
	Country string
	Hits    int
}

// TopCountriesByHits returns true attack geography: total event hits grouped
// by the source IP's country, across ALL events — not just the top-25 IPs.
// It joins each IP's event count to the geo cache (ip_enrichment, source='geo')
// so the chart reflects every resolved attacker, fixing the case where a single
// dominant IP (e.g. 64k hits) was absent because it wasn't in the recent-N
// actor slice the old client-side aggregation walked. IPs with no resolved geo
// are excluded (they can't be placed on a country).
func (s *Store) TopCountriesByHits(limit int) ([]CountryHit, error) {
	if err := s.EnsureEnrichmentTable(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 12
	}
	rows, err := s.db.Query(`
WITH ip_hits AS (
  SELECT src_ip, COUNT(*) AS hits
  FROM events
  WHERE src_ip IS NOT NULL AND src_ip != ''
  GROUP BY src_ip
),
geo AS (
  SELECT ip,
         json_extract(payload, '$.cc')      AS cc,
         json_extract(payload, '$.country') AS country
  FROM ip_enrichment
  WHERE source='geo' AND json_extract(payload, '$.ok') = 1
)
SELECT g.cc, MAX(g.country) AS country, SUM(h.hits) AS hits
FROM ip_hits h
JOIN geo g ON g.ip = h.src_ip
WHERE g.cc IS NOT NULL AND g.cc != ''
GROUP BY g.cc
ORDER BY hits DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CountryHit
	for rows.Next() {
		var c CountryHit
		if err := rows.Scan(&c.CC, &c.Country, &c.Hits); err != nil {
			return nil, err
		}
		if c.Country == "" {
			c.Country = c.CC
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) TopUsernames(limit int) ([]CountRow, error) { return s.topCounts("username", limit) }

func (s *Store) TopCommands(limit int) ([]CountRow, error) { return s.topCounts("command", limit) }

func (s *Store) UniqueIPCount() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(DISTINCT src_ip) FROM events WHERE src_ip IS NOT NULL AND src_ip != ''").Scan(&n)
	return n, err
}

func (s *Store) HourlyEventCounts(limit int) ([]HourCount, error) {
	if limit <= 0 {
		limit = 72
	}
	// events.ts is stored as RFC3339Nano UTC text, so the first 13 bytes are
	// YYYY-MM-DDTHH. Bound the scan to the requested window (limit hours back,
	// +1h margin so the partial current hour is included) so idx_events_ts
	// restricts the rows instead of grouping the entire events table on every
	// dashboard render. The dashboard asks for "the last N hours", so a time
	// bound also matches intent better than an all-time top-N which could
	// surface stale hours when recent traffic is sparse.
	cutoff := time.Now().UTC().Add(-time.Duration(limit+1) * time.Hour).Format(time.RFC3339Nano)
	rows, err := s.db.Query(`
SELECT hour, hits FROM (
  SELECT substr(ts, 1, 13) AS hour, COUNT(*) AS hits
  FROM events
  WHERE ts >= ?
  GROUP BY hour
  ORDER BY hour DESC
  LIMIT ?
) ORDER BY hour ASC`, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []HourCount
	for rows.Next() {
		var hour string
		var hits int
		if err := rows.Scan(&hour, &hits); err != nil {
			return nil, err
		}
		t, err := time.Parse("2006-01-02T15", hour)
		if err != nil {
			continue
		}
		out = append(out, HourCount{Hour: t.UTC(), Hits: hits})
	}
	return out, rows.Err()
}

// topCounts aggregates row counts grouped by an allowlisted column.
// column MUST be a key of topCountsColumns; any other value returns an error.
// Never accept user input here.
func (s *Store) topCounts(column string, limit int) ([]CountRow, error) {
	where, ok := topCountsColumns[column]
	if !ok {
		return nil, fmt.Errorf("topCounts: column %q not in allowlist", column)
	}
	// A non-positive limit must not turn into an unbounded scan: on a busy
	// honeypot the events table is large and the distinct count of usernames/
	// commands an attacker can fabricate is effectively unbounded, so an
	// uncapped GROUP BY could pull a huge result set into memory. Fall back to
	// a generous default cap; every real caller passes an explicit small limit.
	const defaultTopLimit = 1000
	if limit <= 0 {
		limit = defaultTopLimit
	}
	query := "SELECT " + column + ", COUNT(*) AS hits FROM events WHERE " + where + " GROUP BY " + column + " ORDER BY hits DESC LIMIT ?"
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CountRow
	for rows.Next() {
		var row CountRow
		if err := rows.Scan(&row.Key, &row.Hits); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Close() error
	Next() bool
	Scan(dest ...any) error
	Err() error
}
