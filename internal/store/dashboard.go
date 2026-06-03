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
	query := "SELECT " + column + ", COUNT(*) AS hits FROM events WHERE " + where + " GROUP BY " + column + " ORDER BY hits DESC"
	var rows rowScanner
	var err error
	if limit > 0 {
		rows, err = s.db.Query(query+" LIMIT ?", limit)
	} else {
		rows, err = s.db.Query(query)
	}
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
