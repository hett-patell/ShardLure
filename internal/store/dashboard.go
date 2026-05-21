package store

import "time"

type CountRow struct {
	Key  string
	Hits int
}

type HourCount struct {
	Hour time.Time
	Hits int
}

func (s *Store) TopSourceIPs(limit int) ([]CountRow, error) {
	return s.topCounts("src_ip", "src_ip IS NOT NULL AND src_ip != ''", limit)
}

func (s *Store) TopUsernames(limit int) ([]CountRow, error) {
	return s.topCounts("username", "username IS NOT NULL AND username != '' AND username != '?'", limit)
}

func (s *Store) TopCommands(limit int) ([]CountRow, error) {
	return s.topCounts("command", "command IS NOT NULL AND command != ''", limit)
}

func (s *Store) UniqueIPCount() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(DISTINCT src_ip) FROM events WHERE src_ip IS NOT NULL AND src_ip != ''").Scan(&n)
	return n, err
}

func (s *Store) HourlyEventCounts(limit int) ([]HourCount, error) {
	// events.ts is stored as RFC3339Nano UTC text, so the first 13 bytes are YYYY-MM-DDTHH.
	rows, err := s.db.Query(`
SELECT hour, hits FROM (
  SELECT substr(ts, 1, 13) AS hour, COUNT(*) AS hits
  FROM events
  GROUP BY hour
  ORDER BY hour DESC
  LIMIT ?
) ORDER BY hour ASC`, limit)
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

func (s *Store) topCounts(column string, where string, limit int) ([]CountRow, error) {
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
