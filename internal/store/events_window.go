package store

import (
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// EventsSince returns events with TS >= since. Includes all columns the
// classifier and exporters need (kind, command, src_ip, actor_id,
// session_id, hashes, source). limit caps the rows scanned so analysts
// can't accidentally walk an entire 30-day log file from a UI fetch.
//
// Pass limit=0 (or any non-positive value) to use the default cap of
// 5000 rows. Pass an explicit positive limit if you want fewer; there
// is no way to request "all rows" - this method is intentionally
// bounded. For unbounded streaming, use IterateEventsBySource.
//
// Use this for read-only analytics. Streaming ingest paths should
// continue to call IterateEventsBySource so they can consume
// arbitrarily large slices without buffering everything in memory.
func (s *Store) EventsSince(since time.Time, limit int) ([]*models.Event, error) {
	if limit <= 0 {
		limit = 5000
	}
	rows, err := s.db.Query(`
SELECT id, ts, source, kind, src_ip, src_port, username, password, session_id, hassh, ssh_client, ja4, command, sha256, filename, actor_id
FROM events WHERE ts >= ? ORDER BY ts DESC LIMIT ?`,
		since.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Event
	for rows.Next() {
		e := &models.Event{}
		var ts, source, kind string
		if err := rows.Scan(&e.ID, &ts, &source, &kind, &e.SrcIP, &e.SrcPort, &e.Username,
			&e.Password, &e.SessionID, &e.HASSH, &e.SSHClient, &e.JA4, &e.Command,
			&e.SHA256, &e.Filename, &e.ActorID); err != nil {
			return nil, err
		}
		e.TS, _ = parseTime(ts)
		e.Source = models.Source(source)
		e.Kind = models.EventKind(kind)
		out = append(out, e)
	}
	return out, rows.Err()
}
