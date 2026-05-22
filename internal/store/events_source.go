package store

import (
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func (s *Store) EventExists(e *models.Event) (bool, error) {
	var n int
	err := s.db.QueryRow(`
SELECT COUNT(1) FROM events
WHERE source=? AND kind=? AND ts=? AND src_ip=? AND session_id=? AND username=? AND command=?`,
		e.Source, e.Kind, e.TS.UTC().Format(time.RFC3339Nano), e.SrcIP, e.SessionID, e.Username, e.Command).Scan(&n)
	return n > 0, err
}

// EventsBySource loads every event for the given source into memory.
//
// DEPRECATED for hot paths. With a million+ events this allocates ~hundreds
// of MB and is the single biggest reason `shardlure live` can OOM on a small
// VPS. Prefer IterateEventsBySource for streaming consumers (ingest,
// classifier, reporting). EventsBySource is kept only for tests and
// debug/CLI uses where the row count is known small.
func (s *Store) EventsBySource(source models.Source) ([]*models.Event, error) {
	var out []*models.Event
	err := s.IterateEventsBySource(source, func(e *models.Event) error {
		out = append(out, e)
		return nil
	})
	return out, err
}

// IterateEventsBySource streams events for a source in ts ASC order and
// invokes fn for each one. fn must not retain the pointer across calls if
// it intends to mutate; the row is freshly heap-allocated per iteration so
// retaining is safe but expected to be rare.
//
// Returning an error from fn aborts iteration and propagates the error.
func (s *Store) IterateEventsBySource(source models.Source, fn func(*models.Event) error) error {
	rows, err := s.db.Query(`SELECT id, ts, source, kind, src_ip, src_port, username, password, session_id, hassh, ssh_client, ja4, command, sha256, filename, raw, actor_id
FROM events WHERE source=? ORDER BY ts ASC`, source)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		e := &models.Event{}
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Source, &e.Kind, &e.SrcIP, &e.SrcPort, &e.Username, &e.Password,
			&e.SessionID, &e.HASSH, &e.SSHClient, &e.JA4, &e.Command, &e.SHA256, &e.Filename, &e.Raw, &e.ActorID); err != nil {
			return err
		}
		e.TS, _ = time.Parse(time.RFC3339Nano, ts)
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}


