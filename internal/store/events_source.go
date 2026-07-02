package store

import (
	"github.com/networkshard/shardlure/pkg/models"
)

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
	rows, err := s.db.Query(`SELECT id, ts, source, kind, src_ip, src_port, username, password, session_id, hassh, ssh_client, command, sha256, filename, raw, actor_id
FROM events WHERE source=? ORDER BY ts ASC`, source)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		e := &models.Event{}
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Source, &e.Kind, &e.SrcIP, &e.SrcPort, &e.Username, &e.Password,
			&e.SessionID, &e.HASSH, &e.SSHClient, &e.Command, &e.SHA256, &e.Filename, &e.Raw, &e.ActorID); err != nil {
			return err
		}
		e.TS, _ = parseTime(ts)
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// IterateEventsByActorIDs streams every event whose actor_id is in ids, in
// ts ASC order, invoking fn per row. Served by idx_events_actor. Used by the
// incremental cowrie actor rebuild so a 5s ingest tick re-aggregates only the
// handful of actors the fresh batch touched, instead of streaming the entire
// event history (IterateEventsBySource) every tick.
//
// ids is chunked to stay under SQLite's parameter limit. An empty ids is a
// no-op. fn follows the same contract as IterateEventsBySource.
func (s *Store) IterateEventsByActorIDs(ids []string, fn func(*models.Event) error) error {
	const chunk = 400
	for i := 0; i < len(ids); i += chunk {
		end := i + chunk
		if end > len(ids) {
			end = len(ids)
		}
		batch := ids[i:end]
		placeholders := make([]string, len(batch))
		args := make([]any, len(batch))
		for j, id := range batch {
			placeholders[j] = "?"
			args[j] = id
		}
		q := `SELECT id, ts, source, kind, src_ip, src_port, username, password, session_id, hassh, ssh_client, command, sha256, filename, raw, actor_id
FROM events WHERE actor_id IN (` + joinComma(placeholders) + `) ORDER BY ts ASC`
		rows, err := s.db.Query(q, args...)
		if err != nil {
			return err
		}
		err = func() error {
			defer rows.Close()
			for rows.Next() {
				e := &models.Event{}
				var ts string
				if err := rows.Scan(&e.ID, &ts, &e.Source, &e.Kind, &e.SrcIP, &e.SrcPort, &e.Username, &e.Password,
					&e.SessionID, &e.HASSH, &e.SSHClient, &e.Command, &e.SHA256, &e.Filename, &e.Raw, &e.ActorID); err != nil {
					return err
				}
				e.TS, _ = parseTime(ts)
				if err := fn(e); err != nil {
					return err
				}
			}
			return rows.Err()
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}
