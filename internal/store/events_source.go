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
	rows, err := s.db.Query(`SELECT id, ts, source, kind, src_ip, src_port, username, password, session_id, hassh, ssh_client, command, sha256, filename, dst_ip, dst_port, raw, actor_id
FROM events WHERE source=? ORDER BY ts ASC`, source)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		e := &models.Event{}
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Source, &e.Kind, &e.SrcIP, &e.SrcPort, &e.Username, &e.Password,
			&e.SessionID, &e.HASSH, &e.SSHClient, &e.Command, &e.SHA256, &e.Filename, &e.DstIP, &e.DstPort, &e.Raw, &e.ActorID); err != nil {
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
	// One equality query per actor rather than a chunked IN-list: with the
	// composite idx_events_actor_ts, `actor_id = ? ORDER BY ts` streams rows
	// pre-sorted straight off the index, while `actor_id IN (...) ORDER BY
	// ts` still forces a temp B-tree sort of all matched rows per chunk
	// (verified via EXPLAIN QUERY PLAN). Callers only need ts order WITHIN
	// each actor (the collectors key clusters by actor), and the touched-ID
	// set per live tick is small, so per-ID queries are the cheaper shape.
	const q = `SELECT id, ts, source, kind, src_ip, src_port, username, password, session_id, hassh, ssh_client, command, sha256, filename, dst_ip, dst_port, raw, actor_id
FROM events WHERE actor_id = ? ORDER BY ts ASC`
	for _, id := range ids {
		rows, err := s.db.Query(q, id)
		if err != nil {
			return err
		}
		err = func() error {
			defer rows.Close()
			for rows.Next() {
				e := &models.Event{}
				var ts string
				if err := rows.Scan(&e.ID, &ts, &e.Source, &e.Kind, &e.SrcIP, &e.SrcPort, &e.Username, &e.Password,
					&e.SessionID, &e.HASSH, &e.SSHClient, &e.Command, &e.SHA256, &e.Filename, &e.DstIP, &e.DstPort, &e.Raw, &e.ActorID); err != nil {
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
