package store

import (
	"context"
	"github.com/networkshard/shardlure/pkg/models"
)

const fullEventColumns = `id, ts, source, kind, COALESCE(src_ip,''), COALESCE(src_port,0), COALESCE(username,''), COALESCE(password,''), COALESCE(session_id,''), COALESCE(hassh,''), COALESCE(ssh_client,''), COALESCE(command,''), COALESCE(sha256,''), COALESCE(filename,''), COALESCE(dst_ip,''), COALESCE(dst_port,0), COALESCE(raw,''), COALESCE(actor_id,'')`

// EventsBySource loads all source events. Use the iterator for large histories.
func (s *Store) EventsBySource(source models.Source) ([]*models.Event, error) {
	var out []*models.Event
	err := s.IterateEventsBySource(source, func(e *models.Event) error { out = append(out, e); return nil })
	return out, err
}

// IterateEventsBySource streams exact timestamp/ID order, including while the
// legacy backfill runs. SQLite orders legacy rows without a Go bucket buffer.
func (s *Store) IterateEventsBySource(source models.Source, fn func(*models.Event) error) error {
	query, args := orderedEventQuery(fullEventColumns, nil, "source=?", []any{source}, false, 0)
	rows, err := s.db.QueryContext(context.Background(), query, args...)
	if err != nil {
		return err
	}
	return iterateOrderedEventRows(rows, true, fn)
}

// IterateEventsByActorIDs preserves timestamp/ID order within each actor.
// The migrated branch can stream directly from idx_events_actor_ts.
func (s *Store) IterateEventsByActorIDs(ids []string, fn func(*models.Event) error) error {
	for _, id := range ids {
		query, args := orderedEventQuery(fullEventColumns, nil, "actor_id=?", []any{id}, false, 0)
		rows, err := s.db.QueryContext(context.Background(), query, args...)
		if err != nil {
			return err
		}
		if err := iterateOrderedEventRows(rows, true, fn); err != nil {
			return err
		}
	}
	return nil
}
