package store

import (
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

const fullEventColumns = `id, ts, source, kind, COALESCE(src_ip,''), COALESCE(src_port,0), COALESCE(username,''), COALESCE(password,''), COALESCE(session_id,''), COALESCE(hassh,''), COALESCE(ssh_client,''), COALESCE(command,''), COALESCE(sha256,''), COALESCE(filename,''), COALESCE(dst_ip,''), COALESCE(dst_port,0), COALESCE(raw,''), COALESCE(actor_id,'')`

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
	rows, err := s.db.Query("SELECT "+eventTimeBucketSQL+" AS time_bucket,"+fullEventColumns+
		" FROM events WHERE source=? ORDER BY time_bucket ASC,id ASC", source)
	if err != nil {
		return err
	}
	defer rows.Close()
	return iterateFullEventRowsExact(rows, fn)
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
	q := "SELECT " + eventTimeBucketSQL + " AS time_bucket," + fullEventColumns +
		" FROM events WHERE actor_id=? ORDER BY time_bucket ASC,id ASC"
	for _, id := range ids {
		rows, err := s.db.Query(q, id)
		if err != nil {
			return err
		}
		err = func() error {
			defer rows.Close()
			return iterateFullEventRowsExact(rows, fn)
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func iterateFullEventRowsExact(rows *sql.Rows, fn func(*models.Event) error) error {
	type bucketedEvent struct {
		bucket sql.NullInt64
		event  *models.Event
	}
	var group []bucketedEvent
	flush := func() error {
		sort.Slice(group, func(i, j int) bool {
			a, b := group[i].event, group[j].event
			if !a.TS.Equal(b.TS) {
				return a.TS.Before(b.TS)
			}
			return a.ID < b.ID
		})
		for _, item := range group {
			if err := fn(item.event); err != nil {
				return err
			}
		}
		group = group[:0]
		return nil
	}
	equalBucket := func(a, b sql.NullInt64) bool {
		return a.Valid == b.Valid && (!a.Valid || a.Int64 == b.Int64)
	}
	for rows.Next() {
		var item bucketedEvent
		item.event = &models.Event{}
		var ts string
		if err := rows.Scan(&item.bucket, &item.event.ID, &ts, &item.event.Source, &item.event.Kind,
			&item.event.SrcIP, &item.event.SrcPort, &item.event.Username, &item.event.Password,
			&item.event.SessionID, &item.event.HASSH, &item.event.SSHClient, &item.event.Command,
			&item.event.SHA256, &item.event.Filename, &item.event.DstIP, &item.event.DstPort,
			&item.event.Raw, &item.event.ActorID); err != nil {
			return err
		}
		parsed, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return fmt.Errorf("event %d ts: %w", item.event.ID, err)
		}
		item.event.TS = parsed
		if len(group) > 0 && !equalBucket(group[0].bucket, item.bucket) {
			if err := flush(); err != nil {
				return err
			}
		}
		group = append(group, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return flush()
}
