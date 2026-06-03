package store

import (
	"database/sql"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func (s *Store) WithTx(fn func(*sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ReplaceSourceEventsAndActorsAgg is the aggregate-aware replacement for the
// older ReplaceSourceEventsAndActors. It accepts pre-computed per-IP and
// per-user roll-ups from the builder so persistence does NOT scan events a
// second time (was O(N) per actor in addition to the builder's O(N)).
func (s *Store) ReplaceSourceEventsAndActorsAgg(source models.Source, events []*models.Event, actors []*models.AggregatedActor) error {
	return s.WithTx(func(tx *sql.Tx) error {
		if err := clearSourceTx(tx, source); err != nil {
			return err
		}
		for _, e := range events {
			if err := insertEvent(tx, e); err != nil {
				return err
			}
		}
		return writeActorsTx(tx, actors)
	})
}

// AppendEventsAndReplaceActorsAgg inserts fresh events and rewrites all
// per-source actor rows using aggregate stats from the builder.
func (s *Store) AppendEventsAndReplaceActorsAgg(source models.Source, fresh []*models.Event, actors []*models.AggregatedActor) error {
	return s.WithTx(func(tx *sql.Tx) error {
		for _, e := range fresh {
			if err := insertEvent(tx, e); err != nil {
				return err
			}
		}
		if err := deleteActorsTx(tx, source); err != nil {
			return err
		}
		return writeActorsTx(tx, actors)
	})
}

// AppendEventsAndUpsertActorsAgg inserts fresh events and upserts ONLY the
// supplied (touched) actors — it does not delete and rewrite every actor of
// the source. This is the incremental counterpart to
// AppendEventsAndReplaceActorsAgg: the caller re-aggregates just the actors the
// fresh batch touched (from their full event history) and passes them here, so
// a live ingest tick costs O(events-touched-this-tick) instead of O(all
// history). Untouched actors are left exactly as they were.
//
// Because each upserted actor was rebuilt from its complete event set, the
// actor row's totals are authoritative; but its actor_ips / actor_users child
// rows are upserted, not replaced, so stale child rows from a previous
// aggregation could linger if a user/IP somehow disappeared from an actor's
// history (which does not happen on append-only ingest). To stay correct under
// arbitrary rebuilds we clear the touched actors' child rows first, then
// rewrite them from the fresh aggregate.
func (s *Store) AppendEventsAndUpsertActorsAgg(fresh []*models.Event, actors []*models.AggregatedActor) error {
	return s.WithTx(func(tx *sql.Tx) error {
		for _, e := range fresh {
			if err := insertEvent(tx, e); err != nil {
				return err
			}
		}
		for _, agg := range actors {
			if err := deleteActorChildrenTx(tx, agg.Actor.ID); err != nil {
				return err
			}
		}
		return writeActorsTx(tx, actors)
	})
}

// deleteActorChildrenTx removes the actor_ips / actor_users rows for a single
// actor so they can be rewritten from a fresh aggregate without leaving stale
// child rows. The actor row itself is upserted (not deleted) by writeActorsTx.
func deleteActorChildrenTx(tx *sql.Tx, actorID string) error {
	if _, err := tx.Exec("DELETE FROM actor_ips WHERE actor_id=?", actorID); err != nil {
		return err
	}
	_, err := tx.Exec("DELETE FROM actor_users WHERE actor_id=?", actorID)
	return err
}

func writeActorsTx(tx *sql.Tx, actors []*models.AggregatedActor) error {
	for _, agg := range actors {
		a := agg.Actor
		if err := upsertActor(tx, a); err != nil {
			return err
		}
		for ip, st := range agg.IPs {
			if err := upsertActorIP(tx, a.ID, ip, st.First, st.Last, st.Count); err != nil {
				return err
			}
		}
		for username, count := range agg.Users {
			if err := upsertActorUser(tx, a.ID, username, count); err != nil {
				return err
			}
		}
	}
	return nil
}

func clearSourceTx(tx *sql.Tx, source models.Source) error {
	if err := deleteActorsTx(tx, source); err != nil {
		return err
	}
	_, err := tx.Exec("DELETE FROM events WHERE source=?", source)
	return err
}

// UpsertJournalActorAtomic applies the three actor-related writes
// (actor row, single-IP row, optional user row) for a freshly-
// observed journal event in one transaction. The live journal tail
// calls this on every event so callers must keep it cheap; it does
// not iterate event history, only writes the rows the in-memory
// collector says changed.
//
// A nil username (empty or "?") skips the user upsert. The IP row
// is always written because journal actors are one-IP-each.
func (s *Store) UpsertJournalActorAtomic(a *models.Actor, ip string, ipFirst, ipLast time.Time, ipCount int, username string, userCount int) error {
	return s.WithTx(func(tx *sql.Tx) error {
		if err := upsertActor(tx, a); err != nil {
			return err
		}
		if err := upsertActorIP(tx, a.ID, ip, ipFirst, ipLast, ipCount); err != nil {
			return err
		}
		if username != "" && username != "?" {
			if err := upsertActorUser(tx, a.ID, username, userCount); err != nil {
				return err
			}
		}
		return nil
	})
}

func deleteActorsTx(tx *sql.Tx, source models.Source) error {
	if _, err := tx.Exec("DELETE FROM actor_ips WHERE actor_id IN (SELECT id FROM actors WHERE source=?)", source); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM actor_users WHERE actor_id IN (SELECT id FROM actors WHERE source=?)", source); err != nil {
		return err
	}
	_, err := tx.Exec("DELETE FROM actors WHERE source=?", source)
	return err
}
