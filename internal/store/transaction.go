package store

import (
	"database/sql"

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
