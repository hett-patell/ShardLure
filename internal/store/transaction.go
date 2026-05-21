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

func (s *Store) ReplaceSourceEventsAndActors(source models.Source, events []*models.Event, actors []*models.Actor) error {
	return s.WithTx(func(tx *sql.Tx) error {
		if err := clearSourceTx(tx, source); err != nil {
			return err
		}
		for _, e := range events {
			if err := insertEvent(tx, e); err != nil {
				return err
			}
		}
		return replaceActorsTx(tx, source, events, actors)
	})
}

func (s *Store) AppendEventsAndReplaceActors(source models.Source, fresh []*models.Event, all []*models.Event, actors []*models.Actor) error {
	return s.WithTx(func(tx *sql.Tx) error {
		for _, e := range fresh {
			if err := insertEvent(tx, e); err != nil {
				return err
			}
		}
		return replaceActorsTx(tx, source, all, actors)
	})
}

func replaceActorsTx(tx *sql.Tx, source models.Source, events []*models.Event, actors []*models.Actor) error {
	if err := deleteActorsTx(tx, source); err != nil {
		return err
	}

	// Single pass over events: bucket by actor_id so the outer loop over
	// actors is O(M) lookup instead of O(N) per actor.
	byActor := make(map[string][]*models.Event, len(actors))
	for _, e := range events {
		if e.ActorID == "" {
			continue
		}
		byActor[e.ActorID] = append(byActor[e.ActorID], e)
	}

	for _, a := range actors {
		if err := upsertActor(tx, a); err != nil {
			return err
		}

		ipStats := map[string]struct {
			count int
			first time.Time
			last  time.Time
		}{}
		userStats := map[string]int{}

		for _, e := range byActor[a.ID] {
			if e.ID != 0 {
				if err := updateEventActor(tx, e.ID, a.ID); err != nil {
					return err
				}
			}
			if e.SrcIP != "" {
				st := ipStats[e.SrcIP]
				st.count++
				if st.first.IsZero() || e.TS.Before(st.first) {
					st.first = e.TS
				}
				if e.TS.After(st.last) {
					st.last = e.TS
				}
				ipStats[e.SrcIP] = st
			}
			if e.Username != "" {
				userStats[e.Username]++
			}
		}

		for ip, st := range ipStats {
			if err := upsertActorIP(tx, a.ID, ip, st.first, st.last, st.count); err != nil {
				return err
			}
		}
		for username, count := range userStats {
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
