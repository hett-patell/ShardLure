package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func (s *Store) WithTx(fn func(*sql.Tx) error) error {
	// Serialize write transactions (single SQLite writer) while leaving reads
	// concurrent. Held for the whole tx so the begin→commit window can't race
	// another writer's lock acquisition.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
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

// JournalActorUpdate contains the actor roll-up written alongside a newly
// inserted journal event. The event's source IP identifies the actor_ips row.
type JournalActorUpdate struct {
	Actor     *models.Actor
	IPFirst   time.Time
	IPLast    time.Time
	IPCount   int
	Username  string
	UserCount int
}

// AppendJournalEventAtomic deduplicates an exact normalized journal event and
// writes the event plus its optional actor roll-up in one transaction. Event
// IDs are published to the caller only after the transaction commits.
func (s *Store) AppendJournalEventAtomic(e *models.Event, update *JournalActorUpdate) (inserted bool, err error) {
	if e == nil {
		return false, errors.New("store: nil journal event")
	}
	if update != nil && update.Actor == nil {
		return false, errors.New("store: journal actor update has nil actor")
	}

	stored := *e
	normalizedTS := stored.TS.UTC().Format(time.RFC3339Nano)
	err = s.WithTx(func(tx *sql.Tx) error {
		var exists int
		err := tx.QueryRow(`
SELECT 1
FROM events INDEXED BY idx_events_ts
WHERE ts = ?
  AND source = ?
  AND kind = ?
  AND COALESCE(src_ip, '') = ?
  AND COALESCE(src_port, 0) = ?
  AND COALESCE(username, '') = ?
  AND COALESCE(raw, '') = ?
LIMIT 1`, normalizedTS, stored.Source, stored.Kind, stored.SrcIP, stored.SrcPort, stored.Username, stored.Raw).Scan(&exists)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}

		if err := insertEvent(tx, &stored); err != nil {
			return err
		}
		if update != nil {
			if err := upsertActor(tx, update.Actor); err != nil {
				return err
			}
			if err := upsertActorIP(tx, update.Actor.ID, stored.SrcIP, update.IPFirst, update.IPLast, update.IPCount); err != nil {
				return err
			}
			if update.Username != "" && update.Username != "?" {
				if err := upsertActorUser(tx, update.Actor.ID, update.Username, update.UserCount); err != nil {
					return err
				}
			}
		}
		inserted = true
		return nil
	})
	if err != nil {
		return false, err
	}
	if !inserted {
		return false, nil
	}
	e.ID = stored.ID
	return true, nil
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

// ReconcileSessionHASSH updates events for a cowrie session whose actor_id
// was assigned before the session's HASSH fingerprint was known (the common
// case: connect/login events arrive before cowrie.client.kex). It rewrites
// every event for sessionID whose actor_id differs from newActorID to use
// newActorID, then deletes and rewrites the aggregate rows for every old and
// new actor ID involved. Zero-event actor rows (including the old IP-based
// actor if all its events moved) are deleted so the dashboard never shows a
// ghost actor. The caller supplies pre-rebuilt aggregates for the affected
// actor IDs so this method is pure storage plumbing.
func (s *Store) ReconcileSessionHASSH(sessionID, newActorID string, rebuilt []*models.AggregatedActor) error {
	return s.WithTx(func(tx *sql.Tx) error {
		// Discover old actor IDs: distinct actor_id values on this session's
		// events that differ from newActorID.
		oldRows, err := tx.Query(
			`SELECT DISTINCT actor_id FROM events WHERE session_id=? AND actor_id<>? AND actor_id<>''`,
			sessionID, newActorID)
		if err != nil {
			return err
		}
		var oldIDs []string
		func() {
			defer oldRows.Close()
			for oldRows.Next() {
				var id string
				if err := oldRows.Scan(&id); err != nil {
					return
				}
				oldIDs = append(oldIDs, id)
			}
		}()
		if err := oldRows.Err(); err != nil {
			return err
		}
		if len(oldIDs) == 0 {
			return nil // nothing to reconcile
		}

		// Update the events' actor_id to the new value.
		if _, err := tx.Exec(
			`UPDATE events SET actor_id=? WHERE session_id=? AND actor_id<>? AND actor_id<>''`,
			newActorID, sessionID, newActorID); err != nil {
			return err
		}

		// Clear and rewrite aggregates for every affected actor ID (old + new).
		allIDs := append(oldIDs, newActorID)
		for _, id := range allIDs {
			if err := deleteActorChildrenTx(tx, id); err != nil {
				return err
			}
		}
		for _, agg := range rebuilt {
			if err := upsertActor(tx, agg.Actor); err != nil {
				return err
			}
			for ip, st := range agg.IPs {
				if err := upsertActorIP(tx, agg.Actor.ID, ip, st.First, st.Last, st.Count); err != nil {
					return err
				}
			}
			for username, count := range agg.Users {
				if err := upsertActorUser(tx, agg.Actor.ID, username, count); err != nil {
					return err
				}
			}
		}

		// Delete any actor rows that now have zero events (the old IP-based
		// actor that was fully subsumed by the HASSH actor).
		for _, id := range oldIDs {
			var n int
			if err := tx.QueryRow(
				`SELECT COUNT(1) FROM events WHERE actor_id=?`, id).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				if _, err := tx.Exec(`DELETE FROM actors WHERE id=?`, id); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ActorIDsForSession returns the distinct actor_id values on committed events
// for the given session, excluding excludeID. Used by the late-HASSH
// reconciliation to discover whether a session's earlier events were
// committed under a different (IP-based) actor ID.
func (s *Store) ActorIDsForSession(sessionID, excludeID string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT DISTINCT actor_id FROM events WHERE session_id=? AND actor_id<>? AND actor_id<>''`,
		sessionID, excludeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
