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
	normalizedTS := CanonicalEventTime(stored.TS)
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
			// The resident username map is a bounded cache, not an absolute
			// counter. Increment the real name only after dedup, in this same
			// transaction; overflow and cache eviction cannot inflate it.
			if update.Username != "" && update.Username != "?" {
				if _, err := tx.Exec(`INSERT INTO actor_users(actor_id,username,count) VALUES(?,?,1)
ON CONFLICT(actor_id,username) DO UPDATE SET count=actor_users.count+1`, update.Actor.ID, update.Username); err != nil {
					return err
				}
			}
			a := *update.Actor
			if err := tx.QueryRow(`SELECT COUNT(*) FROM actor_users WHERE actor_id=?`, a.ID).Scan(&a.UniqueUsers); err != nil {
				return err
			}
			if err := upsertActor(tx, &a); err != nil {
				return err
			}
			if err := upsertActorIP(tx, update.Actor.ID, stored.SrcIP, update.IPFirst, update.IPLast, update.IPCount); err != nil {
				return err
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

// ReconcileSessionHASSH transfers only the session's retained evidence between
// lifetime aggregates. Reads, callback and writes share the writer transaction;
// callers must not use Store methods inside reconcile (writeMu is not reentrant).
// The iterator excludes already-canonical rows, so retrying never double-counts.
func (s *Store) ReconcileSessionHASSH(sessionID, newActorID, hassh string,
	reconcile func(map[string]*ActorState, func(func(*models.Event) error) error) ([]*models.AggregatedActor, error)) error {
	if sessionID == "" || hassh == "" || newActorID == "" {
		return errors.New("store: empty HASSH reconciliation identity")
	}
	return s.WithTx(func(tx *sql.Tx) error {
		rows, err := tx.Query("SELECT DISTINCT actor_id FROM events WHERE source=? AND session_id=? AND actor_id<>? AND actor_id<>''", models.SourceCowrie, sessionID, newActorID)
		if err != nil {
			return err
		}
		ids := []string{newActorID}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(ids) > 1 {
			states, err := actorStatesForIDs(tx, ids)
			if err != nil {
				return err
			}
			stream := func(fn func(*models.Event) error) error {
				rows, err := tx.Query(
					"SELECT ts,kind,COALESCE(src_ip,''),COALESCE(username,''),COALESCE(ssh_client,''),COALESCE(command,''),COALESCE(sha256,''),actor_id FROM events WHERE source=? AND session_id=? AND actor_id<>? AND actor_id<>'' ORDER BY ts",
					models.SourceCowrie, sessionID, newActorID)
				if err != nil {
					return err
				}
				defer rows.Close()
				for rows.Next() {
					e := &models.Event{Source: models.SourceCowrie, SessionID: sessionID, HASSH: hassh}
					var ts string
					if err := rows.Scan(&ts, &e.Kind, &e.SrcIP, &e.Username, &e.SSHClient, &e.Command, &e.SHA256, &e.ActorID); err != nil {
						return err
					}
					e.TS, err = parseTime(ts)
					if err != nil {
						return err
					}
					if err := fn(e); err != nil {
						return err
					}
				}
				return rows.Err()
			}
			updated, err := reconcile(states, stream)
			if err != nil {
				return err
			}
			for _, id := range ids {
				if err := deleteActorChildrenTx(tx, id); err != nil {
					return err
				}
			}
			if err := writeActorsTx(tx, updated); err != nil {
				return err
			}
			for _, agg := range updated {
				a := agg.Actor
				// Retention is not proof that an actor has no lifetime evidence. Only
				// a genuinely empty, unannotated aggregate may be removed.
				if a.ID != newActorID && a.EventCount == 0 && a.Campaigns == "" && a.Notes == "" {
					if _, err := tx.Exec("DELETE FROM actors WHERE id=?", a.ID); err != nil {
						return err
					}
				}
			}
		}
		// Also repairs legacy rows whose actor_id was already moved but whose
		// HASSH was left empty. Blank actor IDs (admin exemptions) stay blank.
		_, err = tx.Exec("UPDATE events SET hassh=?,actor_id=CASE WHEN COALESCE(actor_id,'')='' THEN actor_id ELSE ? END WHERE source=? AND session_id=? AND (COALESCE(hassh,'')<>? OR (actor_id<>'' AND actor_id<>?))", hassh, newActorID, models.SourceCowrie, sessionID, hassh, newActorID)
		return err
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
