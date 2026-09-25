package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type JournalCounters struct {
	Count, UniqueUsers int
	First, Last        time.Time
}

type JournalDerived struct {
	Playbook, UsernameHash, GeneratedNotes string
	Confidence, ProbeScore                 int
}

// The actor package implements this contract: storage owns the transaction and
// durable cursor, but never imports the classifier or retains its username map.
type JournalSummaryCodec interface {
	Start() ([]byte, error)
	AddUser(state []byte, username string) ([]byte, error)
	Finish(state []byte, counters JournalCounters) (JournalDerived, error)
}

var ErrJournalSummaryCoverage = errors.New("journal summary: incomplete historical coverage")

// Actor rows and aggregate distributions must expose the same derivation
// state. Retaining a legacy label on disk must not silently certify it in a
// chart after the individual actor reader has correctly masked it.
const journalDerivedStateSQL = `CASE WHEN source<>'journal' THEN 'current' ELSE COALESCE((
SELECT CASE WHEN status='current' AND completed_revision=corpus_revision THEN 'current'
WHEN status='unknown_history' THEN status ELSE 'pending' END
FROM journal_summaries js WHERE js.actor_id=actors.id),'unknown_history') END`

const actorVisiblePlaybookSQL = "CASE WHEN (" + journalDerivedStateSQL + ")='current' THEN playbook ELSE (" + journalDerivedStateSQL + ") END"

func (s *Store) migrateJournalSummaries(now string) error {
	return s.WithTx(func(tx *sql.Tx) error {
		has, err := columnExistsIn(tx, "actors", "generated_notes")
		if err != nil {
			return err
		}
		if !has {
			if _, err := tx.Exec("ALTER TABLE actors ADD COLUMN generated_notes TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
		}
		_, err = tx.Exec(`CREATE TABLE IF NOT EXISTS journal_summaries(
 actor_id TEXT PRIMARY KEY,
 corpus_revision INTEGER NOT NULL DEFAULT 0,
 building_revision INTEGER NOT NULL DEFAULT -1,
 completed_revision INTEGER NOT NULL DEFAULT -1,
 user_cursor TEXT NOT NULL DEFAULT '',
 fold_state BLOB,
 status TEXT NOT NULL DEFAULT 'unknown_history' CHECK(status IN ('pending','current','unknown_history'))
);
CREATE INDEX IF NOT EXISTS idx_journal_summary_pending ON journal_summaries(actor_id) WHERE status='pending';
CREATE TRIGGER IF NOT EXISTS journal_summary_actor_insert AFTER INSERT ON actors WHEN NEW.source='journal'
BEGIN INSERT OR IGNORE INTO journal_summaries(actor_id) VALUES(NEW.id); END;
CREATE TRIGGER IF NOT EXISTS journal_summary_actor_delete AFTER DELETE ON actors
BEGIN DELETE FROM journal_summaries WHERE actor_id=OLD.id; END;
CREATE TRIGGER IF NOT EXISTS journal_summary_counters AFTER UPDATE OF event_count,unique_users,first_seen,last_seen ON actors WHEN NEW.source='journal'
BEGIN UPDATE journal_summaries SET status=CASE WHEN status='unknown_history' THEN status ELSE 'pending' END WHERE actor_id=NEW.id; END;
CREATE TRIGGER IF NOT EXISTS journal_summary_user_insert AFTER INSERT ON actor_users
BEGIN UPDATE journal_summaries SET corpus_revision=corpus_revision+1,status=CASE WHEN status='unknown_history' THEN status ELSE 'pending' END WHERE actor_id=NEW.actor_id; END;
CREATE TRIGGER IF NOT EXISTS journal_summary_user_delete AFTER DELETE ON actor_users
BEGIN UPDATE journal_summaries SET corpus_revision=corpus_revision+1,status=CASE WHEN status='unknown_history' THEN status ELSE 'pending' END WHERE actor_id=OLD.actor_id; END;
CREATE TRIGGER IF NOT EXISTS journal_summary_user_identity AFTER UPDATE OF username,actor_id ON actor_users WHEN NEW.username IS NOT OLD.username OR NEW.actor_id IS NOT OLD.actor_id
BEGIN UPDATE journal_summaries SET corpus_revision=corpus_revision+1,status=CASE WHEN status='unknown_history' THEN status ELSE 'pending' END WHERE actor_id IN (NEW.actor_id,OLD.actor_id); END;
`)
		if err != nil {
			return err
		}
		_, err = tx.Exec("INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(23,?)", now)
		return err
	})
}

func (s *Store) LoadJournalCounters(ctx context.Context, actorID, ip string) (JournalCounters, error) {
	var out JournalCounters
	var first, last string
	err := s.db.QueryRowContext(ctx, `SELECT ai.count,a.unique_users,ai.first_seen,ai.last_seen
FROM actor_ips ai JOIN actors a ON a.id=ai.actor_id
WHERE ai.actor_id=? AND ai.ip=? AND a.source='journal'`, actorID, ip).Scan(&out.Count, &out.UniqueUsers, &first, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return JournalCounters{}, err
	}
	if out.First, err = parseTime(first); err != nil {
		return JournalCounters{}, errors.New("journal counters: invalid timestamp")
	}
	if out.Last, err = parseTime(last); err != nil {
		return JournalCounters{}, errors.New("journal counters: invalid timestamp")
	}
	return out, nil
}

func (s *Store) PendingJournalSummaries(ctx context.Context, limit int) ([]string, error) {
	return s.PendingJournalSummariesAfter(ctx, "", limit)
}

// PendingJournalSummariesAfter pages pending actors in actor_id order,
// strictly after the given id, so a caller can move past an actor whose
// derivation keeps failing instead of re-reading the same first page.
func (s *Store) PendingJournalSummariesAfter(ctx context.Context, after string, limit int) ([]string, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, "SELECT actor_id FROM journal_summaries WHERE status='pending' AND actor_id>? ORDER BY actor_id LIMIT ?", after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Pages cap both names and bytes. A pathological raw DB entry bigger than the
// parser's entire 1 MiB input budget is kept, but cannot produce an exact label.
const journalSummaryPageBytes = 1 << 20
const journalSummaryStateBytes = 8192

func (s *Store) AdvanceJournalSummary(ctx context.Context, actorID string, limit int, codec JournalSummaryCodec) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if codec == nil {
		return false, errors.New("journal summary: missing codec")
	}
	if limit <= 0 || limit > 1000 {
		limit = 256
	}
	done := false
	err := s.WithTx(func(tx *sql.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var revision, building, completed int64
		var cursor, status string
		var state []byte
		err := tx.QueryRowContext(ctx, "SELECT corpus_revision,building_revision,completed_revision,user_cursor,CASE WHEN length(fold_state)<=? THEN fold_state ELSE NULL END,status FROM journal_summaries WHERE actor_id=?", journalSummaryStateBytes, actorID).Scan(&revision, &building, &completed, &cursor, &state, &status)
		if errors.Is(err, sql.ErrNoRows) {
			done = true
			return nil
		}
		if err != nil {
			return err
		}
		if status == "unknown_history" {
			done = true
			return nil
		}
		reset := func() error {
			fresh, err := codec.Start()
			if err != nil {
				return err
			}
			if len(fresh) > journalSummaryStateBytes {
				return errors.New("journal summary: oversized state")
			}
			_, err = tx.ExecContext(ctx, "UPDATE journal_summaries SET building_revision=?,completed_revision=-1,user_cursor='',fold_state=?,status='pending' WHERE actor_id=?", revision, fresh, actorID)
			return err
		}
		if building != revision || len(state) == 0 || len(state) > journalSummaryStateBytes {
			state, err = codec.Start()
			if err != nil {
				return err
			}
			cursor = ""
			completed = -1
			if len(state) > journalSummaryStateBytes {
				return errors.New("journal summary: oversized state")
			}
		}
		more := false
		if completed != revision {
			// Return NULL instead of copying an unbounded username into Go. Sort
			// by the original indexed key, never the nullable expression.
			rows, err := tx.QueryContext(ctx, `SELECT CASE WHEN length(CAST(username AS BLOB))<=? THEN username ELSE NULL END
FROM actor_users WHERE actor_id=? AND username>? ORDER BY username LIMIT ?`, journalSummaryPageBytes, actorID, cursor, limit+1)
			if err != nil {
				return err
			}
			used, n := 0, 0
			invalid := false
			for rows.Next() {
				if err := ctx.Err(); err != nil {
					rows.Close()
					return err
				}
				var name sql.NullString
				if err := rows.Scan(&name); err != nil {
					rows.Close()
					return err
				}
				if !name.Valid {
					invalid = true
					break
				}
				if n == limit || used+len(name.String) > journalSummaryPageBytes {
					more = true
					break
				}
				state, err = codec.AddUser(state, name.String)
				if err != nil || len(state) > journalSummaryStateBytes {
					rows.Close()
					return reset()
				}
				cursor = name.String
				used += len(name.String)
				n++
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			if invalid {
				_, err := tx.ExecContext(ctx, "UPDATE journal_summaries SET status='unknown_history' WHERE actor_id=?", actorID)
				done = err == nil
				return err
			}
			if more {
				_, err := tx.ExecContext(ctx, "UPDATE journal_summaries SET building_revision=?,completed_revision=-1,user_cursor=?,fold_state=?,status='pending' WHERE actor_id=?", revision, cursor, state, actorID)
				return err
			}
		}
		var counters JournalCounters
		var first, last string
		if err := tx.QueryRowContext(ctx, "SELECT event_count,unique_users,first_seen,last_seen FROM actors WHERE id=? AND source='journal'", actorID).Scan(&counters.Count, &counters.UniqueUsers, &first, &last); err != nil {
			return err
		}
		if counters.First, err = parseTime(first); err != nil {
			return errors.New("journal summary: invalid first timestamp")
		}
		if counters.Last, err = parseTime(last); err != nil {
			return errors.New("journal summary: invalid last timestamp")
		}
		derived, err := codec.Finish(state, counters)
		if errors.Is(err, ErrJournalSummaryCoverage) {
			_, err := tx.ExecContext(ctx, "UPDATE journal_summaries SET status='unknown_history' WHERE actor_id=?", actorID)
			done = err == nil
			return err
		}
		if err != nil {
			return reset()
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// Writer serialization and this transaction fence the revision and
		// counters together. A later name invalidates the published result.
		if _, err := tx.ExecContext(ctx, "UPDATE actors SET playbook=?,username_hash=?,generated_notes=?,confidence=?,probe_score=? WHERE id=?", derived.Playbook, derived.UsernameHash, derived.GeneratedNotes, derived.Confidence, derived.ProbeScore, actorID); err != nil {
			return err
		}
		if completed != revision {
			_, err = tx.ExecContext(ctx, "UPDATE journal_summaries SET building_revision=?,completed_revision=?,user_cursor=?,fold_state=?,status='current' WHERE actor_id=? AND corpus_revision=?", revision, revision, cursor, state, actorID, revision)
		} else {
			_, err = tx.ExecContext(ctx, "UPDATE journal_summaries SET status='current' WHERE actor_id=? AND corpus_revision=?", actorID, revision)
		}
		done = err == nil
		return err
	})
	if err != nil {
		return false, err
	}
	return done, nil
}
