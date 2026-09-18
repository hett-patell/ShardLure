package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const eventTimeBackfillPath = "events-ts-v20"

// EventTimeBackfillResult describes one bounded migration batch. Invalid rows
// are left untouched but the durable ID cursor advances past them, so one
// corrupt legacy timestamp cannot stall every later row and every restart.
type EventTimeBackfillResult struct {
	Scanned int
	Updated int
	Invalid int
	Done    bool
}

// BackfillEventTimes normalizes at most limit legacy event timestamps and
// populates their exact epoch nanoseconds. Each call uses one short write
// transaction and persists its ID cursor in ingest_state.
func (s *Store) BackfillEventTimes(ctx context.Context, limit int) (EventTimeBackfillResult, error) {
	if err := ctx.Err(); err != nil {
		return EventTimeBackfillResult{}, err
	}
	if limit <= 0 {
		limit = 1000
	}

	var cursor int64
	err := s.db.QueryRowContext(ctx,
		"SELECT offset FROM ingest_state WHERE source=? AND path=?",
		"migration", eventTimeBackfillPath).Scan(&cursor)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return EventTimeBackfillResult{}, err
	}

	type eventTimeRow struct {
		id     int64
		text   string
		parsed time.Time
		valid  bool
	}
	rows, err := s.db.QueryContext(ctx,
		"SELECT id,ts FROM events WHERE id>? AND ts_unix_ns IS NULL ORDER BY id LIMIT ?",
		cursor, limit)
	if err != nil {
		return EventTimeBackfillResult{}, err
	}
	var batch []eventTimeRow
	for rows.Next() {
		var row eventTimeRow
		if err := rows.Scan(&row.id, &row.text); err != nil {
			rows.Close()
			return EventTimeBackfillResult{}, err
		}
		row.parsed, err = time.Parse(time.RFC3339Nano, row.text)
		row.valid = err == nil
		batch = append(batch, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return EventTimeBackfillResult{}, err
	}
	rows.Close()

	result := EventTimeBackfillResult{Scanned: len(batch), Done: len(batch) < limit}
	if len(batch) == 0 {
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		return EventTimeBackfillResult{}, err
	}
	lastID := batch[len(batch)-1].id
	err = s.WithTx(func(tx *sql.Tx) error {
		for _, row := range batch {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !row.valid {
				result.Invalid++
				continue
			}
			res, err := tx.ExecContext(ctx,
				"UPDATE events SET ts=?,ts_unix_ns=? WHERE id=? AND ts_unix_ns IS NULL",
				formatFixedUTC(row.parsed), row.parsed.UnixNano(), row.id)
			if err != nil {
				return err
			}
			if n, err := res.RowsAffected(); err == nil {
				result.Updated += int(n)
			}
		}
		_, err := tx.ExecContext(ctx, `
INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at)
VALUES('migration',?,0,?,'',?)
ON CONFLICT(source,path) DO UPDATE SET offset=excluded.offset,updated_at=excluded.updated_at`,
			eventTimeBackfillPath, lastID, formatFixedUTC(time.Now()))
		return err
	})
	if err != nil {
		return EventTimeBackfillResult{}, err
	}
	return result, nil
}
