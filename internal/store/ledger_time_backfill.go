package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// LedgerTimeBackfillResult describes a committed bounded batch across all
// three ledgers. Invalid text remains authoritative and is never fabricated
// into a successful zero-time submission. Its diagnostic cursor moves on.
type LedgerTimeBackfillResult struct {
	Scanned, Updated, Invalid int
	Done                      bool
}

func (s *Store) BackfillLedgerTimes(ctx context.Context, limit int) (LedgerTimeBackfillResult, error) {
	if err := ctx.Err(); err != nil {
		return LedgerTimeBackfillResult{}, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	var result LedgerTimeBackfillResult
	err := s.WithTx(func(tx *sql.Tx) error {
		for i, d := range submissionLedgers {
			if err := ctx.Err(); err != nil {
				return err
			}
			if result.Scanned == limit {
				return nil
			}
			ledger := submissionLedger(i)
			var cursor int64
			err := tx.QueryRowContext(ctx, "SELECT offset FROM ingest_state WHERE source='migration' AND path=?", ledger.backfillPath()).Scan(&cursor)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			// Rowid seeks cap work even when native rows are interspersed. Do not
			// use a timestamp-sorted partial index for an ID cursor: it can sort
			// the entire remaining legacy ledger on each nominally small page.
			rows, err := tx.QueryContext(ctx, "SELECT rowid,"+d.timestamp+","+d.key+" FROM "+d.table+" WHERE rowid>? ORDER BY rowid LIMIT ?", cursor, limit-result.Scanned)
			if err != nil {
				return err
			}
			type entry struct {
				id  int64
				raw string
				key sql.NullString
			}
			var batch []entry
			for rows.Next() {
				var r entry
				if err := rows.Scan(&r.id, &r.raw, &r.key); err != nil {
					rows.Close()
					return err
				}
				batch = append(batch, r)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			if len(batch) == 0 {
				continue
			}
			for _, r := range batch {
				if err := ctx.Err(); err != nil {
					return err
				}
				result.Scanned++
				if r.key.Valid {
					continue
				}
				at, err := parseLedgerTimestamp(r.raw)
				if err != nil {
					result.Invalid++
					continue
				}
				if _, err := tx.ExecContext(ctx, "UPDATE "+d.table+" SET "+d.key+"=? WHERE rowid=?", formatFixedUTC(at), r.id); err != nil {
					return err
				}
				result.Updated++
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES('migration',?,0,?,'',?)
ON CONFLICT(source,path) DO UPDATE SET offset=excluded.offset,updated_at=excluded.updated_at`, ledger.backfillPath(), batch[len(batch)-1].id, formatFixedUTC(time.Now()))
			if err != nil {
				return err
			}
		}
		// Hitting exactly the budget requires one further (empty) confirmation
		// batch; Done never promises that unvisited rows are already repaired.
		result.Done = result.Scanned < limit
		return ctx.Err()
	})
	if err != nil {
		if ctx.Err() != nil {
			return LedgerTimeBackfillResult{}, ctx.Err()
		}
		return LedgerTimeBackfillResult{}, errors.New("submission ledger time backfill failed")
	}
	return result, nil
}
