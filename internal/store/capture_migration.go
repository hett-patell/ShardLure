package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// captureTime is fixed-width UTC, so timestamps written by the queue have
// chronological text order, including whole seconds and fractional seconds.
func captureTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000000Z") }

func (s *Store) migrateCaptureEvidence(now string) error {
	return s.WithTx(func(tx *sql.Tx) error {
		for _, col := range []string{"first_observed_at", "last_seen_at", "last_fetch_attempt_at", "last_successful_fetch_at", "lease_until"} {
			has, err := columnExistsIn(tx, "artifacts", col)
			if err != nil {
				return err
			}
			if !has {
				if _, err := tx.Exec("ALTER TABLE artifacts ADD COLUMN " + col + " TEXT"); err != nil {
					return err
				}
			}
		}
		_, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (19, ?)`, now)
		return err
	})
}

const artifactTimeBackfillPath = "artifacts-v19"

type ArtifactTimeBackfillResult struct {
	Scanned int
	Updated int
	Invalid int
	Done    bool
}

// BackfillArtifactTimes repairs at most limit pre-v19 artifact rows in one
// short transaction. The durable ID cursor makes the work resumable without
// holding startup or writeMu for the whole ledger.
func (s *Store) BackfillArtifactTimes(ctx context.Context, limit int) (ArtifactTimeBackfillResult, error) {
	if err := ctx.Err(); err != nil {
		return ArtifactTimeBackfillResult{}, err
	}
	if limit <= 0 {
		limit = 500
	}
	var cursor int64
	err := s.db.QueryRowContext(ctx, "SELECT offset FROM ingest_state WHERE source=? AND path=?",
		"migration", artifactTimeBackfillPath).Scan(&cursor)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ArtifactTimeBackfillResult{}, err
	}

	// julianday rounds away sub-millisecond precision; comparisons also turn
	// invalid dates into NULL and could silently choose today's registration
	// date as successful-fetch provenance. Parse in Go and fail closed instead.
	// Keyset pages bound memory even for a large imported artifact ledger.
	type legacyRow struct {
		id                        int64
		ts, created, status, next string
		attempts                  int
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, COALESCE(ts,''), COALESCE(created_at,''), status, COALESCE(next_attempt_at,''), attempt_count
FROM artifacts
WHERE id>? AND first_observed_at IS NULL AND last_seen_at IS NULL
ORDER BY id LIMIT ?`, cursor, limit)
	if err != nil {
		return ArtifactTimeBackfillResult{}, err
	}
	var batch []legacyRow
	for rows.Next() {
		var row legacyRow
		if err := rows.Scan(&row.id, &row.ts, &row.created, &row.status, &row.next, &row.attempts); err != nil {
			rows.Close()
			return ArtifactTimeBackfillResult{}, err
		}
		batch = append(batch, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return ArtifactTimeBackfillResult{}, err
	}
	rows.Close()
	result := ArtifactTimeBackfillResult{Scanned: len(batch), Done: len(batch) < limit}
	if len(batch) == 0 {
		return result, nil
	}
	lastID := batch[len(batch)-1].id
	err = s.WithTx(func(tx *sql.Tx) error {
		for _, row := range batch {
			if err := ctx.Err(); err != nil {
				return err
			}
			observed, obsErr := time.Parse(time.RFC3339Nano, row.ts)
			registered, regErr := time.Parse(time.RFC3339Nano, row.created)
			var first, seen, attempted, fetched, lease, next any
			invalid := obsErr != nil || regErr != nil
			if obsErr == nil {
				seen = captureTime(observed)
				first = seen
			}
			if obsErr == nil && regErr == nil {
				if registered.Before(observed) {
					first = captureTime(registered)
				}
				if row.status == "fetched" {
					fetched = first
				}
			}
			if row.attempts > 0 && regErr == nil {
				attempted = captureTime(registered)
			}
			if due, err := time.Parse(time.RFC3339Nano, row.next); err == nil {
				if row.status == "capturing" {
					lease = captureTime(due)
				} else {
					next = captureTime(due)
				}
			} else if row.next != "" {
				invalid = true
				if row.status == "capturing" || row.status == "failed" {
					row.status = "failed_permanently"
				}
			}
			detail := any(nil)
			if row.status == "failed_permanently" && row.next != "" && next == nil && lease == nil {
				detail = "invalid legacy capture schedule"
			}
			res, err := tx.Exec(`UPDATE artifacts SET first_observed_at=?, last_seen_at=?, last_fetch_attempt_at=?, last_successful_fetch_at=?, lease_until=?, next_attempt_at=?, status=?, detail=COALESCE(?,detail) WHERE id=? AND first_observed_at IS NULL AND last_seen_at IS NULL`, first, seen, attempted, fetched, lease, next, row.status, detail, row.id)
			if err != nil {
				return err
			}
			if n, err := res.RowsAffected(); err == nil {
				result.Updated += int(n)
			}
			if invalid {
				result.Invalid++
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at)
VALUES('migration',?,0,?,'',?)
ON CONFLICT(source,path) DO UPDATE SET offset=excluded.offset,updated_at=excluded.updated_at`,
			artifactTimeBackfillPath, lastID, captureTime(time.Now()))
		return err
	})
	if err != nil {
		return ArtifactTimeBackfillResult{}, err
	}
	return result, nil
}
