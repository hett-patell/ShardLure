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

// The original cursor skipped rows touched before backfill. A fresh pass also
// repairs those rows on databases that have already completed v19/v20.
const artifactTimeBackfillPath = "artifacts-v19-repair-v2"

type ArtifactTimeBackfillResult struct {
	Scanned int
	Updated int
	Invalid int
	Done    bool
}

// BackfillArtifactTimes visits at most limit artifact rows (capped at 500) in
// one short transaction. Cursor, reads and repairs share writeMu and the same
// transaction: a claim, completion or touch cannot invalidate a repair's input.
func (s *Store) BackfillArtifactTimes(ctx context.Context, limit int) (ArtifactTimeBackfillResult, error) {
	if err := ctx.Err(); err != nil {
		return ArtifactTimeBackfillResult{}, err
	}
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	// Lazy DDL takes writeMu itself; it must run before WithTx.
	if err := s.ensureArtifactsTable(); err != nil {
		return ArtifactTimeBackfillResult{}, errors.New("artifact time backfill initialization failed")
	}
	var result ArtifactTimeBackfillResult
	err := s.WithTx(func(tx *sql.Tx) error {
		var cursor int64
		err := tx.QueryRowContext(ctx, `SELECT offset FROM ingest_state WHERE source='migration' AND path=?`, artifactTimeBackfillPath).Scan(&cursor)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		// Page by primary key, including modern rows, so a sparse legacy ledger
		// cannot turn a nominally bounded repair into a full-table scan.
		rows, err := tx.QueryContext(ctx, `SELECT `+artifactTimeRepairColumns+` FROM artifacts WHERE id>? ORDER BY id LIMIT ?`, cursor, limit)
		if err != nil {
			return err
		}
		var batch []artifactTimeRepairRow
		for rows.Next() {
			var row artifactTimeRepairRow
			if err := row.scan(rows); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, row)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		result = ArtifactTimeBackfillResult{Scanned: len(batch), Done: len(batch) < limit}
		if len(batch) == 0 {
			return nil
		}
		for _, row := range batch {
			if err := ctx.Err(); err != nil {
				return err
			}
			if row.first.Valid && row.seen.Valid {
				continue
			}
			invalid, err := repairArtifactTimeRow(ctx, tx, row)
			if err != nil {
				return err
			}
			result.Updated++
			if invalid {
				result.Invalid++
			}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at)
VALUES('migration',?,0,?,'',?)
ON CONFLICT(source,path) DO UPDATE SET offset=excluded.offset,updated_at=excluded.updated_at`,
			artifactTimeBackfillPath, batch[len(batch)-1].id, captureTime(time.Now()))
		return err
	})
	if err != nil {
		if ctx.Err() != nil {
			return ArtifactTimeBackfillResult{}, ctx.Err()
		}
		return ArtifactTimeBackfillResult{}, errors.New("artifact time backfill failed")
	}
	return result, nil
}

const artifactTimeRepairColumns = `id,ts,created_at,status,next_attempt_at,attempt_count,first_observed_at,last_seen_at,last_fetch_attempt_at,last_successful_fetch_at,lease_until`

type artifactTimeRepairRow struct {
	id                              int64
	ts, created, status             string
	attempts                        int
	first, seen, attempted, fetched sql.NullString
	lease, next                     sql.NullString
}

func (r *artifactTimeRepairRow) scan(row interface{ Scan(...any) error }) error {
	return row.Scan(&r.id, &r.ts, &r.created, &r.status, &r.next, &r.attempts, &r.first, &r.seen, &r.attempted, &r.fetched, &r.lease)
}

// repairArtifactTimesForURL must run in the caller's writeMu transaction. It
// preserves legacy provenance before a touch replaces ts, or a new claim
// replaces the legacy retry/lease fields. No ensure helpers belong here.
func repairArtifactTimesForURL(ctx context.Context, tx *sql.Tx, url string) error {
	var row artifactTimeRepairRow
	err := row.scan(tx.QueryRowContext(ctx, `SELECT `+artifactTimeRepairColumns+` FROM artifacts WHERE url=? AND (first_observed_at IS NULL OR last_seen_at IS NULL)`, url))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = repairArtifactTimeRow(ctx, tx, row)
	return err
}

func repairArtifactTimeRow(ctx context.Context, tx *sql.Tx, row artifactTimeRepairRow) (bool, error) {
	// SQLite accepts non-RFC3339 dates and rounds sub-millisecond precision.
	// Parse in Go; unknown legacy evidence must never acquire fresh provenance.
	observed, obsErr := time.Parse(time.RFC3339Nano, row.ts)
	registered, regErr := time.Parse(time.RFC3339Nano, row.created)
	invalid := obsErr != nil || regErr != nil
	var first, seen, attempted, fetched, detail any
	if obsErr == nil {
		seen = captureTime(observed)
		first = seen
	}
	legacyCapture := !row.attempted.Valid && !row.lease.Valid && !row.fetched.Valid
	if obsErr == nil && regErr == nil {
		if registered.Before(observed) {
			first = captureTime(registered)
		}
		if row.status == "fetched" && legacyCapture {
			fetched = first
		}
	}
	if row.attempts > 0 && regErr == nil && legacyCapture {
		attempted = captureTime(registered)
	}
	// A modern attempt/lease/result is authoritative even while observation
	// columns are NULL. Only untouched legacy schedules need conversion.
	if legacyCapture && row.next.Valid {
		due, err := time.Parse(time.RFC3339Nano, row.next.String)
		if err == nil {
			if row.status == "capturing" {
				row.lease = sql.NullString{String: captureTime(due), Valid: true}
				row.next = sql.NullString{}
			} else {
				row.next.String = captureTime(due)
			}
		} else {
			invalid = true
			row.next = sql.NullString{}
			if row.status == "capturing" || row.status == "failed" || row.status == "pending" {
				row.status = "failed_permanently"
				detail = "invalid legacy capture schedule"
			}
		}
	}
	_, err := tx.ExecContext(ctx, `UPDATE artifacts SET
first_observed_at=COALESCE(first_observed_at,?), last_seen_at=COALESCE(last_seen_at,?),
last_fetch_attempt_at=COALESCE(last_fetch_attempt_at,?), last_successful_fetch_at=COALESCE(last_successful_fetch_at,?),
lease_until=?, next_attempt_at=?, status=?, detail=COALESCE(?,detail) WHERE id=?`,
		first, seen, attempted, fetched, row.lease, row.next, row.status, detail, row.id)
	return invalid, err
}
