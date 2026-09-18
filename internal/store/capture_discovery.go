package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// DiscoverCommandArtifacts scans a bounded primary-key page, not just the most
// recent commands. Queue inserts and the cursor commit together, so a burst,
// backfilled timestamp, cancellation or restart cannot silently skip commands.
// extract is a pure parser: it must not access the store or perform network IO.
func (s *Store) DiscoverCommandArtifacts(ctx context.Context, limit int, extract func(string) []string) (int, error) {
	if limit <= 0 || limit > 2000 {
		limit = 2000
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return 0, err
	}
	queued := 0
	err := s.WithTx(func(tx *sql.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		const key = "command-artifacts-v1"
		var cursor int64
		err := tx.QueryRowContext(ctx, `SELECT offset FROM ingest_state WHERE source='capture' AND path=?`, key).Scan(&cursor)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT id,ts,kind,COALESCE(src_ip,''),COALESCE(session_id,''),COALESCE(actor_id,''),COALESCE(command,'') FROM events WHERE id>? ORDER BY id LIMIT ?`, cursor, limit)
		if err != nil {
			return err
		}
		var commands []*EventRow
		end := cursor
		for rows.Next() {
			e := &EventRow{}
			var ts, kind string
			if err := rows.Scan(&e.ID, &ts, &kind, &e.SrcIP, &e.SessionID, &e.ActorID, &e.Command); err != nil {
				rows.Close()
				return err
			}
			end = e.ID
			if kind != string(models.KindCommand) || e.Command == "" {
				continue
			}
			e.TS, err = parseTime(ts)
			if err != nil {
				rows.Close()
				return err
			}
			commands = append(commands, e)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if end == cursor {
			return nil
		}
		for _, e := range commands {
			for _, url := range extract(e.Command) {
				if err := ctx.Err(); err != nil {
					return err
				}
				ts := captureTime(e.TS)
				result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO artifacts(ts,src_ip,session_id,actor_id,url,origin,status,created_at,first_observed_at,last_seen_at) VALUES(?,?,?,?,?,'quarantine_fetch','pending',?,?,?)`, ts, e.SrcIP, e.SessionID, e.ActorID, url, captureTime(time.Now()), ts, ts)
				if err != nil {
					return err
				}
				n, err := result.RowsAffected()
				if err != nil {
					return err
				}
				queued += int(n)
				if n == 0 {
					var seen string
					if err := tx.QueryRowContext(ctx, `SELECT COALESCE(last_seen_at,ts) FROM artifacts WHERE url=?`, url).Scan(&seen); err != nil {
						return err
					}
					previous, err := parseTime(seen)
					if err != nil {
						return err
					}
					if e.TS.After(previous) {
						// Observation only. Never modify an active lease, attempt budget,
						// terminal status or the provenance of a successful download.
						if _, err := tx.ExecContext(ctx, `UPDATE artifacts SET ts=?,last_seen_at=? WHERE url=?`, ts, ts, url); err != nil {
							return err
						}
					}
				}
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES('capture',?,0,?,'',?) ON CONFLICT(source,path) DO UPDATE SET offset=excluded.offset,updated_at=excluded.updated_at`, key, end, time.Now().UTC().Format(time.RFC3339Nano))
		return err
	})
	if err != nil {
		return 0, err
	}
	return queued, nil
}
