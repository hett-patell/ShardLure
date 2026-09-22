package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const CaptureDiscoveryTooManyURLs = "too_many_urls"
const commandCaptureMaxURLs = 512
const commandCapturePageURLs = 2000

func boundedCaptureField(predicate, column string, limit int) string {
	return "CASE WHEN " + predicate + " THEN CASE WHEN length(CAST(COALESCE(" + column + ",'') AS BLOB))<=" + fmt.Sprint(limit) + " THEN COALESCE(" + column + ",'') ELSE NULL END ELSE '' END"
}

const commandCapturePredicate = "kind='command' AND COALESCE(command,'')<>''"

var commandDiscoveryQuery = "SELECT id," + commandCapturePredicate + "," +
	boundedCaptureField(commandCapturePredicate, "ts", 64) + "," +
	boundedCaptureField(commandCapturePredicate, "src_ip", 64) + "," +
	boundedCaptureField(commandCapturePredicate, "session_id", 1024) + "," +
	boundedCaptureField(commandCapturePredicate, "actor_id", 1024) + "," +
	boundedCaptureField(commandCapturePredicate, "command", 2<<20) +
	" FROM events WHERE id>? ORDER BY id LIMIT ?"

// DiscoverCommandArtifacts streams one bounded primary-key page. Work, explicit
// malformed-row diagnostics and the checkpoint commit together. extract is a
// pure parser: it must not access the store or perform network I/O.
func (s *Store) DiscoverCommandArtifacts(ctx context.Context, limit int, extract func(string) []string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if extract == nil {
		return 0, errors.New("capture discovery: missing extractor")
	}
	if limit <= 0 || limit > 2000 {
		limit = 2000
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return 0, err
	}
	if err := s.ensureFileCaptureTable(); err != nil {
		return 0, err
	}
	queued := 0
	err := s.WithTx(func(tx *sql.Tx) error {
		const key = "command-artifacts-v1"
		now := captureTime(time.Now())
		// A first write acquires the WAL writer before selecting a checkpoint.
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES('capture',?,0,0,'',?)", key, now); err != nil {
			return err
		}
		var cursor int64
		if err := tx.QueryRowContext(ctx, "SELECT offset FROM ingest_state WHERE source='capture' AND path=?", key).Scan(&cursor); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, commandDiscoveryQuery, cursor, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		end, used, work := cursor, 0, 0
		for rows.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			var id int64
			var applicable bool
			var fields [5]sql.NullString
			if err := rows.Scan(&id, &applicable, &fields[0], &fields[1], &fields[2], &fields[3], &fields[4]); err != nil {
				return err
			}
			end = id
			used += 64
			if !applicable {
				continue
			}
			reason := ""
			for _, f := range fields {
				used += len(f.String)
				if !f.Valid || strings.ContainsRune(f.String, 0) || !utf8.ValidString(f.String) {
					reason = FileCaptureInvalidMetadata
				}
			}
			at, parseErr := parseLedgerTimestamp(fields[0].String)
			if reason == "" && (parseErr != nil || at.IsZero()) {
				reason = FileCaptureInvalidTime
			}
			var urls []string
			if reason == "" {
				urls = extract(fields[4].String)
				if len(urls) > commandCaptureMaxURLs {
					reason = CaptureDiscoveryTooManyURLs
				} else {
					urlBytes := 0
					for _, u := range urls {
						urlBytes += len(u)
						if u == "" || len(u) > 65536 || strings.ContainsRune(u, 0) || !utf8.ValidString(u) {
							reason = FileCaptureInvalidMetadata
							break
						}
					}
					if urlBytes > 2<<20 {
						reason = CaptureDiscoveryTooManyURLs
					}
					used += urlBytes
				}
			}
			if reason != "" {
				if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO capture_discovery_errors(event_id,kind,reason,created_at) VALUES(?,'command',?,?)", id, reason, now); err != nil {
					return err
				}
			} else {
				ts := captureTime(at)
				for _, url := range urls {
					if err := ctx.Err(); err != nil {
						return err
					}
					result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO artifacts(ts,src_ip,session_id,actor_id,url,origin,status,created_at,first_observed_at,last_seen_at)
VALUES(?,?,?,?,?,'quarantine_fetch','pending',?,?,?)`, ts, fields[1].String, fields[2].String, fields[3].String, url, now, ts, ts)
					if err != nil {
						return err
					}
					n, err := result.RowsAffected()
					if err != nil {
						return err
					}
					queued += int(n)
					if n == 0 {
						// Observation never refreshes successful-fetch provenance or a lease.
						if err := repairArtifactTimesForURL(ctx, tx, url); err != nil {
							return err
						}
						var seen string
						if err := tx.QueryRowContext(ctx, "SELECT COALESCE(last_seen_at,ts) FROM artifacts WHERE url=?", url).Scan(&seen); err != nil {
							return err
						}
						previous, err := parseTime(seen)
						if err != nil || at.After(previous) {
							if _, err := tx.ExecContext(ctx, "UPDATE artifacts SET ts=?,last_seen_at=?,first_observed_at=COALESCE(first_observed_at,?) WHERE url=?", ts, ts, ts, url); err != nil {
								return err
							}
						}
					}
				}
				// Count attempted work, including dedup hits: repeated known URLs must
				// not turn a bounded byte page into millions of writer queries.
				work += len(urls)
			}
			if used >= captureDiscoveryPageBytes || work >= commandCapturePageURLs {
				break
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if end == cursor {
			return nil
		}
		_, err = tx.ExecContext(ctx, "UPDATE ingest_state SET offset=?,updated_at=? WHERE source='capture' AND path=?", end, now, key)
		return err
	})
	if err != nil {
		return 0, err
	}
	return queued, nil
}
