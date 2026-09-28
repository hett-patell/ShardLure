package store

import (
	"context"
	"database/sql"
	"path"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/script"
	"github.com/networkshard/shardlure/pkg/models"
)

const evidenceCursorSource, evidenceCursorPath = "campaign", "evidence-v1"

// evidenceScanQuery walks a bounded rowid window. The unary + keeps source
// and kind out of index selection: commands are ~1% of events, so answering
// source='cowrie' from idx_events_session would scan most Cowrie rows under
// writeMu — the v2.8.0 HASSH-repair regression on ARM.
const evidenceScanQuery = `SELECT id, ts, COALESCE(ts_unix_ns,0), kind, COALESCE(session_id,''), COALESCE(actor_id,''), COALESCE(src_ip,''),
  substr(COALESCE(command,''),1,65536), COALESCE(sha256,''), substr(COALESCE(filename,''),1,4096)
FROM events WHERE id>? AND id<=? AND +source='cowrie' AND +kind IN ('command','file_download','file_upload') ORDER BY id`

// maxEvidenceWindowBytes bounds memory and writeMu hold time per window.
var maxEvidenceWindowBytes = 8 << 20

// maxEvidenceWindow is the largest rowid window one RecordCampaignEvidence
// transaction covers (see there).
const maxEvidenceWindow = 5000

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

type EvidenceRecordResult struct {
	// Scanned counts Cowrie command/file events read from the window.
	Scanned int
	// Recorded counts events processed into lines or evidence, including
	// replays the dedup then ignored and lines dropped by the session caps;
	// it is not a count of new rows.
	Recorded int
	Done     bool
}

// RecordCampaignEvidence turns Cowrie events in the next rowid window past a
// durable cursor into per-event script lines and linking evidence, in one
// transaction. Line inserts are keyed by event id, so replaying a range after
// a cursor reset does not double-append.
//
// window is clamped to maxEvidenceWindow rowids. The whole window is one
// writeMu transaction with no time cap inside it; 50,000 rowids held writeMu
// for about 0.4-1 s on ARM, 10x the 5,000-row chunk MaintenancePurge uses so
// ingest is never stalled behind a batch. Callers loop over windows instead,
// releasing writeMu in between.
func (s *Store) RecordCampaignEvidence(ctx context.Context, window int) (EvidenceRecordResult, error) {
	if window <= 0 || window > maxEvidenceWindow {
		window = maxEvidenceWindow
	}
	var res EvidenceRecordResult
	err := s.WithTxContext(ctx, func(tx *sql.Tx) error {
		var cursor, maxID int64
		if err := tx.QueryRow(`SELECT offset FROM ingest_state WHERE source=? AND path=?`, evidenceCursorSource, evidenceCursorPath).Scan(&cursor); err != nil && err != sql.ErrNoRows {
			return err
		}
		if err := tx.QueryRow(`SELECT COALESCE(MAX(id),0) FROM events`).Scan(&maxID); err != nil {
			return err
		}
		end := min(cursor+int64(window), maxID)
		res.Done = end >= maxID
		if end <= cursor {
			return nil
		}
		type ev struct {
			id, tsNS                                   int64
			ts, kind, session, actor, ip, cmd, sha, fn string
		}
		rows, err := tx.QueryContext(ctx, evidenceScanQuery, cursor, end)
		if err != nil {
			return err
		}
		var batch []ev
		budget := 0
		for rows.Next() {
			var e ev
			if err := rows.Scan(&e.id, &e.ts, &e.tsNS, &e.kind, &e.session, &e.actor, &e.ip, &e.cmd, &e.sha, &e.fn); err != nil {
				rows.Close()
				return err
			}
			budget += len(e.cmd) + len(e.fn)
			if budget > maxEvidenceWindowBytes && len(batch) > 0 {
				end, res.Done = batch[len(batch)-1].id, false
				break
			}
			batch = append(batch, e)
		}
		// rows.Next returning false can mean an error, not the end: without
		// this check an I/O or corruption failure mid-scan would still advance
		// the cursor to end and silently drop the rest of the window.
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		res.Scanned = len(batch)
		now := formatFixedUTC(time.Now())
		for _, e := range batch {
			if e.session == "" || e.actor == "" {
				continue // admin exemption or sessionless row
			}
			// Stored times must be fixed-width UTC text so min()/max()/<
			// order correctly. Prefer the exact v20 column; legacy rows carry
			// variable-width RFC3339Nano text. A row with neither usable is
			// skipped (still counted as scanned), never stored raw.
			if e.tsNS != 0 {
				e.ts = formatFixedUTC(time.Unix(0, e.tsNS))
			} else if t, err := time.Parse(time.RFC3339Nano, e.ts); err == nil {
				e.ts = formatFixedUTC(t)
			} else {
				continue
			}
			switch models.EventKind(e.kind) {
			case models.KindCommand:
				if err := appendSessionLineTx(tx, e.id, e.session, e.actor, e.ip, e.cmd, e.ts, now); err != nil {
					return err
				}
				for _, k := range script.ExtractKeys(e.cmd) {
					if err := upsertEvidenceTx(tx, "ssh_key", k.Fingerprint, k.Comment, e.session, e.actor, e.ip, e.ts); err != nil {
						return err
					}
				}
				res.Recorded++
			case models.KindFileDown, models.KindFileUp:
				sha := strings.ToLower(e.sha)
				if !validCaptureHash(sha) || sha == emptySHA256 {
					continue
				}
				if err := upsertEvidenceTx(tx, "payload", sha, path.Base(e.fn), e.session, e.actor, e.ip, e.ts); err != nil {
					return err
				}
				res.Recorded++
			}
		}
		_, err = tx.Exec(`INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES(?,?,0,?,'',?)
ON CONFLICT(source,path) DO UPDATE SET offset=excluded.offset, updated_at=excluded.updated_at`,
			evidenceCursorSource, evidenceCursorPath, end, now)
		return err
	})
	return res, err
}

// appendSessionLineTx stores one command line (O(1) per command; the script
// is assembled once when the session settles). Caps: MaxCommands lines and
// MaxNormalizedBytes per session, where bytes is len(script.Join(lines)):
// every line after the first also costs its one-byte separator.
func appendSessionLineTx(tx *sql.Tx, eventID int64, session, actor, ip, cmd, ts, now string) error {
	line := script.EncodeLine(cmd)
	if line == "" {
		return nil
	}
	var count, bytes int
	if err := tx.QueryRow(`SELECT line_count, bytes FROM session_scripts WHERE session_id=?`, session).Scan(&count, &bytes); err != nil && err != sql.ErrNoRows {
		return err
	}
	add := len(line)
	if count > 0 {
		add++ // script.Join separator
	}
	if count >= script.MaxCommands || bytes+add > script.MaxNormalizedBytes {
		return nil
	}
	r, err := tx.Exec(`INSERT OR IGNORE INTO session_script_lines(session_id,event_id,line) VALUES(?,?,?)`, session, eventID, line)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return nil // replayed event
	}
	_, err = tx.Exec(`INSERT INTO session_scripts(session_id,actor_id,src_ip,line_count,bytes,first_seen,last_seen,updated_at) VALUES(?,?,?,1,?,?,?,?)
ON CONFLICT(session_id) DO UPDATE SET actor_id=excluded.actor_id, line_count=line_count+1, bytes=bytes+excluded.bytes,
  first_seen=min(first_seen, excluded.first_seen), last_seen=max(last_seen, excluded.last_seen), updated_at=excluded.updated_at`,
		session, actor, ip, add, ts, ts, now)
	return err
}

func upsertEvidenceTx(tx *sql.Tx, kind, value, label, session, actor, ip, ts string) error {
	_, err := tx.Exec(`INSERT INTO campaign_evidence(kind,value,label,session_id,actor_id,src_ip,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(kind,value,session_id) DO UPDATE SET actor_id=excluded.actor_id,
  first_seen=min(first_seen, excluded.first_seen), last_seen=max(last_seen, excluded.last_seen)`,
		kind, value, label, session, actor, ip, ts, ts)
	return err
}

// rekeyCampaignEvidenceTx moves a session's derived rows with its events.
func rekeyCampaignEvidenceTx(tx *sql.Tx, sessionID, newActorID string) error {
	for _, table := range []string{"session_scripts", "campaign_evidence"} {
		if _, err := tx.Exec(`UPDATE `+table+` SET actor_id=? WHERE session_id=? AND actor_id<>'' AND actor_id<>?`, newActorID, sessionID, newActorID); err != nil {
			return err
		}
	}
	return nil
}

// clearCampaignDerivedTx empties derived tables and rewinds the recorder when
// the Cowrie source is replaced. Operator edits and campaign identity are
// kept, so re-ingested evidence maps back to the same campaign IDs.
func clearCampaignDerivedTx(tx *sql.Tx) error {
	for _, q := range []string{
		`DELETE FROM session_script_lines`, `DELETE FROM session_scripts`, `DELETE FROM scripts`, `DELETE FROM script_families`,
		`DELETE FROM campaign_evidence`, `DELETE FROM campaign_members`, `DELETE FROM campaigns WHERE name='' AND notes=''`,
		`DELETE FROM ingest_state WHERE source='campaign' AND path='evidence-v1'`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// purgeCampaignDerived applies event retention to derived rows, in bounded
// chunks with writeMu released between them (like the events purge).
func (s *Store) purgeCampaignDerived(ctx context.Context, cutoff time.Time) error {
	c := formatFixedUTC(cutoff)
	steps := []struct {
		q        string
		cutoffed bool
	}{
		// Selected by line rowid so each chunk is at most 5000 rows under
		// writeMu (a session batch could be 300 lines per session). The join
		// is the existence guard: every selected row is deleted, so the next
		// chunk cannot re-select it and the loop ends at zero.
		{`DELETE FROM session_script_lines WHERE rowid IN (SELECT l.rowid FROM session_scripts ss
  JOIN session_script_lines l ON l.session_id=ss.session_id WHERE ss.last_seen < ? LIMIT 5000)`, true},
		{`DELETE FROM session_scripts WHERE rowid IN (SELECT ss.rowid FROM session_scripts ss WHERE ss.last_seen < ?
  AND NOT EXISTS (SELECT 1 FROM session_script_lines l WHERE l.session_id=ss.session_id) LIMIT 5000)`, true},
		{`DELETE FROM session_script_lines WHERE rowid IN (SELECT l.rowid FROM session_script_lines l
  LEFT JOIN session_scripts ss ON ss.session_id=l.session_id WHERE ss.session_id IS NULL LIMIT 5000)`, false},
		{`DELETE FROM campaign_evidence WHERE rowid IN (SELECT rowid FROM campaign_evidence WHERE last_seen < ? LIMIT 5000)`, true},
	}
	for _, st := range steps {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			var n int64
			err := s.WithTxContext(ctx, func(tx *sql.Tx) error {
				var r sql.Result
				var err error
				if st.cutoffed {
					r, err = tx.Exec(st.q, c)
				} else {
					r, err = tx.Exec(st.q)
				}
				if err != nil {
					return err
				}
				n, _ = r.RowsAffected()
				return nil
			})
			if err != nil {
				return err
			}
			if n == 0 {
				break
			}
		}
	}
	return nil
}
