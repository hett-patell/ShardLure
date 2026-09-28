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

// maxEvidenceWindowBytes bounds the command text one window normalises, and
// so worker CPU and memory per window, not writeMu hold time: the recorder
// normalises outside the lock (see RecordCampaignEvidence). At the measured
// worst of 0.85 us/byte on x86 (2-3x on ARM) a hostile 1 MB window costs about
// 1-3 s of CPU inside the tick's 2-minute context and no lock time. It never
// binds on normal data (prod's ~17.5k commands total about 2 MB), so only an
// attacker padding commands to the 64 KiB cap reaches it.
var maxEvidenceWindowBytes = 1 << 20

// evidenceEncodeLine and evidenceExtractKeys are the normalisers phase 1 of
// RecordCampaignEvidence runs; variables so a test can count calls and pin
// that none happen under writeMu. evidenceBetweenPhases, when set, runs
// between the two phases so a test can delete rows or reset the cursor there.
var (
	evidenceEncodeLine    = script.EncodeLine
	evidenceExtractKeys   = script.ExtractKeys
	evidenceBetweenPhases func()
)

type ctxRowQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type ctxQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// evidenceCursor reads the recorder's durable cursor (0 when unset) from a
// connection or an open transaction.
func evidenceCursor(ctx context.Context, q ctxRowQueryer) (int64, error) {
	var cursor int64
	err := q.QueryRowContext(ctx, `SELECT offset FROM ingest_state WHERE source=? AND path=?`, evidenceCursorSource, evidenceCursorPath).Scan(&cursor)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	return cursor, nil
}

type evidenceEvent struct {
	id, tsNS                                   int64
	ts, kind, session, actor, ip, cmd, sha, fn string
}

// scanEvidenceWindow reads the Cowrie command/file rows in (cursor, end] in
// id order and hands each to visit until it returns false.
func scanEvidenceWindow(ctx context.Context, q ctxQueryer, cursor, end int64, visit func(evidenceEvent) bool) error {
	rows, err := q.QueryContext(ctx, evidenceScanQuery, cursor, end)
	if err != nil {
		return err
	}
	for rows.Next() {
		var e evidenceEvent
		if err := rows.Scan(&e.id, &e.ts, &e.tsNS, &e.kind, &e.session, &e.actor, &e.ip, &e.cmd, &e.sha, &e.fn); err != nil {
			rows.Close()
			return err
		}
		if !visit(e) {
			break
		}
	}
	// rows.Next returning false can mean an error, not the end: without this
	// check an I/O or corruption failure mid-scan would still let the caller
	// advance the cursor to end and silently drop the rest of the window.
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	return rows.Close()
}

// sessionAtCap is phase 1's read-only look at the caps appendSessionLineTx
// enforces, so a session already holding MaxCommands lines or
// MaxNormalizedBytes does not pay normalisation for commands the transaction
// would drop anyway. It is an optimisation only and deliberately weaker than
// the in-transaction check (bytes >= cap, not bytes+add > cap), so it never
// skips a line the transaction would have accepted; the transaction re-reads
// the counters and decides.
func (s *Store) sessionAtCap(ctx context.Context, session string) (bool, error) {
	var count, bytes int
	err := s.db.QueryRowContext(ctx, `SELECT line_count, bytes FROM session_scripts WHERE session_id=?`, session).Scan(&count, &bytes)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return count >= script.MaxCommands || bytes >= script.MaxNormalizedBytes, nil
}

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

// precomputed is what phase 1 of RecordCampaignEvidence derives from a
// command row outside writeMu: its encoded line ("" when the session was
// already at cap or the command normalised to nothing) and the SSH keys in
// its text. File rows get a zero value, so "present in the map" means "seen
// in phase 1" for every kind.
type precomputed struct {
	line string
	keys []script.Key
}

// RecordCampaignEvidence turns Cowrie events in the next rowid window past a
// durable cursor into per-event script lines and linking evidence. Line
// inserts are keyed by event id, so replaying a range after a cursor reset
// does not double-append.
//
// It is split into read -> compute -> short write because the normaliser's
// cost is attacker-controlled: EncodeLine and ExtractKeys run 0.12-0.85 us per
// byte on x86 (2-3x on ARM) and a command is up to 64 KiB, so normalising a
// window inside the write transaction put up to 7 s (x86) or 14-24 s (ARM) of
// attacker-proportional CPU under writeMu; 128 `ssh ... exec` sessions of
// padded commands produced one such window, repeatable indefinitely, and
// during each hold the Cowrie ticker, journal tail, purge and dashboard edits
// all blocked. Ingest must never stall behind derived analysis.
//
//  1. Phase 1, no lock: read the cursor and MAX(id), scan (cursor, end] and
//     normalise every command into a map keyed by event id. Event ids are
//     AUTOINCREMENT and sqlite_sequence is never reset, so an id names one
//     immutable command forever: a row can only disappear (purge, --replace)
//     or change actor_id (HASSH re-key). The byte budget applies here.
//  2. Phase 2, one writeMu transaction: re-read the cursor and give up
//     (Done:false, no error, the tick retries) if another writer moved it,
//     because advancing to end would overwrite a --replace's reset and skip
//     the re-ingested rows. Re-run the same rowid seek for the same
//     (cursor, end], take session_id/actor_id fresh from each row (re-key
//     correctness) and the line and keys from the map; a row absent from the
//     map or from the table is skipped. Then advance the cursor to end. The
//     hold is the SQL alone: at most three statements per command row.
//
// The session caps are still enforced inside the transaction
// (appendSessionLineTx); phase 1 only reads them to avoid normalising commands
// a capped session would drop.
//
// window is clamped to maxEvidenceWindow rowids: 50,000 rowids held writeMu
// for about 0.4-1 s on ARM for the SQL alone, 10x the 5,000-row chunk
// MaintenancePurge uses so ingest is never stalled behind a batch. Callers
// loop over windows instead, releasing writeMu in between.
func (s *Store) RecordCampaignEvidence(ctx context.Context, window int) (EvidenceRecordResult, error) {
	if window <= 0 || window > maxEvidenceWindow {
		window = maxEvidenceWindow
	}
	var res EvidenceRecordResult
	cursor, err := evidenceCursor(ctx, s.db)
	if err != nil {
		return res, err
	}
	var maxID int64
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id),0) FROM events`).Scan(&maxID); err != nil {
		return res, err
	}
	end := min(cursor+int64(window), maxID)
	res.Done = end >= maxID
	if end <= cursor {
		return res, nil
	}
	var batch []evidenceEvent
	budget := 0
	err = scanEvidenceWindow(ctx, s.db, cursor, end, func(e evidenceEvent) bool {
		budget += len(e.cmd) + len(e.fn)
		if budget > maxEvidenceWindowBytes && len(batch) > 0 {
			end, res.Done = batch[len(batch)-1].id, false
			return false
		}
		batch = append(batch, e)
		return true
	})
	if err != nil {
		return res, err
	}
	res.Scanned = len(batch)
	pre := make(map[int64]precomputed, len(batch))
	capped := map[string]bool{} // per session, read once per window
	for _, e := range batch {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if e.session == "" || e.actor == "" {
			continue // admin exemption or sessionless row: counted, never recorded
		}
		var p precomputed
		if models.EventKind(e.kind) == models.KindCommand {
			// Keys are extracted unconditionally: a key is evidence even past
			// the session's line cap.
			p.keys = evidenceExtractKeys(e.cmd)
			atCap, seen := capped[e.session]
			if !seen {
				if atCap, err = s.sessionAtCap(ctx, e.session); err != nil {
					return res, err
				}
				capped[e.session] = atCap
			}
			if !atCap {
				p.line = evidenceEncodeLine(e.cmd)
			}
		}
		pre[e.id] = p
	}
	batch = nil // the command text is not needed under writeMu
	if evidenceBetweenPhases != nil {
		evidenceBetweenPhases()
	}
	err = s.WithTxContext(ctx, func(tx *sql.Tx) error {
		cur, err := evidenceCursor(ctx, tx)
		if err != nil {
			return err
		}
		if cur != cursor {
			res = EvidenceRecordResult{}
			return nil
		}
		var live []evidenceEvent
		if err := scanEvidenceWindow(ctx, tx, cursor, end, func(e evidenceEvent) bool {
			e.cmd = "" // normalised in phase 1; never touched here
			live = append(live, e)
			return true
		}); err != nil {
			return err
		}
		now := formatFixedUTC(time.Now())
		for _, e := range live {
			p, ok := pre[e.id]
			if !ok || e.session == "" || e.actor == "" {
				continue // not seen in phase 1, admin exemption or sessionless row
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
				if err := appendSessionLineTx(tx, e.id, e.session, e.actor, e.ip, p.line, e.ts, now); err != nil {
					return err
				}
				for _, k := range p.keys {
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
// is assembled once when the session settles). line is the command already
// encoded by script.EncodeLine outside writeMu ("" stores nothing): nothing
// attacker-proportional may run here. Caps: MaxCommands lines and
// MaxNormalizedBytes per session, where bytes is len(script.Join(lines)):
// every line after the first also costs its one-byte separator.
func appendSessionLineTx(tx *sql.Tx, eventID int64, session, actor, ip, line, ts, now string) error {
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

// clearCampaignDerivedTx empties derived tables and parks the recorder when
// the Cowrie source is replaced. Operator edits and campaign identity are
// kept, so re-ingested evidence maps back to the same campaign IDs.
//
// The cursor is set to the largest event id ever issued rather than deleted.
// events.id is AUTOINCREMENT and sqlite_sequence is never reset, so every
// re-ingested row gets a larger id and the first tick after a replace reads
// them in one window; a deleted cursor made it step 5,000-rowid windows
// across the emptied (0, oldMax] first (~350 empty seeks on prod). Both
// floors are safe: clearSourceTx calls this before DELETE FROM events, so
// MAX(id) is the pre-delete maximum, and seq is at least that even when the
// top rows were deleted earlier; max() of the two never sits above the next
// id to be issued, so no re-ingested row is skipped.
func clearCampaignDerivedTx(tx *sql.Tx) error {
	for _, q := range []string{
		`DELETE FROM session_script_lines`, `DELETE FROM session_scripts`, `DELETE FROM scripts`, `DELETE FROM script_families`,
		`DELETE FROM campaign_evidence`, `DELETE FROM campaign_members`, `DELETE FROM campaigns WHERE name='' AND notes=''`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	var floor int64
	if err := tx.QueryRow(`SELECT max(COALESCE((SELECT seq FROM sqlite_sequence WHERE name='events'),0), COALESCE((SELECT MAX(id) FROM events),0))`).Scan(&floor); err != nil {
		return err
	}
	_, err := tx.Exec(`INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES(?,?,0,?,'',?)
ON CONFLICT(source,path) DO UPDATE SET offset=excluded.offset, updated_at=excluded.updated_at`,
		evidenceCursorSource, evidenceCursorPath, floor, formatFixedUTC(time.Now()))
	return err
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
