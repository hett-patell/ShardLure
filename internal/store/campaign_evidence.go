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

// sessionAtCap is phase 1's read-only look at the caps evidenceWriter.flush
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
	// Skipped counts rows dropped because neither ts_unix_ns nor ts gave a
	// usable time. They are never stored (a raw ts would break the
	// fixed-width min/max ordering), and the cursor still moves past them,
	// so without this count a corrupt or legacy import would lose evidence
	// silently. The worker logs it.
	Skipped int
	Done    bool
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
// (evidenceWriter.flush); phase 1 only reads them to avoid normalising commands
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
		var w evidenceWriter
		for _, e := range live {
			p, ok := pre[e.id]
			if !ok || e.session == "" || e.actor == "" {
				continue // not seen in phase 1, admin exemption or sessionless row
			}
			// Stored times must be fixed-width UTC text so min()/max()/<
			// order correctly. Prefer the exact v20 column; legacy rows carry
			// variable-width RFC3339Nano text. A row with neither usable is
			// skipped (counted as scanned and Skipped), never stored raw.
			if e.tsNS != 0 {
				e.ts = formatFixedUTC(time.Unix(0, e.tsNS))
			} else if t, err := time.Parse(time.RFC3339Nano, e.ts); err == nil {
				e.ts = formatFixedUTC(t)
			} else {
				res.Skipped++
				continue
			}
			switch models.EventKind(e.kind) {
			case models.KindCommand:
				w.appendLine(e.id, e.session, e.actor, e.ip, p.line, e.ts)
				for _, k := range p.keys {
					w.upsertEvidence("ssh_key", k.Fingerprint, k.Comment, e.session, e.actor, e.ip, e.ts)
				}
				res.Recorded++
			case models.KindFileDown, models.KindFileUp:
				sha := strings.ToLower(e.sha)
				if !validCaptureHash(sha) || sha == emptySHA256 {
					continue
				}
				w.upsertEvidence("payload", sha, path.Base(e.fn), e.session, e.actor, e.ip, e.ts)
				res.Recorded++
			}
		}
		if err := w.flush(ctx, tx, cursor, end, now); err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES(?,?,0,?,'',?)
ON CONFLICT(source,path) DO UPDATE SET offset=excluded.offset, updated_at=excluded.updated_at`,
			evidenceCursorSource, evidenceCursorPath, end, now)
		return err
	})
	return res, err
}

// evidenceWriter buffers phase 2's writes and applies them set-wise: a
// fixed number of statements per window instead of up to three per command
// row. A dense window (5,000 short commands across 1,000 sessions) held
// writeMu 433-571 ms on x86 with per-row tx.Exec. Preparing the statements
// once (tx.Prepare) only reached ~330-370 ms, because modernc.org/sqlite
// (v1.34.5) re-runs sqlite3_prepare_v2 on every Stmt.Exec, so a prepared
// statement saves the Go-side work and not the compile; what costs is the
// statement count. Batched (see batchParams), the same window holds writeMu
// 63-78 ms on x86.
//
// Semantics match the old per-row path exactly: per session, the counters
// are loaded once inside this transaction (only this transaction writes
// session_scripts while it holds writeMu), lines already stored (a replay
// after a cursor reset) are found up front and neither inserted nor counted,
// and the caps are applied in event-id order.
type evidenceWriter struct {
	lines []lineRow
	evs   []evidenceRow
}

type lineRow struct {
	id                           int64
	session, actor, ip, line, ts string
}

type evidenceRow struct{ kind, value, label, session, actor, ip, ts string }

// appendLine queues one encoded command line ("" stores nothing). line was
// encoded by script.EncodeLine outside writeMu: nothing
// attacker-proportional runs under the lock.
func (w *evidenceWriter) appendLine(eventID int64, session, actor, ip, line, ts string) {
	if line != "" {
		w.lines = append(w.lines, lineRow{eventID, session, actor, ip, line, ts})
	}
}

func (w *evidenceWriter) upsertEvidence(kind, value, label, session, actor, ip, ts string) {
	w.evs = append(w.evs, evidenceRow{kind, value, label, session, actor, ip, ts})
}

// batchParams bounds the bound parameters of one multi-row statement.
// modernc.org/sqlite matches each positional parameter by scanning the
// argument list, so binding costs O(params^2) per statement: measured on the
// dense window, 32 params 85-100 ms, 256 params 63-78 ms, 1,024 params
// 68-88 ms. 256 is the flat middle, and far below SQLite's 32,766 limit.
const batchParams = 256

// execBatched runs head + n row tuples (each `tuple`, joined by commas) +
// tail in statements of at most batchRows rows. SQLite applies a multi-row
// INSERT ... ON CONFLICT row by row, so a later row in the same statement
// sees an earlier one exactly as consecutive single-row statements would.
func execBatched(ctx context.Context, tx *sql.Tx, head, tuple, tail string, n int, args func(i int) []any) error {
	per := max(1, batchParams/max(1, strings.Count(tuple, "?")))
	for lo := 0; lo < n; lo += per {
		hi := min(lo+per, n)
		var q strings.Builder
		q.WriteString(head)
		var a []any
		for i := lo; i < hi; i++ {
			if i > lo {
				q.WriteByte(',')
			}
			q.WriteString(tuple)
			a = append(a, args(i)...)
		}
		q.WriteString(tail)
		if _, err := tx.ExecContext(ctx, q.String(), a...); err != nil {
			return err
		}
	}
	return nil
}

// queryBatched runs head + an IN list of up to batchRows keys + tail, with
// extra appended after the keys, and hands every row to scan.
func queryBatched(ctx context.Context, tx *sql.Tx, head, tail string, keys []string, extra []any, scan func(*sql.Rows) error) error {
	per := max(1, batchParams-len(extra))
	for lo := 0; lo < len(keys); lo += per {
		hi := min(lo+per, len(keys))
		a := make([]any, 0, hi-lo+len(extra))
		for _, k := range keys[lo:hi] {
			a = append(a, k)
		}
		a = append(a, extra...)
		rows, err := tx.QueryContext(ctx, head+"(?"+strings.Repeat(",?", hi-lo-1)+")"+tail, a...)
		if err != nil {
			return err
		}
		for rows.Next() {
			if err := scan(rows); err != nil {
				rows.Close()
				return err
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	return nil
}

// sessionDelta is what one window adds to a session_scripts row.
type sessionDelta struct {
	actor, ip, first, last string
	lines, bytes           int
}

// flush writes the queued rows. Caps: MaxCommands lines and
// MaxNormalizedBytes per session, where bytes is len(script.Join(lines)):
// every line after the first also costs its one-byte separator.
func (w *evidenceWriter) flush(ctx context.Context, tx *sql.Tx, cursor, end int64, now string) error {
	if len(w.lines) > 0 {
		type counts struct{ lines, bytes int }
		cur := map[string]*counts{}
		var sessions []string
		for _, l := range w.lines {
			if cur[l.session] == nil {
				cur[l.session] = &counts{}
				sessions = append(sessions, l.session)
			}
		}
		if err := queryBatched(ctx, tx, `SELECT session_id, line_count, bytes FROM session_scripts WHERE session_id IN `, ``, sessions, nil, func(r *sql.Rows) error {
			var id string
			var c counts
			if err := r.Scan(&id, &c.lines, &c.bytes); err != nil {
				return err
			}
			*cur[id] = c
			return nil
		}); err != nil {
			return err
		}
		// Replays: a cursor reset re-reads rows whose lines are stored. Line
		// event ids lie in this window, so the PK (session_id, event_id)
		// answers it with one range per session.
		stored := map[int64]bool{}
		if err := queryBatched(ctx, tx, `SELECT event_id FROM session_script_lines WHERE session_id IN `, ` AND event_id>? AND event_id<=?`, sessions, []any{cursor, end}, func(r *sql.Rows) error {
			var id int64
			if err := r.Scan(&id); err != nil {
				return err
			}
			stored[id] = true
			return nil
		}); err != nil {
			return err
		}
		var ins []lineRow
		deltas := map[string]*sessionDelta{}
		var order []string
		closed := map[string]lineRow{} // sessions a refused line closed, with that line
		var closedOrder []string
		for _, l := range w.lines {
			if stored[l.id] {
				continue // replayed event
			}
			c := cur[l.session]
			add := len(l.line)
			if c.lines > 0 {
				add++ // script.Join separator
			}
			if c.lines >= script.MaxCommands || c.bytes >= script.MaxNormalizedBytes {
				// Past the cap nothing touches the session row, so its
				// last_seen (and updated_at) stop at the last stored line
				// while the session may run on. Harmless for linking: the
				// script is the capped prefix, which can no longer change,
				// so settling it early (idle is measured from that line)
				// fingerprints the final value; keys and payloads past the
				// cap are still recorded with their own times. The visible
				// effects are that a script occurrence's last_seen can
				// understate the session's end, and retention may drop the
				// script row while the session's later events remain.
				continue
			}
			if c.bytes+add > script.MaxNormalizedBytes {
				// The first line that does not fit closes the session: the
				// script is the capped *prefix*. Skipping only this line and
				// admitting later, smaller ones let an attacker drop one
				// oversized, payload-bearing command (encodings grow up to
				// 4x, `<` -> `<lt>`) from the middle of a script and collide
				// with a session that never ran it (script audit M8). The
				// closure must outlive this window, so it is stored as
				// bytes = MaxNormalizedBytes (the budget is spent), which
				// every later window and sessionAtCap read as full. bytes is
				// therefore len(script.Join(lines)) for an open session and
				// exactly the cap for a closed one; nothing else reads it.
				c.bytes = script.MaxNormalizedBytes
				if _, ok := closed[l.session]; !ok {
					closed[l.session] = l
					closedOrder = append(closedOrder, l.session)
				}
				continue
			}
			c.lines++
			c.bytes += add
			ins = append(ins, l)
			d := deltas[l.session]
			if d == nil {
				// ip is written only when the row is created: the first
				// stored line's, as with the per-row upsert.
				d = &sessionDelta{ip: l.ip, first: l.ts, last: l.ts}
				deltas[l.session] = d
				order = append(order, l.session)
			}
			d.actor = l.actor // last line wins, as excluded.actor_id did per row
			d.first, d.last = min(d.first, l.ts), max(d.last, l.ts)
			d.lines++
			d.bytes += add
		}
		if err := execBatched(ctx, tx, `INSERT OR IGNORE INTO session_script_lines(session_id,event_id,line) VALUES`, `(?,?,?)`, ``, len(ins), func(i int) []any {
			return []any{ins[i].session, ins[i].id, ins[i].line}
		}); err != nil {
			return err
		}
		if err := execBatched(ctx, tx, `INSERT INTO session_scripts(session_id,actor_id,src_ip,line_count,bytes,first_seen,last_seen,updated_at) VALUES`, `(?,?,?,?,?,?,?,?)`,
			` ON CONFLICT(session_id) DO UPDATE SET actor_id=excluded.actor_id, line_count=line_count+excluded.line_count, bytes=bytes+excluded.bytes,
  first_seen=min(first_seen, excluded.first_seen), last_seen=max(last_seen, excluded.last_seen), updated_at=excluded.updated_at,
  settled_at=''`, len(order), func(i int) []any {
				d := deltas[order[i]]
				return []any{order[i], d.actor, d.ip, d.lines, d.bytes, d.first, d.last, now}
			}); err != nil {
			return err
		}
		// Closing a session changes no line, so it touches neither its
		// times nor its settle state: only bytes moves to the cap. A
		// session whose very first line was refused has an empty prefix
		// and gets a row too (or a later window would start its script at
		// a later command), written already settled with no fingerprint:
		// the pending predicate never lists it, so settle does not revisit
		// it every pass, and every script read skips fingerprint=''.
		// Retention takes it by last_seen like any other session row.
		if err := execBatched(ctx, tx, `INSERT INTO session_scripts(session_id,actor_id,src_ip,line_count,bytes,first_seen,last_seen,updated_at,settled_at,fingerprint) VALUES`, `(?,?,?,0,?,?,?,?,?,'')`,
			` ON CONFLICT(session_id) DO UPDATE SET bytes=excluded.bytes`, len(closedOrder), func(i int) []any {
				l := closed[closedOrder[i]]
				return []any{l.session, l.actor, l.ip, script.MaxNormalizedBytes, l.ts, l.ts, now, now}
			}); err != nil {
			return err
		}
	}
	return execBatched(ctx, tx, `INSERT INTO campaign_evidence(kind,value,label,session_id,actor_id,src_ip,first_seen,last_seen) VALUES`, `(?,?,?,?,?,?,?,?)`,
		` ON CONFLICT(kind,value,session_id) DO UPDATE SET actor_id=excluded.actor_id,
  first_seen=min(first_seen, excluded.first_seen), last_seen=max(last_seen, excluded.last_seen)`, len(w.evs), func(i int) []any {
			e := w.evs[i]
			return []any{e.kind, e.value, e.label, e.session, e.actor, e.ip, e.ts, e.ts}
		})
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
//
// During a script rebuild hold (ResetScriptsForVersion) the parked cursor is
// at or past the hold's high-water mark, so the next check would find nothing
// pending, release, and drop script_version_carry before any re-ingested
// session settled: every script row in campaign_ids orphaned. The re-ingested
// events keep their session IDs, so the carry still applies once they are
// re-recorded. The hold is therefore kept: script_version_carry stays, the
// deadline anchor is dropped, and the high-water mark is set to
// scriptHoldRemeasure so the next ScriptRebuildHold re-reads MAX(events.id).
// clearSourceTx runs this before the replace re-inserts the events in the
// same transaction, so any check sees the re-inserted rows in that maximum.
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
	stamp := formatFixedUTC(time.Now())
	if err := upsertIngestOffsetTx(tx, evidenceCursorSource, evidenceCursorPath, floor, stamp); err != nil {
		return err
	}
	// Only an active hold is touched; without one this is a no-op.
	r, err := tx.Exec(`UPDATE ingest_state SET offset=?, updated_at=? WHERE source=? AND path=?`,
		scriptHoldRemeasure, stamp, scriptVersionSource, scriptHoldHWMPath)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n > 0 {
		_, err = tx.Exec(`DELETE FROM ingest_state WHERE source=? AND path=?`, scriptVersionSource, scriptHoldDeadlinePath)
	}
	return err
}

// purgeOldSessionsQuery lists retention step 1's candidates through the
// last_seen index (TestPurgeScriptLinesPlan pins it).
const purgeOldSessionsQuery = `SELECT session_id, line_count FROM session_scripts WHERE last_seen < ? ORDER BY last_seen LIMIT 5000`

// purgeLineBudget bounds the lines one retention transaction deletes, the
// MaintenancePurge chunk size.
const purgeLineBudget = 5000

// purgeCampaignDerived applies event retention to derived rows, in bounded
// chunks with writeMu released between them (like the events purge).
//
// Sessions go whole: each transaction takes old sessions in last_seen order
// until their line_count reaches purgeLineBudget (at least one session, and
// line_count is capped at MaxCommands, so a chunk is at most 5,299 lines) and
// deletes their lines and their rows together. Deleting lines by line rowid
// instead split a long session across chunks, and a settle running between
// two chunks fingerprinted the surviving suffix as the session's script
// (SettleSessionScripts reads outside writeMu; its guard checks updated_at,
// which a purge does not change). Rows and lines are deleted in the same
// transaction, so a reader sees a session either whole or gone.
//
// There is no orphan-line step: the one other deleter of session_scripts
// (the orphan-actor sweep in MaintenancePurgeContext) removes lines with
// their rows too. The step it replaces was a LEFT JOIN over every line on
// every purge.
func (s *Store) purgeCampaignDerived(ctx context.Context, cutoff time.Time) error {
	if purgeCampaignDerivedFail != nil {
		if err := purgeCampaignDerivedFail(); err != nil {
			return err
		}
	}
	c := formatFixedUTC(cutoff)
	steps := []func(tx *sql.Tx) (int64, error){
		func(tx *sql.Tx) (int64, error) {
			var ids []string
			lines := 0
			err := func() error {
				rows, err := tx.QueryContext(ctx, purgeOldSessionsQuery, c)
				if err != nil {
					return err
				}
				defer rows.Close()
				for lines < purgeLineBudget && rows.Next() {
					var id string
					var n int
					if err := rows.Scan(&id, &n); err != nil {
						return err
					}
					ids, lines = append(ids, id), lines+n
				}
				return rows.Err()
			}()
			if err != nil || len(ids) == 0 {
				return 0, err
			}
			// Rows before lines, the order ResetScriptsForVersion uses. In
			// one transaction the order is invisible to readers (WAL
			// snapshot); it is kept the same so every deleter follows the
			// rule that matters across transactions: a session row is never
			// left with some of its lines gone.
			for _, table := range []string{"session_scripts", "session_script_lines"} {
				if err := execBatched(ctx, tx, `DELETE FROM `+table+` WHERE session_id IN (`, `?`, `)`, len(ids), func(i int) []any { return []any{ids[i]} }); err != nil {
					return 0, err
				}
			}
			return int64(len(ids)), nil
		},
		func(tx *sql.Tx) (int64, error) {
			r, err := tx.Exec(`DELETE FROM campaign_evidence WHERE rowid IN (SELECT rowid FROM campaign_evidence WHERE last_seen < ? LIMIT 5000)`, c)
			if err != nil {
				return 0, err
			}
			return r.RowsAffected()
		},
	}
	for stepIdx, step := range steps {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			var n int64
			err := s.WithTxContext(ctx, func(tx *sql.Tx) error {
				var err error
				n, err = step(tx)
				return err
			})
			if err != nil {
				return err
			}
			if purgeChunkDone != nil {
				purgeChunkDone(stepIdx, n)
			}
			if n == 0 {
				break
			}
		}
	}
	return nil
}

// purgeChunkDone, when set (tests only), runs after each committed retention
// chunk with the step (0 sessions, 1 evidence) and how much the chunk deleted,
// so a test can count the chunks that did work rather than the empty one that
// ends each step; purgeCampaignDerivedFail, when set, can fail the whole step.
var (
	purgeChunkDone           func(step int, deleted int64)
	purgeCampaignDerivedFail func() error
)
