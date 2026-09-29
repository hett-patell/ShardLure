package store

import (
	"context"
	"database/sql"
	"sort"
	"time"
)

// The normaliser version the stored script lines were encoded with, and the
// regroup hold a rebuild sets, live in ingest_state beside the recorder
// cursor they govern (offset carries the value).
const (
	scriptVersionSource    = "script_version"
	scriptVersionPath      = "normaliser"
	scriptHoldHWMPath      = "hold_hwm"      // events high-water mark at reset
	scriptHoldDeadlinePath = "hold_deadline" // unix seconds; set once the recorder passes hold_hwm
)

// scriptHoldRemeasure is the hold_hwm sentinel a Cowrie --replace leaves
// (clearCampaignDerivedTx): the next ScriptRebuildHold replaces it with the
// current MAX(events.id), which then includes the re-inserted events.
const scriptHoldRemeasure = -1

// scriptResetChunk bounds one reset transaction, the MaintenancePurge chunk
// size: prod ARM holds ~21k sessions and a few hundred thousand lines, and
// one DELETE of them all would hold writeMu for seconds.
const scriptResetChunk = 5000

// scriptHoldDuration caps how long a rebuild holds regroups once the
// recorder has re-read every event up to the high-water mark. Re-recorded
// sessions settle 10 minutes after they were recorded (the ingest-time idle
// clock restarts), so a hold normally ends in ~10-12 minutes; the deadline
// only bounds a session that keeps receiving commands. It is counted from
// that first observation, not from the reset: counted from the reset, a
// restart after more than 30 minutes of downtime released the hold before
// anything was re-recorded, dropping the carry snapshot with nothing
// settled, which is the bug the hold exists to prevent.
var scriptHoldDuration = 30 * time.Minute

// ResetScriptsForVersion makes the script-derived rows match normaliser
// version (script.Version). When the stored version differs (or none is
// stored: rows written before versioning) it:
//
//  1. snapshots every settled session's fingerprint into
//     script_version_carry (INSERT OR IGNORE in 5,000-row chunks, so a rerun
//     after a crash keeps the oldest fingerprint and never the empty state a
//     half-finished delete left);
//  2. deletes session_scripts, session_script_lines, scripts and
//     script_families in 5,000-row transactions (rows before lines: a reader
//     that finds a session row finds all its lines, and SettleSessionScripts'
//     guarded UPDATE skips a session whose row is gone);
//  3. in one final transaction, rewinds the campaign recorder's cursor to 0,
//     stores version and, when there was anything to rebuild, sets the
//     regroup hold: the events high-water mark (the deadline is set later,
//     see ScriptRebuildHold).
//
// The version is written last, so an interrupted reset simply runs again.
// It reports whether it reset anything: a database with no script rows and
// the recorder at 0 (a fresh install) only has the version stored.
//
// Why the hold: until the re-recorded sessions settle there are no script
// occurrences, and a regroup then drops every script row from campaign_ids
// (Group is fed exactly the previous assignments and returns only live
// values). When the sessions settle, Group mints a new ID, because the
// renamed campaign's ID is reserved by its edits: the operator's name and
// notes stay on an empty shell. So the worker suppresses regroups while the
// hold is active (ScriptRebuildHold), and releasing it carries the old
// fingerprints' assignments to the new ones (carryScriptAssignments).
//
// campaign_evidence, campaign_ids, campaign_aliases, campaign_edits and
// campaigns are left alone: key and payload evidence does not depend on the
// normaliser and its replay is idempotent (ON CONFLICT keeps min/max
// times), and campaign identity lives in those tables.
//
// The caller is the campaign worker, before it records, so nothing re-adds
// rows between chunks.
func (s *Store) ResetScriptsForVersion(ctx context.Context, version int) (bool, error) {
	var stored int64
	err := s.db.QueryRowContext(ctx, `SELECT offset FROM ingest_state WHERE source=? AND path=?`, scriptVersionSource, scriptVersionPath).Scan(&stored)
	if err == nil && stored == int64(version) {
		return false, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	cursor, err := evidenceCursor(ctx, s.db)
	if err != nil {
		return false, err
	}
	reset := cursor != 0
	// 1. Old fingerprints, by session rowid window.
	var after int64
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		var hi sql.NullInt64
		if err := s.WithTxContext(ctx, func(tx *sql.Tx) error {
			if err := tx.QueryRow(`SELECT MAX(rowid) FROM (SELECT rowid FROM session_scripts WHERE rowid>? ORDER BY rowid LIMIT ?)`, after, scriptResetChunk).Scan(&hi); err != nil || !hi.Valid {
				return err
			}
			_, err := tx.Exec(`INSERT OR IGNORE INTO script_version_carry(session_id, fingerprint)
SELECT session_id, fingerprint FROM session_scripts WHERE rowid>? AND rowid<=? AND fingerprint<>''`, after, hi.Int64)
			return err
		}); err != nil {
			return false, err
		}
		if !hi.Valid {
			break
		}
		after, reset = hi.Int64, true
	}
	// 2. Derived rows, session rows before their lines.
	for _, table := range []string{"session_scripts", "session_script_lines", "scripts", "script_families"} {
		for {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			var n int64
			if err := s.WithTxContext(ctx, func(tx *sql.Tx) error {
				r, err := tx.Exec(`DELETE FROM `+table+` WHERE rowid IN (SELECT rowid FROM `+table+` LIMIT ?)`, scriptResetChunk)
				if err != nil {
					return err
				}
				n, err = r.RowsAffected()
				return err
			}); err != nil {
				return false, err
			}
			if n == 0 {
				break
			}
			reset = true
		}
	}
	// 3. Cursor, version and hold, the version last in effect: all one tx.
	now := time.Now()
	err = s.WithTxContext(ctx, func(tx *sql.Tx) error {
		var hwm int64
		if err := tx.QueryRow(`SELECT COALESCE(MAX(id),0) FROM events`).Scan(&hwm); err != nil {
			return err
		}
		type offsetRow struct {
			path   string
			offset int64
		}
		stamp := formatFixedUTC(now)
		if err := upsertIngestOffsetTx(tx, evidenceCursorSource, evidenceCursorPath, 0, stamp); err != nil {
			return err
		}
		// A deadline left by an earlier, unfinished hold must not carry over:
		// the new hold starts its clock when the recorder catches up again.
		if _, err := tx.Exec(`DELETE FROM ingest_state WHERE source=? AND path=?`, scriptVersionSource, scriptHoldDeadlinePath); err != nil {
			return err
		}
		var rows []offsetRow
		if reset {
			rows = append(rows, offsetRow{scriptHoldHWMPath, hwm})
		}
		rows = append(rows, offsetRow{scriptVersionPath, int64(version)})
		for _, row := range rows {
			if err := upsertIngestOffsetTx(tx, scriptVersionSource, row.path, row.offset, stamp); err != nil {
				return err
			}
		}
		return nil
	})
	return reset && err == nil, err
}

func upsertIngestOffsetTx(tx *sql.Tx, source, path string, offset int64, stamp string) error {
	_, err := tx.Exec(`INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES(?,?,0,?,'',?)
ON CONFLICT(source,path) DO UPDATE SET offset=excluded.offset, updated_at=excluded.updated_at`, source, path, offset, stamp)
	return err
}

// ScriptRebuildHold reports whether regroups must wait for a script rebuild
// (see ResetScriptsForVersion), and releases the hold once it is over. The
// hold lives in the database, so it survives a restart.
//
// It never ends while the recorder is below the events high-water mark taken
// at reset (re-measured after a --replace, see scriptHoldRemeasure). Once the
// recorder has passed it, the first check stores a deadline of now +
// scriptHoldDuration (persisted, so a restart keeps it), and the hold ends
// when no session with a line at or below the mark is unsettled, or at that
// deadline, whichever comes first. Release is one transaction: carry the
// script assignments to the new fingerprints, empty script_version_carry,
// then delete the hold, so the first regroup after the hold sees the carried
// rows. Sessions a purge removed during the hold simply have nothing to
// carry.
func (s *Store) ScriptRebuildHold(ctx context.Context, now time.Time) (bool, error) {
	var hwm int64
	err := s.db.QueryRowContext(ctx, `SELECT offset FROM ingest_state WHERE source=? AND path=?`, scriptVersionSource, scriptHoldHWMPath).Scan(&hwm)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if hwm == scriptHoldRemeasure {
		// A --replace ran during the hold: measure the mark again over the
		// re-inserted events. The UPDATE is guarded by the sentinel so a
		// concurrent re-measure cannot move it twice.
		if err := s.WithTxContext(ctx, func(tx *sql.Tx) error {
			if _, err := tx.Exec(`UPDATE ingest_state SET offset=(SELECT COALESCE(MAX(id),0) FROM events), updated_at=?
WHERE source=? AND path=? AND offset=?`, formatFixedUTC(now), scriptVersionSource, scriptHoldHWMPath, scriptHoldRemeasure); err != nil {
				return err
			}
			return tx.QueryRow(`SELECT offset FROM ingest_state WHERE source=? AND path=?`, scriptVersionSource, scriptHoldHWMPath).Scan(&hwm)
		}); err != nil {
			return false, err
		}
	}
	cursor, err := evidenceCursor(ctx, s.db)
	if err != nil {
		return false, err
	}
	if cursor < hwm {
		return true, nil // not re-recorded yet: no deadline can release this
	}
	var deadline int64
	err = s.db.QueryRowContext(ctx, `SELECT offset FROM ingest_state WHERE source=? AND path=?`, scriptVersionSource, scriptHoldDeadlinePath).Scan(&deadline)
	if err == sql.ErrNoRows {
		// First observation past the mark: start the clock. INSERT OR IGNORE
		// keeps an existing deadline if one was written meanwhile.
		deadline = now.Add(scriptHoldDuration).Unix()
		if err := s.WithTxContext(ctx, func(tx *sql.Tx) error {
			if _, err := tx.Exec(`INSERT OR IGNORE INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES(?,?,0,?,'',?)`,
				scriptVersionSource, scriptHoldDeadlinePath, deadline, formatFixedUTC(now)); err != nil {
				return err
			}
			return tx.QueryRow(`SELECT offset FROM ingest_state WHERE source=? AND path=?`, scriptVersionSource, scriptHoldDeadlinePath).Scan(&deadline)
		}); err != nil {
			return false, err
		}
	} else if err != nil {
		return false, err
	}
	if now.Unix() < deadline {
		// The pending partial index lists unsettled sessions; each is probed
		// on the line key for a line at or below the high-water mark.
		var pending bool
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM session_scripts ss WHERE (ss.settled_at='' OR ss.updated_at>ss.settled_at)
  AND EXISTS (SELECT 1 FROM session_script_lines l WHERE l.session_id=ss.session_id AND l.event_id<=?))`, hwm).Scan(&pending); err != nil {
			return false, err
		}
		if pending {
			return true, nil
		}
	}
	return false, s.WithTxContext(ctx, func(tx *sql.Tx) error {
		if err := carryScriptAssignmentsTx(tx); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM script_version_carry`); err != nil {
			return err
		}
		_, err := tx.Exec(`DELETE FROM ingest_state WHERE source=? AND path IN (?,?)`, scriptVersionSource, scriptHoldHWMPath, scriptHoldDeadlinePath)
		return err
	})
}

// scriptAssignment is a campaign_ids row of kind 'script', keyed by its
// fingerprint.
type scriptAssignment struct {
	campaignID string
	seq        int64
}

func carryScriptAssignmentsTx(tx *sql.Tx) error {
	var pairs [][2]string
	rows, err := tx.Query(`SELECT c.fingerprint, ss.fingerprint FROM script_version_carry c
JOIN session_scripts ss ON ss.session_id=c.session_id WHERE ss.fingerprint<>''`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var p [2]string
		if err := rows.Scan(&p[0], &p[1]); err != nil {
			rows.Close()
			return err
		}
		pairs = append(pairs, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	assigned := map[string]scriptAssignment{}
	rows, err = tx.Query(`SELECT value, campaign_id, seq FROM campaign_ids WHERE kind='script'`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var fp string
		var a scriptAssignment
		if err := rows.Scan(&fp, &a.campaignID, &a.seq); err != nil {
			rows.Close()
			return err
		}
		assigned[fp] = a
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	set, del := carryScriptAssignments(pairs, assigned)
	for _, fp := range del {
		if _, err := tx.Exec(`DELETE FROM campaign_ids WHERE kind='script' AND value=?`, fp); err != nil {
			return err
		}
	}
	for _, fp := range sortedAssignmentKeys(set) {
		a := set[fp]
		if _, err := tx.Exec(`INSERT INTO campaign_ids(kind,value,campaign_id,seq) VALUES('script',?,?,?)
ON CONFLICT(kind,value) DO UPDATE SET campaign_id=excluded.campaign_id, seq=excluded.seq`, fp, a.campaignID, a.seq); err != nil {
			return err
		}
	}
	return nil
}

// carryScriptAssignments maps script assignments from old fingerprints to
// the fingerprints their sessions settled to after a rebuild. pairs holds one
// (old, new) per session that settled again; assigned is campaign_ids' script
// rows. It returns the rows to write and the old fingerprints to delete.
//
// Per old fingerprint O that has a row:
//   - no session settled again (purged, or no script now): nothing to carry;
//     Group drops the row as it would any value without occurrences;
//   - otherwise O's row (campaign ID and seq) belongs to the fingerprint
//     holding most of O's sessions, ties to the smallest fingerprint. When
//     that is O itself (unchanged, or O keeps the majority of a split),
//     nothing moves. Otherwise the row moves there even if a minority of
//     O's sessions still settles to O: the campaign follows where most of
//     its sessions went, and the minority (O included) gets fresh rows from
//     Group. One rule for every split, so a survivor never outvotes the
//     majority.
//
// Several claims on one new fingerprint (a collapse, or a fingerprint that
// already has a row of its own) keep the lowest seq, then the lowest key:
// seq is Group's age order, and the oldest lineage owns a shared value.
func carryScriptAssignments(pairs [][2]string, assigned map[string]scriptAssignment) (map[string]scriptAssignment, []string) {
	counts := map[string]map[string]int{}
	for _, p := range pairs {
		if counts[p[0]] == nil {
			counts[p[0]] = map[string]int{}
		}
		counts[p[0]][p[1]]++
	}
	type claim struct {
		key string
		a   scriptAssignment
	}
	claims := map[string][]claim{}
	moved := map[string]bool{}
	for _, old := range sortedAssignmentKeys(assigned) {
		news := counts[old]
		if len(news) == 0 {
			continue
		}
		target, best := "", 0
		for fp, n := range news {
			if n > best || (n == best && fp < target) {
				target, best = fp, n
			}
		}
		if target == old {
			continue
		}
		claims[target] = append(claims[target], claim{old, assigned[old]})
		moved[old] = true
	}
	set := map[string]scriptAssignment{}
	for target, cs := range claims {
		if a, ok := assigned[target]; ok && !moved[target] {
			cs = append(cs, claim{target, a})
		}
		win := cs[0]
		for _, c := range cs[1:] {
			if c.a.seq < win.a.seq || (c.a.seq == win.a.seq && c.key < win.key) {
				win = c
			}
		}
		if win.key != target {
			set[target] = win.a
		}
	}
	var del []string
	for old := range moved {
		if _, ok := set[old]; !ok {
			del = append(del, old)
		}
	}
	sort.Strings(del)
	return set, del
}

func sortedAssignmentKeys(m map[string]scriptAssignment) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
