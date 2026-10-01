package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/script"
)

const scriptDisplayBytes = 2048

// familyPassBudget caps the wall-clock distance work of one family pass; a
// var so tests can shrink it.
var familyPassBudget = 2 * time.Second

// settleBeforeWrite, when set (tests only), runs between
// SettleSessionScripts' unlocked compute and its guarded write, so a test can
// record a late line there.
var settleBeforeWrite func()

// familyRepLoaded, when set (tests only), observes each representative whose
// normalized text a family pass loads.
var familyRepLoaded func(fingerprint string)

// settlePending is one session SettleSessionScripts read as pending, with the
// fingerprint and script row computed from its lines.
type settlePending struct {
	id, first, last, updated string
	fp, enc, display         string
	cmds, tokens             int
	distinctive              int
}

// settleSessionsBatched runs the guarded settle UPDATE for every ready
// session in multi-row statements (batchParams-bounded, three parameters per
// session plus one for now) and returns the session IDs it matched. Each
// session keeps its own guard, session_id AND updated_at as read, through a
// VALUES CTE joined in UPDATE ... FROM; RETURNING replaces the per-statement
// RowsAffected.
func settleSessionsBatched(ctx context.Context, tx *sql.Tx, ready []*settlePending, now string) (map[string]bool, error) {
	matched := make(map[string]bool, len(ready))
	per := max(1, (batchParams-1)/3) // 3 params per session, one for now
	for lo := 0; lo < len(ready); lo += per {
		hi := min(lo+per, len(ready))
		var q strings.Builder
		q.WriteString(`WITH v(sid, upd, fp) AS (VALUES `)
		args := make([]any, 0, 3*(hi-lo)+1)
		for i := lo; i < hi; i++ {
			if i > lo {
				q.WriteByte(',')
			}
			q.WriteString(`(?,?,?)`)
			args = append(args, ready[i].id, ready[i].updated, ready[i].fp)
		}
		q.WriteString(`) UPDATE session_scripts SET fingerprint=v.fp, settled_at=max(?, session_scripts.updated_at)
FROM v WHERE session_scripts.session_id=v.sid AND session_scripts.updated_at=v.upd RETURNING session_scripts.session_id`)
		args = append(args, now)
		rows, err := tx.QueryContext(ctx, q.String(), args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			matched[id] = true
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return matched, nil
}

// settlePendingQuery lists sessions due for a settle. Its WHERE carries
// idx_session_scripts_pending's predicate verbatim so the planner can use the
// partial index; TestPurgeScriptLinesPlan pins the plan.
const settlePendingQuery = `SELECT session_id, first_seen, last_seen, updated_at FROM session_scripts
WHERE (settled_at='' OR updated_at>settled_at) AND last_seen < ? AND updated_at < ? ORDER BY last_seen LIMIT ?`

// SettleSessionScripts computes each idle session's script once: the
// fingerprint of its lines in event order. Sessions that received commands
// after their last settle (updated_at > settled_at) are re-settled; the
// script row of their old fingerprint is left for PruneOrphanScripts, which
// removes it once nothing references it.
//
// Lines are read and fingerprinted outside writeMu (up to limit sessions x
// MaxNormalizedBytes of SHA-256); the write transaction only applies the
// results. Each session's write is guarded by the updated_at value that was
// read, so a line recorded in between skips that session this pass instead
// of settling it on a stale script; the next pass picks it up again.
func (s *Store) SettleSessionScripts(ctx context.Context, idleBefore time.Time, limit int) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if limit <= 0 || limit > 2000 {
		limit = 2000
	}
	var list []*settlePending
	err := func() error {
		// Same predicate as idx_session_scripts_pending so the planner can
		// use the partial index (EXPLAIN: SEARCH session_scripts USING INDEX
		// idx_session_scripts_pending (last_seen<?)). Idle is required on
		// both clocks: last_seen is event time; updated_at is ingest time.
		// Without the second, the history seed (recording in 5,000-rowid
		// windows) would fingerprint a session's prefix before the rest of
		// its old events were recorded. No prefix rows are ever written.
		cut := formatFixedUTC(idleBefore)
		rows, err := s.db.QueryContext(ctx, settlePendingQuery, cut, cut, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p := &settlePending{}
			if err := rows.Scan(&p.id, &p.first, &p.last, &p.updated); err != nil {
				return err
			}
			list = append(list, p)
		}
		return rows.Err()
	}()
	if err != nil || len(list) == 0 {
		return 0, err
	}
	ready := list[:0]
	for _, p := range list {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		lines, err := s.sessionScriptLines(ctx, p.id)
		if err != nil {
			return 0, err
		}
		if len(lines) == 0 {
			// The session was deleted after it was listed: retention takes
			// its row and lines in one transaction (purgeCampaignDerived),
			// and a normaliser reset deletes rows in earlier transactions
			// than their lines (ResetScriptsForVersion). Never fingerprint
			// an empty script. Non-empty lines are either the whole session
			// or, mid-reset, lines whose row is already gone, and then the
			// guarded UPDATE below finds no row and writes nothing.
			continue
		}
		p.enc = script.Join(lines)
		cmds := script.Split(p.enc)
		p.fp = script.Fingerprint(p.enc)
		p.display = script.Display(p.enc, scriptDisplayBytes)
		p.cmds = script.CommandCount(cmds)
		p.distinctive = scriptBool(script.Distinctive(cmds))
		p.tokens = len(script.Tokens(p.enc)) // capped at MaxDistanceTokens, as distance sees it
		ready = append(ready, p)
	}
	if settleBeforeWrite != nil {
		settleBeforeWrite()
	}
	settled := 0
	err = s.WithTxContext(ctx, func(tx *sql.Tx) error {
		settled = 0
		// max(now, updated_at): a wall clock stepped back behind updated_at
		// would otherwise leave the row pending and re-settle it every pass.
		now := formatFixedUTC(time.Now())
		// Multi-row statements, as RecordCampaignEvidence and SaveGrouping
		// write (see batchParams): modernc re-prepares on every Exec, so two
		// statements per session held writeMu for the statement count, not
		// the row count. 2,000 sessions x 2 statements measured 121-138 ms
		// of writeMu on x86 (a full settle pass runs ~11 times during a
		// rebuild on prod's 21k sessions); batched, 60-64 ms, flat across
		// 64-1,024 params per UPDATE, so batchParams is kept. The plan is
		// SCAN v then SEARCH session_scripts by its primary key, O(batch)
		// regardless of table size. The guarded UPDATE keeps
		// its per-session check (session_id AND updated_at from the read)
		// through a VALUES CTE joined in UPDATE ... FROM, and RETURNING says
		// which sessions it matched, so the scripts upsert runs only for
		// those, exactly as the per-row RowsAffected check did. A session
		// that gained a line or was purged since the read matches nothing:
		// next pass.
		matched, err := settleSessionsBatched(ctx, tx, ready, now)
		if err != nil {
			return err
		}
		if len(matched) == 0 {
			return nil
		}
		// One upsert row per matched session, in the read order. SQLite
		// applies a multi-row INSERT ... ON CONFLICT row by row, so several
		// sessions settling to one fingerprint in a batch fold their
		// first/last_seen exactly as consecutive single-row statements did.
		rows := make([]*settlePending, 0, len(matched))
		for _, p := range ready {
			if matched[p.id] {
				rows = append(rows, p)
			}
		}
		if err := execBatched(ctx, tx, `INSERT INTO scripts(fingerprint,normalized,display,command_count,distinctive,token_count,first_seen,last_seen) VALUES `,
			`(?,?,?,?,?,?,?,?)`, ` ON CONFLICT(fingerprint) DO UPDATE SET first_seen=min(first_seen, excluded.first_seen), last_seen=max(last_seen, excluded.last_seen)`,
			len(rows), func(i int) []any {
				p := rows[i]
				return []any{p.fp, p.enc, p.display, p.cmds, p.distinctive, p.tokens, p.first, p.last}
			}); err != nil {
			return err
		}
		settled = len(rows)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return settled, nil
}

// sessionScriptLines returns a session's encoded lines in event order.
func (s *Store) sessionScriptLines(ctx context.Context, sessionID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT line FROM session_script_lines WHERE session_id=? ORDER BY event_id`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var l string
		if err := rows.Scan(&l); err != nil {
			return nil, err
		}
		lines = append(lines, l)
	}
	return lines, rows.Err()
}

// familyRep is a representative as a family pass lists it: no script text.
type familyRep struct {
	fp     string
	tokens int
}

// AssignScriptFamilies places up to limit unassigned scripts, oldest first,
// into the closest representative's family or starts a family. Families are
// display-only; they never link sessions.
//
// Bounded four ways, because the representative set is attacker-driven and
// unbounded: representatives are listed by (fingerprint, token_count) only;
// a pending script is compared with at most familyNearestReps of them, the
// in-band ones nearest in token count (nearestReps: deterministic, ties by
// fingerprint); a representative's normalized text is loaded (once per pass,
// memoised) only when it is one of those; and the distance work stops after
// familyPassBudget, leaving the rest for the next pass in the same order, so
// the outcome is the same as one unbounded pass. At least one script is
// always processed so a pass makes progress. All of it runs before the write transaction; writeMu is
// held only for the UPDATEs.
//
// Assumes a single sequential caller (the live ticker): a concurrent
// PruneOrphanScripts could delete a representative this pass has loaded, and
// two concurrent passes could each start a family for near-identical scripts.
func (s *Store) AssignScriptFamilies(ctx context.Context, limit int) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	type pendingScript struct {
		fp, enc     string
		distinctive bool
	}
	var pending []pendingScript
	err := func() error {
		rows, err := s.db.QueryContext(ctx, `SELECT fingerprint, normalized, distinctive FROM scripts WHERE family='' ORDER BY first_seen, fingerprint LIMIT ?`, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p pendingScript
			var d int
			if err := rows.Scan(&p.fp, &p.enc, &d); err != nil {
				return err
			}
			p.distinctive = d == 1
			pending = append(pending, p)
		}
		return rows.Err()
	}()
	if err != nil || len(pending) == 0 {
		return 0, err
	}
	// Representatives bucketed by token count, each bucket sorted by
	// fingerprint. Token counts are capped at MaxDistanceTokens, so there
	// are at most a few hundred buckets and nearestReps walks them outward
	// from a pending script's own count.
	byTokens := map[int][]string{}
	err = func() error {
		rows, err := s.db.QueryContext(ctx, `SELECT fingerprint, token_count FROM scripts WHERE family=fingerprint AND distinctive=1 ORDER BY fingerprint`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r familyRep
			if err := rows.Scan(&r.fp, &r.tokens); err != nil {
				return err
			}
			byTokens[r.tokens] = append(byTokens[r.tokens], r.fp) // ORDER BY fingerprint
		}
		return rows.Err()
	}()
	if err != nil {
		return 0, err
	}
	memo := map[string][]string{} // representative tokens, loaded on demand
	repTokens := func(fp string) ([]string, bool, error) {
		if t, ok := memo[fp]; ok {
			return t, t != nil, nil
		}
		if familyRepLoaded != nil {
			familyRepLoaded(fp)
		}
		var enc string
		err := s.db.QueryRowContext(ctx, `SELECT normalized FROM scripts WHERE fingerprint=?`, fp).Scan(&enc)
		if err == sql.ErrNoRows {
			memo[fp] = nil // pruned since listed
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		t := script.Tokens(enc)
		memo[fp] = t
		return t, true, nil
	}
	type assign struct {
		fp, family string
		dist       float64
	}
	out := make([]assign, 0, len(pending))
	start := time.Now()
	for _, p := range pending {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if len(out) > 0 && time.Since(start) >= familyPassBudget {
			break // the rest waits for the next pass, same order
		}
		family, dist := p.fp, 0.0
		if p.distinctive {
			toks := script.Tokens(p.enc)
			var cands []script.Rep
			// Only in-band representatives are listed (AssignFamily would
			// skip the rest: never load them), at most familyNearestReps.
			for _, fp := range nearestReps(byTokens, len(toks), familyNearestReps) {
				t, ok, err := repTokens(fp)
				if err != nil {
					return 0, err
				}
				if ok {
					cands = append(cands, script.Rep{Fingerprint: fp, Tokens: t})
				}
			}
			if f, d, ok := script.AssignFamily(toks, cands); ok {
				family, dist = f, d
			} else {
				byTokens[len(toks)] = insertSorted(byTokens[len(toks)], p.fp)
				memo[p.fp] = toks
			}
		}
		out = append(out, assign{p.fp, family, dist})
	}
	assigned := 0
	err = s.WithTxContext(ctx, func(tx *sql.Tx) error {
		assigned = 0
		for _, a := range out {
			r, err := tx.Exec(`UPDATE scripts SET family=?, family_distance=? WHERE fingerprint=? AND family=''`, a.family, a.dist, a.fp)
			if err != nil {
				return err
			}
			if n, _ := r.RowsAffected(); n > 0 {
				assigned++
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return assigned, nil
}

// insertSorted inserts fp into a fingerprint-sorted bucket.
func insertSorted(bucket []string, fp string) []string {
	i := sort.SearchStrings(bucket, fp)
	bucket = append(bucket, "")
	copy(bucket[i+1:], bucket[i:])
	bucket[i] = fp
	return bucket
}

// familyNearestReps is how many representatives one pending script is
// compared with. Each comparison is an O(n*m) token distance (up to 300x300),
// and the representative set is attacker-driven: 3,000 in-band
// representatives cost 2.7 s of CPU per pending script on x86 (measured),
// so one pass spent its whole budget on a single script. 256 bounds the cost
// per script and is far above any real family count in one length band.
const familyNearestReps = 256

// nearestReps returns at most k representatives inside AssignFamily's length
// band for a script of n tokens: the ones nearest in token count, ties by
// fingerprint, returned sorted by fingerprint (AssignFamily's tie rule). The
// choice depends only on the stored rows, so a pass is deterministic and a
// budget-split pass resumes to the same result. Variants of one bot differ by
// a few tokens, so the nearest counts are where a family match lives.
func nearestReps(byTokens map[int][]string, n, k int) []string {
	var out []string
	for d := 0; len(out) < k; d++ {
		lo, hi := n-d, n+d
		inLo, inHi := script.InLengthBand(n, lo), script.InLengthBand(n, hi)
		if !inLo && !inHi {
			break // the band is contiguous around n: nothing further is in it
		}
		var ring []string
		if inLo {
			ring = append(ring, byTokens[lo]...)
		}
		if inHi && hi != lo {
			ring = append(ring, byTokens[hi]...)
		}
		if len(ring) > k-len(out) {
			sort.Strings(ring) // equal distance: smallest fingerprints first
			ring = ring[:k-len(out)]
		}
		out = append(out, ring...)
	}
	sort.Strings(out)
	return out
}

type familyVariant struct {
	Fingerprint string  `json:"fingerprint"`
	Distance    float64 `json:"distance"`
	Sessions    int     `json:"sessions"`
	Links       bool    `json:"links"`
	Reason      string  `json:"reason"`
}

// FamilyVariantCap bounds the variants a script_families row stores: the
// FamilyVariantCap largest by sessions (ties in stored order), plus the
// representative. A family stores one variant per member fingerprint, and a
// bot whose scripts differ only in text the normaliser keeps mints one per
// session, so the uncapped array grew without bound: 20 families of 30,000
// variants made every 30 s Scripts poll read ~113 MB and take ~0.8 s, and
// the web memo kept those strings resident (premerge store-read M1, web
// M1/M5). Nothing reads past the cap: the list sends 50 and the script
// dialog 200 (web listVariantCap/scriptVariantCap, pinned <= this), and the
// "N of M" total is a count of the family's scripts (VariantsTotal), not the
// length of this array. Capping keeps the survivors in stored order, so the
// largest-N view of the capped array is exactly that of the whole one.
const FamilyVariantCap = 200

func capFamilyVariants(vs []familyVariant, representative string) []familyVariant {
	if len(vs) <= FamilyVariantCap {
		return vs
	}
	idx := make([]int, len(vs))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return vs[idx[a]].Sessions > vs[idx[b]].Sessions })
	keep := make([]bool, len(vs))
	for _, i := range idx[:FamilyVariantCap] {
		keep[i] = true
	}
	out := make([]familyVariant, 0, FamilyVariantCap+1)
	for i, v := range vs {
		if keep[i] || v.Fingerprint == representative {
			out = append(out, v)
		}
	}
	return out
}

// RebuildScriptFamilies materialises the Scripts view so the panel reads one
// small table. population is the Cowrie actor count within retention. Reads
// run in one read-only snapshot outside writeMu, and so does the comparison
// with the stored rows: only families whose row would change are written.
//
// It runs on every regroup (every 10 minutes and after edits), and the family
// count is attacker-driven, since each non-distinctive script is its own
// family. The old DELETE-everything-then-INSERT held writeMu for every row on
// every regroup: 10,000 families cost 204-230 ms on x86 (~0.5-0.7 s on ARM),
// and batching the INSERTs saved under 10% because the cost is per row, not
// per statement (store-pipeline audit M3). Between two regroups only the
// families that gained or lost a session, or whose link decision moved with
// the population, differ, so a steady-state regroup writes a handful of rows
// or none; ARM carries ~164 families. The full-size writes that remain (the
// first rebuild after a version reset, which empties the table) go in
// familyWriteChunk-row transactions so ingest interleaves. Only the campaign
// worker writes script_families (this and the version reset, one goroutine
// under the cross-process lease), so the stored rows cannot move between the
// snapshot and the write; a reader between two chunks sees some families
// already updated, which is harmless for a display-only view.
func (s *Store) RebuildScriptFamilies(ctx context.Context, population int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	type fam struct {
		display, first, last  string
		sessions, actors, ips int
		cmds                  int
		distinctive, links    bool
		reason                string
		variants              []familyVariant
	}
	fams := map[string]*fam{}
	stored := map[string]familyRow{}
	err := func() error {
		rtx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return err
		}
		defer rtx.Rollback()
		rows, err := rtx.QueryContext(ctx, `SELECT sc.family, COUNT(*), COUNT(DISTINCT ss.actor_id), COUNT(DISTINCT ss.src_ip), MIN(ss.first_seen), MAX(ss.last_seen)
FROM session_scripts ss JOIN scripts sc ON sc.fingerprint=ss.fingerprint WHERE sc.family<>'' GROUP BY sc.family`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			f := &fam{}
			if err := rows.Scan(&id, &f.sessions, &f.actors, &f.ips, &f.first, &f.last); err != nil {
				rows.Close()
				return err
			}
			fams[id] = f
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		vrows, err := rtx.QueryContext(ctx, `SELECT sc.family, sc.fingerprint, sc.family_distance, sc.distinctive, sc.command_count, sc.display,
  COUNT(ss.session_id), COUNT(DISTINCT ss.actor_id)
FROM scripts sc LEFT JOIN session_scripts ss ON ss.fingerprint=sc.fingerprint
WHERE sc.family<>'' GROUP BY sc.fingerprint ORDER BY sc.family, sc.family_distance, sc.fingerprint`)
		if err != nil {
			return err
		}
		defer vrows.Close()
		for vrows.Next() {
			var family, fp, display string
			var dist float64
			var distinctive, cmds, sessions, actors int
			if err := vrows.Scan(&family, &fp, &dist, &distinctive, &cmds, &display, &sessions, &actors); err != nil {
				return err
			}
			f := fams[family]
			if f == nil {
				continue // no member has a session any more
			}
			links, reason := script.LinkDecision(distinctive == 1, actors, population)
			f.variants = append(f.variants, familyVariant{Fingerprint: fp, Distance: dist, Sessions: sessions, Links: links, Reason: reason})
			if fp == family {
				f.display, f.cmds, f.distinctive = display, cmds, distinctive == 1
				if f.reason == "" {
					f.reason = reason
				}
			}
			if links && !f.links {
				f.links, f.reason = true, reason
			}
		}
		if err := vrows.Err(); err != nil {
			return err
		}
		srows, err := rtx.QueryContext(ctx, `SELECT family,display,variants,sessions,actors,ips,command_count,distinctive,links,reason,first_seen,last_seen FROM script_families`)
		if err != nil {
			return err
		}
		defer srows.Close()
		for srows.Next() {
			var id string
			var r familyRow
			if err := srows.Scan(&id, &r.display, &r.variants, &r.sessions, &r.actors, &r.ips, &r.cmds, &r.distinctive, &r.links, &r.reason, &r.first, &r.last); err != nil {
				return err
			}
			stored[id] = r
		}
		return srows.Err()
	}()
	if err != nil {
		return err
	}
	want := make(map[string]familyRow, len(fams))
	for id, f := range fams {
		v, err := json.Marshal(capFamilyVariants(f.variants, id))
		if err != nil {
			return err
		}
		want[id] = familyRow{display: f.display, variants: string(v), sessions: f.sessions, actors: f.actors, ips: f.ips,
			cmds: f.cmds, distinctive: scriptBool(f.distinctive), links: scriptBool(f.links), reason: f.reason, first: f.first, last: f.last}
	}
	var upserts, deletes []string
	for _, id := range sortedFamilyKeys(want) {
		if old, ok := stored[id]; !ok || old != want[id] {
			upserts = append(upserts, id)
		}
	}
	for _, id := range sortedFamilyKeys(stored) {
		if _, ok := want[id]; !ok {
			deletes = append(deletes, id)
		}
	}
	for lo := 0; lo < len(deletes); lo += familyWriteChunk {
		chunk := deletes[lo:min(lo+familyWriteChunk, len(deletes))]
		if err := s.WithTxContext(ctx, func(tx *sql.Tx) error {
			for _, id := range chunk {
				if _, err := tx.Exec(`DELETE FROM script_families WHERE family=?`, id); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	for lo := 0; lo < len(upserts); lo += familyWriteChunk {
		chunk := upserts[lo:min(lo+familyWriteChunk, len(upserts))]
		if err := s.WithTxContext(ctx, func(tx *sql.Tx) error {
			for _, id := range chunk {
				f := want[id]
				if _, err := tx.Exec(`INSERT INTO script_families(family,display,variants,sessions,actors,ips,command_count,distinctive,links,reason,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(family) DO UPDATE SET display=excluded.display, variants=excluded.variants, sessions=excluded.sessions, actors=excluded.actors,
  ips=excluded.ips, command_count=excluded.command_count, distinctive=excluded.distinctive, links=excluded.links, reason=excluded.reason,
  first_seen=excluded.first_seen, last_seen=excluded.last_seen`,
					id, f.display, f.variants, f.sessions, f.actors, f.ips, f.cmds, f.distinctive, f.links, f.reason, f.first, f.last); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// familyWriteChunk bounds one RebuildScriptFamilies write transaction: ~500
// rows is ~10 ms of writeMu on x86 at the measured per-row cost, so even the
// full rebuild after a version reset releases the lock between chunks.
const familyWriteChunk = 500

// familyRow is one script_families row minus its key, comparable with ==.
type familyRow struct {
	display, variants                               string
	sessions, actors, ips, cmds, distinctive, links int
	reason, first, last                             string
}

func sortedFamilyKeys(m map[string]familyRow) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func scriptBool(b bool) int {
	if b {
		return 1
	}
	return 0
}

// PruneOrphanScripts drops scripts no session points at any more (retention,
// or a re-settle that moved the session to a new fingerprint).
//
// A representative is no exception. It used to be kept while any member still
// had sessions, so its normalized text (attacker commands, possibly typed
// passwords) outlived retention_days for as long as the family kept recurring,
// against the rule that settled scripts follow event retention
// (store-pipeline audit M8). Now a representative with no session of its own
// dissolves its family in the same transaction: every member's family is
// cleared and the representative is deleted with the other orphans. The next
// AssignScriptFamilies pass regroups the members around a live
// representative. Families are display only (they never link), so the only
// visible effect is a new family ID in the Scripts view, which
// RebuildScriptFamilies rewrites on the next regroup. Re-electing a member in
// place was rejected: every other member's family_distance is measured to the
// old representative, and recomputing it needs script.* under writeMu.
//
// Assumes a single sequential caller alongside AssignScriptFamilies: run
// concurrently, it could delete a representative an in-flight assign pass
// has loaded, and that pass would then file new members under a family
// whose representative row no longer exists.
func (s *Store) PruneOrphanScripts(ctx context.Context) error {
	return s.WithTxContext(ctx, func(tx *sql.Tx) error {
		// idx_scripts_family serves the member lookup; the representative
		// set is bounded by families whose own sessions retention just took.
		if _, err := tx.Exec(`UPDATE scripts SET family='', family_distance=0 WHERE family IN (
  SELECT r.fingerprint FROM scripts r WHERE r.family=r.fingerprint
    AND NOT EXISTS (SELECT 1 FROM session_scripts ss WHERE ss.fingerprint=r.fingerprint)
    AND EXISTS (SELECT 1 FROM scripts m WHERE m.family=r.fingerprint AND m.fingerprint<>r.fingerprint))`); err != nil {
			return err
		}
		_, err := tx.Exec(`DELETE FROM scripts WHERE NOT EXISTS (SELECT 1 FROM session_scripts ss WHERE ss.fingerprint=scripts.fingerprint)
  AND NOT EXISTS (SELECT 1 FROM scripts m WHERE m.family=scripts.fingerprint AND m.fingerprint<>scripts.fingerprint)`)
		return err
	})
}
