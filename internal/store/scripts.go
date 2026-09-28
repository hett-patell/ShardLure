package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/networkshard/shardlure/internal/script"
)

const scriptDisplayBytes = 2048

// familyPassBudget caps the wall-clock distance work of one family pass; a
// var so tests can shrink it.
var familyPassBudget = 2 * time.Second

// familyRepLoaded, when set (tests only), observes each representative whose
// normalized text a family pass loads.
var familyRepLoaded func(fingerprint string)

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
	type pending struct {
		id, first, last, updated string
		fp, enc, display         string
		cmds, tokens             int
		distinctive              int
	}
	var list []*pending
	err := func() error {
		// Same predicate as idx_session_scripts_pending so the planner can
		// use the partial index (EXPLAIN: SEARCH session_scripts USING INDEX
		// idx_session_scripts_pending (last_seen<?)). Idle is required on
		// both clocks: last_seen is event time; updated_at is ingest time.
		// Without the second, the history seed (recording in 5,000-rowid
		// windows) would fingerprint a session's prefix before the rest of
		// its old events were recorded. No prefix rows are ever written.
		cut := formatFixedUTC(idleBefore)
		rows, err := s.db.QueryContext(ctx, `SELECT session_id, first_seen, last_seen, updated_at FROM session_scripts
WHERE (settled_at='' OR updated_at>settled_at) AND last_seen < ? AND updated_at < ? ORDER BY last_seen LIMIT ?`, cut, cut, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p := &pending{}
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
			// Retention removed the lines mid-purge; the purge's next step
			// deletes this row. Never fingerprint an empty script.
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
	settled := 0
	err = s.WithTxContext(ctx, func(tx *sql.Tx) error {
		settled = 0
		// max(now, updated_at): a wall clock stepped back behind updated_at
		// would otherwise leave the row pending and re-settle it every pass.
		now := formatFixedUTC(time.Now())
		for _, p := range ready {
			r, err := tx.Exec(`UPDATE session_scripts SET fingerprint=?, settled_at=max(?, updated_at) WHERE session_id=? AND updated_at=?`,
				p.fp, now, p.id, p.updated)
			if err != nil {
				return err
			}
			if n, _ := r.RowsAffected(); n == 0 {
				continue // late line or purge since the read: next pass
			}
			if _, err := tx.Exec(`INSERT INTO scripts(fingerprint,normalized,display,command_count,distinctive,token_count,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(fingerprint) DO UPDATE SET first_seen=min(first_seen, excluded.first_seen), last_seen=max(last_seen, excluded.last_seen)`,
				p.fp, p.enc, p.display, p.cmds, p.distinctive, p.tokens, p.first, p.last); err != nil {
				return err
			}
			settled++
		}
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
// Bounded three ways, because the representative set is attacker-driven and
// unbounded: representatives are listed by (fingerprint, token_count) only;
// a representative's normalized text is loaded (once per pass, memoised) only
// when its token count is inside AssignFamily's length-ratio band for some
// pending script; and the distance work stops after familyPassBudget, leaving
// the rest for the next pass in the same order, so the outcome is the same
// as one unbounded pass. At least one script is always processed so a pass
// makes progress. All of it runs before the write transaction; writeMu is
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
	var reps []familyRep // sorted by fingerprint: AssignFamily's tie rule
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
			reps = append(reps, r)
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
			for _, r := range reps {
				if !script.InLengthBand(len(toks), r.tokens) {
					continue // AssignFamily would skip it: never load it
				}
				t, ok, err := repTokens(r.fp)
				if err != nil {
					return 0, err
				}
				if ok {
					cands = append(cands, script.Rep{Fingerprint: r.fp, Tokens: t})
				}
			}
			if f, d, ok := script.AssignFamily(toks, cands); ok {
				family, dist = f, d
			} else {
				reps = insertRep(reps, familyRep{p.fp, len(toks)})
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

// insertRep keeps reps sorted by fingerprint (AssignFamily's tie rule: the
// smallest fingerprint wins).
func insertRep(reps []familyRep, r familyRep) []familyRep {
	i := 0
	for i < len(reps) && reps[i].fp < r.fp {
		i++
	}
	reps = append(reps, familyRep{})
	copy(reps[i+1:], reps[i:])
	reps[i] = r
	return reps
}

type familyVariant struct {
	Fingerprint string  `json:"fingerprint"`
	Distance    float64 `json:"distance"`
	Sessions    int     `json:"sessions"`
	Links       bool    `json:"links"`
	Reason      string  `json:"reason"`
}

// RebuildScriptFamilies materialises the Scripts view so the panel reads one
// small table. population is the Cowrie actor count within retention. Reads
// run in one read-only snapshot outside writeMu; only the replace is a write.
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
		return vrows.Err()
	}()
	if err != nil {
		return err
	}
	return s.WithTxContext(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM script_families`); err != nil {
			return err
		}
		for id, f := range fams {
			v, err := json.Marshal(f.variants)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO script_families(family,display,variants,sessions,actors,ips,command_count,distinctive,links,reason,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
				id, f.display, string(v), f.sessions, f.actors, f.ips, f.cmds, scriptBool(f.distinctive), scriptBool(f.links), f.reason, f.first, f.last); err != nil {
				return err
			}
		}
		return nil
	})
}

func scriptBool(b bool) int {
	if b {
		return 1
	}
	return 0
}

// PruneOrphanScripts drops scripts no session points at any more (retention,
// or a re-settle that moved the session to a new fingerprint) unless they
// represent a family that still has members.
//
// Freeing a representative is not transitive within one call: the members
// and the representative are judged against the same pre-delete state, so a
// representative is freed on the pass after its last member goes.
//
// Assumes a single sequential caller alongside AssignScriptFamilies: run
// concurrently, it could delete a representative an in-flight assign pass
// has loaded, and that pass would then file new members under a family
// whose representative row no longer exists.
func (s *Store) PruneOrphanScripts(ctx context.Context) error {
	return s.WithTxContext(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM scripts WHERE NOT EXISTS (SELECT 1 FROM session_scripts ss WHERE ss.fingerprint=scripts.fingerprint)
  AND NOT EXISTS (SELECT 1 FROM scripts m WHERE m.family=scripts.fingerprint AND m.fingerprint<>scripts.fingerprint)`)
		return err
	})
}
