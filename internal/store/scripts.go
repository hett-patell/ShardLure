package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/networkshard/shardlure/internal/script"
)

const scriptDisplayBytes = 2048

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
		cmds                     int
		distinctive              int
	}
	var list []*pending
	err := func() error {
		// Same predicate as idx_session_scripts_pending so the planner can
		// use the partial index.
		rows, err := s.db.QueryContext(ctx, `SELECT session_id, first_seen, last_seen, updated_at FROM session_scripts
WHERE (settled_at='' OR updated_at>settled_at) AND last_seen < ? ORDER BY last_seen LIMIT ?`, formatFixedUTC(idleBefore), limit)
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
			if _, err := tx.Exec(`INSERT INTO scripts(fingerprint,normalized,display,command_count,distinctive,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)
ON CONFLICT(fingerprint) DO UPDATE SET first_seen=min(first_seen, excluded.first_seen), last_seen=max(last_seen, excluded.last_seen)`,
				p.fp, p.enc, p.display, p.cmds, p.distinctive, p.first, p.last); err != nil {
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

// AssignScriptFamilies places up to limit unassigned scripts, oldest first,
// into the closest representative's family or starts a family. Bounded and
// cancellable: compute cost is scripts x representatives x tokens^2, all of
// it done before the write transaction, so writeMu is held only for the
// UPDATEs. Families are display-only; they never link sessions.
func (s *Store) AssignScriptFamilies(ctx context.Context, limit int) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	type row struct {
		fp, enc     string
		distinctive bool
	}
	load := func(q string, args ...any) ([]row, error) {
		rows, err := s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []row
		for rows.Next() {
			var r row
			var d int
			if err := rows.Scan(&r.fp, &r.enc, &d); err != nil {
				return nil, err
			}
			r.distinctive = d == 1
			out = append(out, r)
		}
		return out, rows.Err()
	}
	pending, err := load(`SELECT fingerprint, normalized, distinctive FROM scripts WHERE family='' ORDER BY first_seen, fingerprint LIMIT ?`, limit)
	if err != nil || len(pending) == 0 {
		return 0, err
	}
	repRows, err := load(`SELECT fingerprint, normalized, distinctive FROM scripts WHERE family=fingerprint AND distinctive=1 ORDER BY fingerprint`)
	if err != nil {
		return 0, err
	}
	reps := make([]script.Rep, 0, len(repRows))
	for _, r := range repRows {
		reps = append(reps, script.Rep{Fingerprint: r.fp, Tokens: script.Tokens(r.enc)})
	}
	type assign struct {
		fp, family string
		dist       float64
	}
	out := make([]assign, 0, len(pending))
	for _, p := range pending {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		family, dist := p.fp, 0.0
		if p.distinctive {
			toks := script.Tokens(p.enc)
			if f, d, ok := script.AssignFamily(toks, reps); ok {
				family, dist = f, d
			} else {
				reps = insertRep(reps, script.Rep{Fingerprint: p.fp, Tokens: toks})
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
func insertRep(reps []script.Rep, r script.Rep) []script.Rep {
	i := 0
	for i < len(reps) && reps[i].Fingerprint < r.Fingerprint {
		i++
	}
	reps = append(reps, script.Rep{})
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
func (s *Store) PruneOrphanScripts(ctx context.Context) error {
	return s.WithTxContext(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM scripts WHERE NOT EXISTS (SELECT 1 FROM session_scripts ss WHERE ss.fingerprint=scripts.fingerprint)
  AND NOT EXISTS (SELECT 1 FROM scripts m WHERE m.family=scripts.fingerprint AND m.fingerprint<>scripts.fingerprint)`)
		return err
	})
}
