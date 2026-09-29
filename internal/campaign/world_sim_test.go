package campaign

// TestCampaignWorldSimulation is the randomized, day-by-day world simulation
// the identity rules in group.go were checked against (review round 4 onward).
// Run it before changing any identity rule in group.go (ID inheritance,
// aliases, merges, splits, edit resolution, renames).
//
// A world has families (true campaigns) with rolling or constant evidence, a
// retention window, bridges (shared session, third-party actor, new value X),
// organic permanent merges (3 variants), mixed actors, and operator edits
// issued from the previous cycle's output. Ground truth is computed from the
// world, never from Group's own state.
//
// It is opt-in and never runs in CI or a plain `go test ./...`:
//
//	SHARDLURE_CAMPAIGN_SIM=300 go test ./internal/campaign/ -run TestCampaignWorldSimulation -v
//
// Knobs (environment):
//
//	SHARDLURE_CAMPAIGN_SIM=<trials>          required; number of random worlds
//	SHARDLURE_CAMPAIGN_SIM_SEED=<n>          replay only seed n, verbosely (trial i uses seed BASE+i+1)
//	SHARDLURE_CAMPAIGN_SIM_BASE=<n>          seed offset for a fresh batch of worlds
//	SHARDLURE_CAMPAIGN_SIM_MODE=organic|const  bias worlds toward organic merges / constant evidence
//	SHARDLURE_CAMPAIGN_SIM_BRIDGE_KIND=0|1|2   force one bridge kind (shared session, third-party actor, new value)
//	SHARDLURE_CAMPAIGN_SIM_NO_BRIDGE, _NO_ORGANIC, _NO_NEW_VALUE, _NO_EDITS=1  disable that feature
//
// Reading the output:
//   - It logs failure counts per class with example seeds and NEVER fails on
//     them; the counts are the result. Compare them before and after a change.
//   - A small residue in home-collision / id-lost-hard / id-lost-soft is the
//     expected "born-in-bridge" case: a family whose first evidence arrives in
//     a session shared with an existing campaign inherits that lineage. This
//     is the accepted known limitation documented in CLAUDE.md (Campaigns and
//     scripts, Identity). Membership stays correct.
//   - organic-churn counts baselines recorded on bridged or edit days, a known
//     artifact of the simulation's bookkeeping, not an identity bug by itself.
//   - Worker goroutines are bounded by GOMAXPROCS.

import (
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type qFam struct {
	actors     []string
	start, end int
	vals       []qVal
	constKey   bool
	turnover   int
}
type qVal struct {
	name       string
	born, died int
}
type qBridge struct {
	a, b, start, end, kind int
	newEach                bool
	cont, x                string
	ignoreDay              int
}
type qOrg struct{ a, b, day, variant int }
type qMixed struct {
	name string
	p, q int
}
type qWorld struct {
	R, T       int
	fams       []*qFam
	bridges    []*qBridge
	orgs       []*qOrg
	mixed      []qMixed
	valFam     map[string]int
	daily      [][]Occurrence
	ignorePlan map[int]int
}

func qKind(v string) string {
	switch v[0] {
	case 'K':
		return "ssh_key"
	case 'S':
		return "script"
	}
	return "payload"
}

func qOcc(v, sess, actor string, day int) Occurrence { return o(qKind(v), v, sess, actor, day) }

func (f *qFam) cur(d int) []string {
	if d < f.start || d >= f.end {
		return nil
	}
	var out []string
	for _, v := range f.vals {
		if v.born <= d && d < v.died {
			out = append(out, v.name)
		}
	}
	return out
}

func qSubset(r *rand.Rand, xs []string) []string {
	var out []string
	for _, x := range xs {
		if r.Intn(2) == 0 {
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		out = []string{xs[r.Intn(len(xs))]}
	}
	return out
}

func qBuild(r *rand.Rand, mode string) *qWorld {
	w := &qWorld{valFam: map[string]int{}, ignorePlan: map[int]int{}}
	big := r.Intn(10) < 3
	nf, nb := 3+r.Intn(8), 1+r.Intn(4)
	if big {
		nf, nb = 20+r.Intn(5), 4+r.Intn(6)
	}
	w.T = 45 + r.Intn(26)
	w.R = 6 + r.Intn(9)
	pref := "KPS"
	for i := 0; i < nf; i++ {
		f := &qFam{end: w.T}
		if r.Intn(5) == 0 {
			f.start = r.Intn(w.T / 2)
		}
		if r.Intn(7) == 0 {
			f.end = min(w.T, f.start+10+r.Intn(w.T))
		}
		for j := 0; j < 4+r.Intn(3); j++ {
			f.actors = append(f.actors, fmt.Sprintf("f%da%d", i, j))
		}
		if r.Intn(3) == 0 || mode == "const" {
			f.constKey = true
			f.vals = append(f.vals, qVal{fmt.Sprintf("Kf%dkey", i), f.start, 1 << 30})
		}
		f.turnover = 2 + r.Intn(6)
		overlap := 1 + r.Intn(3)
		for k, b := 0, f.start; b < f.end; k, b = k+1, b+f.turnover {
			f.vals = append(f.vals, qVal{fmt.Sprintf("%cf%dv%d", pref[r.Intn(3)], i, k), b, b + f.turnover + overlap})
		}
		w.fams = append(w.fams, f)
	}
	if (r.Intn(5) < 2 || mode == "organic" || mode == "const") && os.Getenv("SHARDLURE_CAMPAIGN_SIM_NO_ORGANIC") == "" {
		for k := 0; k < 1+r.Intn(2); k++ {
			a, b := r.Intn(nf), r.Intn(nf)
			day := 5 + r.Intn(max(1, w.T-30))
			fa, fb := w.fams[a], w.fams[b]
			if a == b || fa.end < w.T || fb.end < w.T || fa.start > day || fb.start > day {
				continue
			}
			w.orgs = append(w.orgs, &qOrg{a, b, day, r.Intn(3)})
		}
	}
	if os.Getenv("SHARDLURE_CAMPAIGN_SIM_NO_BRIDGE") != "" {
		nb = 0
	}
	for k := 0; k < nb; k++ {
		a, b := r.Intn(nf), r.Intn(nf)
		br := &qBridge{a: a, b: b, kind: r.Intn(3), ignoreDay: -1}
		if s := os.Getenv("SHARDLURE_CAMPAIGN_SIM_BRIDGE_KIND"); s != "" {
			br.kind = int(s[0] - '0')
		}
		dur := 1 + r.Intn(3)
		if r.Intn(2) == 0 {
			dur = 10 + r.Intn(11)
		}
		br.start = 3 + r.Intn(max(1, w.T-w.R-dur-5))
		br.end = br.start + dur
		fa, fb := w.fams[a], w.fams[b]
		if a == b || fa.start > br.start || fb.start > br.start || fa.end < br.end || fb.end < br.end {
			continue
		}
		if br.kind < 2 {
			br.newEach = r.Intn(2) == 0 && os.Getenv("SHARDLURE_CAMPAIGN_SIM_NO_NEW_VALUE") == ""
			if r.Intn(2) == 0 && os.Getenv("SHARDLURE_CAMPAIGN_SIM_NO_NEW_VALUE") == "" {
				br.cont = fmt.Sprintf("Pc%d", k)
				fa.vals = append(fa.vals, qVal{br.cont, br.start, br.start + 5 + r.Intn(10)})
			}
		} else {
			br.x = fmt.Sprintf("Sx%d", k)
			if r.Intn(2) == 0 {
				w.ignorePlan[br.start+r.Intn(dur)] = len(w.bridges)
			}
		}
		w.bridges = append(w.bridges, br)
	}
	for k := 0; k < r.Intn(4); k++ {
		if p, q := r.Intn(nf), r.Intn(nf); p != q {
			w.mixed = append(w.mixed, qMixed{fmt.Sprintf("mx%d", k), p, q})
		}
	}
	for i, f := range w.fams {
		for _, v := range f.vals {
			w.valFam[v.name] = i
		}
	}
	w.daily = make([][]Occurrence, w.T)
	for d := 0; d < w.T; d++ {
		var day []Occurrence
		add := func(sess, actor string, vals []string) {
			for _, v := range vals {
				day = append(day, qOcc(v, sess, actor, d))
			}
		}
		for i, f := range w.fams {
			cur := f.cur(d)
			if len(cur) == 0 {
				continue
			}
			link := append([]string(nil), cur...)
			for _, og := range w.orgs {
				if og.variant == 2 && d >= og.day && (og.a == i || og.b == i) {
					p := og.b
					if og.b == i {
						p = og.a
					}
					link = append(link, w.fams[p].cur(d)...)
				}
			}
			add(fmt.Sprintf("L%d_%d", d, i), f.actors[0], link)
			perm := r.Perm(len(f.actors) - 1)
			for e := 0; e < 2; e++ {
				add(fmt.Sprintf("E%d_%d_%d", d, i, e), f.actors[1+perm[e]], qSubset(r, cur))
			}
		}
		for k, og := range w.orgs {
			if d < og.day || og.variant == 2 {
				continue
			}
			ca, cb := w.fams[og.a].cur(d), w.fams[og.b].cur(d)
			va, vb := ca[0], cb[0]
			if og.variant == 1 {
				va, vb = ca[len(ca)-1], cb[len(cb)-1]
			}
			add(fmt.Sprintf("J%d_%d", d, k), w.fams[og.a].actors[0], []string{va, vb})
		}
		for k, br := range w.bridges {
			if d < br.start || d >= br.end {
				continue
			}
			ca, cb := w.fams[br.a].cur(d), w.fams[br.b].cur(d)
			if len(ca) == 0 || len(cb) == 0 {
				continue
			}
			switch br.kind {
			case 0, 1:
				actor := w.fams[br.a].actors[1]
				if br.kind == 1 {
					actor = fmt.Sprintf("zb%d", k)
				}
				vals := []string{ca[r.Intn(len(ca))], cb[r.Intn(len(cb))]}
				if br.cont != "" {
					for _, c := range ca {
						if c == br.cont {
							vals = append(vals, c)
						}
					}
				}
				if br.newEach {
					vals = append(vals, fmt.Sprintf("Pn%d_%d", k, d))
				}
				add(fmt.Sprintf("B%d_%d", k, d), actor, vals)
			case 2:
				add(fmt.Sprintf("X%d_%d_a", k, d), w.fams[br.a].actors[1], []string{ca[r.Intn(len(ca))], br.x})
				add(fmt.Sprintf("X%d_%d_b", k, d), w.fams[br.b].actors[1], []string{cb[r.Intn(len(cb))], br.x})
			}
		}
		for _, m := range w.mixed {
			for _, fi := range []int{m.p, m.q} {
				if c := w.fams[fi].cur(d); len(c) > 0 && r.Intn(2) == 0 {
					add(fmt.Sprintf("M%s_%d_%d", m.name, d, fi), m.name, []string{c[r.Intn(len(c))]})
				}
			}
		}
		w.daily[d] = day
	}
	return w
}

func (w *qWorld) window(d int) []Occurrence {
	var occ []Occurrence
	for b := max(0, d-w.R+1); b <= d; b++ {
		occ = append(occ, w.daily[b]...)
	}
	return occ
}

func (w *qWorld) bridgeActive(br *qBridge, d int) bool {
	if max(br.start, d-w.R+1) > min(br.end-1, d) {
		return false
	}
	return !(br.kind == 2 && br.ignoreDay >= 0 && d >= br.ignoreDay)
}

type qEdit struct {
	e                              Edit
	famLit, famInt, dstLit, dstInt int
	day                            int
}

type qUF []int

func (u qUF) find(x int) int {
	for u[x] != x {
		u[x] = u[u[x]]
		x = u[x]
	}
	return x
}
func (u qUF) union(a, b int) {
	if a < 0 || b < 0 {
		return
	}
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		u[max(ra, rb)] = min(ra, rb)
	}
}

type qResult struct {
	seed                               int64
	fails                              map[string]string
	amb                                int // trials with an ambiguous (aliased raw ID) edit
	ambLitOnly, ambIntOnly, ambNeither int
	orgCycles                          map[int]int // organic variant -> at-rest compared cycles
	orgChurn                           map[string]int
	log                                []string
}

func qShuffle(r *rand.Rand, occ []Occurrence, prev Output, edits []Edit) Input {
	sh := append([]Occurrence(nil), occ...)
	r.Shuffle(len(sh), func(a, b int) { sh[a], sh[b] = sh[b], sh[a] })
	as := append([]Assignment(nil), prev.Assignments...)
	r.Shuffle(len(as), func(a, b int) { as[a], as[b] = as[b], as[a] })
	ed := append([]Edit(nil), edits...)
	r.Shuffle(len(ed), func(a, b int) { ed[a], ed[b] = ed[b], ed[a] })
	return Input{Occurrences: sh, Assignments: as, Aliases: prev.Aliases, Edits: ed}
}

func qAliasCycle(al map[string]string) bool {
	for from := range al {
		seen := map[string]bool{}
		for id := from; ; {
			if seen[id] {
				return true
			}
			seen[id] = true
			next, ok := al[id]
			if !ok || next == id {
				break
			}
			id = next
		}
	}
	return false
}

func qRun(seed int64, mode string, verbose bool) *qResult {
	r := rand.New(rand.NewSource(seed))
	w := qBuild(r, mode)
	res := &qResult{seed: seed, fails: map[string]string{}, orgCycles: map[int]int{}, orgChurn: map[string]int{}}
	logf := func(f string, a ...any) {
		if verbose {
			res.log = append(res.log, fmt.Sprintf(f, a...))
		}
	}
	fail := func(cat, f string, a ...any) {
		if _, ok := res.fails[cat]; !ok {
			res.fails[cat] = fmt.Sprintf(f, a...)
		}
	}
	nf := len(w.fams)
	logf("T=%d R=%d fams=%d", w.T, w.R, nf)
	for i, f := range w.fams {
		logf("fam %d [%d,%d) const=%v turnover=%d vals=%v", i, f.start, f.end, f.constKey, f.turnover, f.vals)
	}
	for k, b := range w.bridges {
		logf("bridge %d %+v", k, *b)
	}
	for _, og := range w.orgs {
		logf("organic %+v", *og)
	}
	home := make([]string, nf)
	owner := map[string]int{}
	var edits []Edit
	var qe []qEdit
	removed := map[int]bool{}
	var prev Output
	var prevFamVals [][]string
	prevCamps := map[string]string{}
	eid := int64(1)
	planned := map[int]int{}
	for k := r.Intn(10); k > 0; k-- {
		planned[4+r.Intn(w.T-7)]++
	}
	if os.Getenv("SHARDLURE_CAMPAIGN_SIM_NO_EDITS") != "" {
		planned = map[int]int{}
		w.ignorePlan = map[int]int{}
	}
	forced := map[int]int{} // day -> family: a merge right after a remove
	orgLast := make([]string, len(w.orgs))
	ambig := false
	lastMergeDst := -1

	for d := 0; d < w.T; d++ {
		touched := map[int]bool{}
		// ---- operator edits, issued from the previous output ----
		displayID := func(f int) string {
			if prevFamVals == nil || len(prevFamVals[f]) == 0 {
				return ""
			}
			for _, c := range prev.Campaigns {
				for _, v := range c.Values {
					if v == prevFamVals[f][0] {
						return c.ID
					}
				}
			}
			return ""
		}
		pickID := func(f int) string {
			if r.Intn(2) == 0 {
				if id := displayID(f); id != "" {
					if _, ok := owner[id]; ok {
						return id
					}
				}
			}
			return home[f]
		}
		litFam := func(id string) int {
			if f, ok := owner[Resolve(prev.Aliases, id)]; ok {
				return f
			}
			return owner[id]
		}
		var alive []int
		for f := 0; f < nf && prevFamVals != nil; f++ {
			if home[f] != "" && len(prevFamVals[f]) > 0 {
				alive = append(alive, f)
			}
		}
		var bridged []int
		for _, br := range w.bridges {
			if w.bridgeActive(br, d-1) {
				bridged = append(bridged, br.a, br.b)
			}
		}
		if bi, ok := w.ignorePlan[d]; ok {
			br := w.bridges[bi]
			br.ignoreDay = d
			edits = append(edits, Edit{ID: eid, CampaignID: home[br.a], Action: "ignore_evidence", Arg: "script:" + br.x})
			logf("day %d edit %d ignore %s", d, eid, br.x)
			eid++
		}
		issue := func(kind int, forceSrc int) {
			if len(alive) < 2 {
				return
			}
			pick := func() int {
				if len(bridged) > 0 && r.Intn(2) == 0 {
					f := bridged[r.Intn(len(bridged))]
					if home[f] != "" && len(prevFamVals[f]) > 0 {
						return f
					}
				}
				return alive[r.Intn(len(alive))]
			}
			switch {
			case kind < 40:
				s := pick()
				if forceSrc >= 0 {
					s = forceSrc
				} else if lastMergeDst >= 0 && r.Intn(3) == 0 && len(prevFamVals[lastMergeDst]) > 0 {
					s = lastMergeDst // chained merge B -> C
				}
				t := pick()
				dstID := pickID(t)
				if r.Intn(2) == 0 { // merge into an ID that is only an automatic alias
					var cand []int
					for _, f := range alive {
						if a, ok := prev.Aliases[home[f]]; ok && a != "" {
							cand = append(cand, f)
						}
					}
					if len(cand) > 0 {
						t = cand[r.Intn(len(cand))]
						dstID = home[t]
					}
				}
				if s == t || home[s] == "" {
					return
				}
				srcID := pickID(s)
				q := qEdit{e: Edit{ID: eid, CampaignID: srcID, Action: "merge", Arg: dstID}, famLit: litFam(srcID), famInt: owner[srcID],
					dstLit: litFam(dstID), dstInt: owner[dstID], day: d}
				if q.famLit != q.famInt || q.dstLit != q.dstInt {
					ambig = true
				}
				qe = append(qe, q)
				edits = append(edits, q.e)
				lastMergeDst = t
				for _, f := range []int{q.famLit, q.famInt, q.dstLit, q.dstInt} {
					touched[f] = true
				}
				logf("day %d edit %d merge %s(fam lit %d int %d) into %s(fam lit %d int %d)", d, eid, srcID, q.famLit, q.famInt, dstID, q.dstLit, q.dstInt)
				eid++
			case kind < 65:
				f := pick()
				id := pickID(f)
				q := qEdit{e: Edit{ID: eid, CampaignID: id, Action: "rename", Arg: fmt.Sprintf("name%d", eid)}, famLit: litFam(id), famInt: owner[id], day: d}
				if q.famLit != q.famInt {
					ambig = true
				}
				qe = append(qe, q)
				edits = append(edits, q.e)
				touched[q.famLit], touched[q.famInt] = true, true
				logf("day %d edit %d rename %s (fam lit %d int %d)", d, eid, id, q.famLit, q.famInt)
				eid++
			default:
				f := pick()
				if removed[f] {
					return
				}
				removed[f] = true
				id := pickID(f)
				a := w.fams[f].actors[2+r.Intn(len(w.fams[f].actors)-2)]
				q := qEdit{e: Edit{ID: eid, CampaignID: id, Action: "remove_actor", Arg: a}, famLit: litFam(id), famInt: owner[id], day: d}
				qe = append(qe, q)
				edits = append(edits, q.e)
				logf("day %d edit %d remove %s from %s (fam %d)", d, eid, a, id, f)
				eid++
				if r.Intn(2) == 0 {
					forced[d+1+r.Intn(4)] = f
				}
			}
		}
		for k := planned[d]; k > 0; k-- {
			issue(r.Intn(100), -1)
		}
		if f, ok := forced[d]; ok && home[f] != "" && prevFamVals != nil && len(prevFamVals[f]) > 0 {
			issue(0, f)
		}
		editToday := len(edits) > 0 && (planned[d] > 0 || forced[d] != 0 || w.ignorePlan[d] != 0)
		if _, ok := forced[d]; ok {
			editToday = true
		}
		if _, ok := w.ignorePlan[d]; ok {
			editToday = true
		}

		// ---- regroup ----
		occ := w.window(d)
		out := groupT(qShuffle(r, occ, prev, edits))
		if again := groupT(qShuffle(r, occ, prev, edits)); !reflect.DeepEqual(out, again) {
			fail("shuffle", "day %d: output depends on input order", d)
		}
		if qAliasCycle(out.Aliases) {
			fail("alias-cycle", "day %d: %v", d, out.Aliases)
			res.log = append(res.log, "stopped at alias cycle")
			return res
		}
		if fp := groupT(Input{Occurrences: occ, Assignments: out.Assignments, Aliases: out.Aliases, Edits: edits}); !reflect.DeepEqual(fp, out) {
			fail("fixpoint", "day %d: re-running on own output changes it", d)
			if verbose {
				logf("FIXPOINT day %d\n out=%s al=%v\n fp =%s al=%v\n outA=%v\n fpA =%v\n edits=%v", d, qShow(out), out.Aliases, qShow(fp), fp.Aliases, out.Assignments, fp.Assignments, edits)
			}
		}
		byC := byID(out)
		for _, q := range qe {
			switch q.e.Action {
			case "merge":
				if Resolve(out.Aliases, q.e.CampaignID) != Resolve(out.Aliases, q.e.Arg) {
					fail("merge-alias", "day %d: edit %d %s->%s resolve apart", d, q.e.ID, q.e.CampaignID, q.e.Arg)
				}
			case "remove_actor":
				if c, ok := byC[Resolve(out.Aliases, q.e.CampaignID)]; ok && hasActor(c, q.e.Arg) {
					fail("removed-actor", "day %d: %s back in %s (edit %d on %s)", d, q.e.Arg, c.ID, q.e.ID, q.e.CampaignID)
				}
			}
		}
		// family values live this cycle
		famVals := make([][]string, nf)
		seenV := map[string]bool{}
		for _, x := range occ {
			if f, ok := w.valFam[x.Value]; ok && !seenV[x.Value] {
				seenV[x.Value] = true
				famVals[f] = append(famVals[f], x.Value)
			}
		}
		for f := range famVals {
			sort.Strings(famVals[f])
		}
		campOf := map[string]int{}
		for ci, c := range out.Campaigns {
			for _, v := range c.Values {
				campOf[v] = ci
			}
		}
		prevAssign := map[string]string{}
		for _, a := range prev.Assignments {
			prevAssign[a.Value] = a.CampaignID
		}
		bridgeTouch := map[int]bool{}
		for _, br := range w.bridges {
			if w.bridgeActive(br, d) {
				bridgeTouch[br.a], bridgeTouch[br.b] = true, true
			}
		}
		groups := func(m int, merges, bridges bool) qUF {
			u := make(qUF, nf)
			for i := range u {
				u[i] = i
			}
			if bridges {
				for _, br := range w.bridges {
					if w.bridgeActive(br, d) {
						u.union(br.a, br.b)
					}
				}
			}
			for _, og := range w.orgs {
				if d >= og.day {
					u.union(og.a, og.b)
				}
			}
			for _, q := range qe {
				if merges && q.e.Action == "merge" {
					if m == 0 {
						u.union(q.famLit, q.dstLit)
					} else {
						u.union(q.famInt, q.dstInt)
					}
				}
			}
			return u
		}
		check := func(m int) map[string]string {
			errs := map[string]string{}
			ef := func(cat, f string, a ...any) {
				if _, ok := errs[cat]; !ok {
					errs[cat] = fmt.Sprintf(f, a...)
				}
			}
			u := groups(m, true, true)
			nomerge := groups(m, false, true)
			for _, c := range out.Campaigns {
				rs := map[int]bool{}
				for _, v := range c.Values {
					if f, ok := w.valFam[v]; ok {
						rs[u.find(f)] = true
					}
				}
				if len(rs) > 1 {
					ef("fusion", "day %d: %s joins groups %v %v", d, c.ID, rs, c.Values)
				}
			}
			simAl := map[string]string{}
			for _, q := range qe {
				if q.e.Action != "merge" {
					continue
				}
				s, t := q.famLit, q.dstLit
				if m == 1 {
					s, t = q.famInt, q.dstInt
				}
				if s < 0 || t < 0 {
					continue
				}
				if a, b := Resolve(simAl, home[s]), Resolve(simAl, home[t]); a != b {
					simAl[a] = b
				}
			}
			names := map[int]string{} // group root -> latest rename
			for _, q := range qe {
				if q.e.Action == "rename" {
					f := q.famLit
					if m == 1 {
						f = q.famInt
					}
					names[u.find(f)] = q.e.Arg
				}
			}
			hasOrg := map[int]bool{}
			for _, og := range w.orgs {
				if d >= og.day {
					hasOrg[u.find(og.a)] = true
				}
			}
			byRoot := map[int][]int{}
			for f := 0; f < nf; f++ {
				if len(famVals[f]) > 0 {
					byRoot[u.find(f)] = append(byRoot[u.find(f)], f)
				}
			}
			for g, fs := range byRoot {
				cs := map[int]bool{}
				famCamp := map[int]int{}
				for _, f := range fs {
					for _, v := range famVals[f] {
						if ci, ok := campOf[v]; ok {
							cs[ci] = true
							famCamp[f] = ci
						}
					}
				}
				if len(cs) == 0 {
					ef("missing", "day %d: group %v not emitted", d, fs)
					continue
				}
				if len(cs) > 1 {
					cat := "fragment"
					for _, f1 := range fs {
						for _, f2 := range fs {
							if nomerge.find(f1) != nomerge.find(f2) && famCamp[f1] != famCamp[f2] {
								cat = "merge-lost"
							}
						}
					}
					var ids []string
					for ci := range cs {
						ids = append(ids, out.Campaigns[ci].ID)
					}
					ef(cat, "day %d: group %v split over %v", d, fs, ids)
					continue
				}
				var c Campaign
				for ci := range cs {
					c = out.Campaigns[ci]
				}
				rest := true
				for _, f := range fs {
					if bridgeTouch[f] {
						rest = false
					}
				}
				if !rest {
					continue
				}
				if want := names[g]; c.Name != want {
					ef("rename", "day %d: group %v campaign %s name %q want %q", d, fs, c.ID, c.Name, want)
				}
				if hasOrg[g] {
					continue
				}
				exp, ok := "", true
				for _, f := range fs {
					if home[f] == "" {
						continue
					}
					e := Resolve(simAl, home[f])
					if exp != "" && e != exp {
						ok = false
					}
					exp = e
				}
				if !ok || exp == "" || c.ID == exp {
					continue
				}
				homes := map[string]bool{exp: true}
				for _, f := range fs {
					homes[home[f]] = true
				}
				hard := false
				for _, f := range fs {
					for _, v := range famVals[f] {
						if homes[prevAssign[v]] {
							hard = true
						}
					}
				}
				cat := "id-lost-soft"
				if hard {
					cat = "id-lost-hard"
				}
				ef(cat, "day %d: group %v has %s want %s (owner %d)", d, fs, c.ID, exp, owner[c.ID])
			}
			return errs
		}
		e0, e1 := check(0), check(1)
		for cat, msg := range e0 {
			if _, both := e1[cat]; both {
				fail(cat, "%s", msg)
			}
		}
		if ambig {
			if len(e0) == 0 && len(e1) > 0 {
				res.ambLitOnly++
			} else if len(e1) == 0 && len(e0) > 0 {
				res.ambIntOnly++
			} else if len(e0) > 0 && len(e1) > 0 {
				res.ambNeither++
			}
		}
		// ID never changes while the evidence set is unchanged.
		curCamps := map[string]string{}
		for _, c := range out.Campaigns {
			if len(c.Values) == 0 {
				continue
			}
			k := strings.Join(c.Values, ",")
			curCamps[k] = c.ID
			if pid, ok := prevCamps[k]; ok && pid != c.ID && !editToday {
				fail("id-change-same-evidence", "day %d: %v was %s now %s", d, c.Values, pid, c.ID)
			}
		}
		// Organic permanent merges: ID stable while at rest.
		u := groups(0, true, true)
		for k, og := range w.orgs {
			if d < og.day {
				continue
			}
			ci, ok := campOf[famVals[og.a][0]]
			if !ok {
				continue
			}
			id := out.Campaigns[ci].ID
			g := u.find(og.a)
			rest, edited := true, editToday
			for _, og2 := range w.orgs {
				if og2.day == d && u.find(og2.a) == u.find(og.a) {
					edited = true
				}
			}
			for f := 0; f < nf; f++ {
				if u.find(f) == g && bridgeTouch[f] {
					rest = false
				}
			}
			switch {
			case d == og.day || edited:
				orgLast[k] = id
			case rest:
				if orgLast[k] != "" && id != orgLast[k] {
					anyAssigned := false
					for f := 0; f < nf; f++ {
						if u.find(f) == g {
							for _, v := range famVals[f] {
								if prevAssign[v] != "" {
									anyAssigned = true
								}
							}
						}
					}
					key := fmt.Sprintf("v%d const=%v/%v assignedLeft=%v", og.variant, w.fams[og.a].constKey, w.fams[og.b].constKey, anyAssigned)
					res.orgChurn[key]++
					fail("organic-churn", "day %d (merged day %d, R=%d): organic %d-%d variant %d id %s -> %s, group values had prior assignment: %v",
						d, og.day, w.R, og.a, og.b, og.variant, orgLast[k], id, anyAssigned)
				}
				res.orgCycles[og.variant]++
				orgLast[k] = id
			}
		}
		// Record home IDs for clean singleton families.
		gAll0, gAll1 := groups(0, true, true), groups(1, true, true)
		for f := 0; f < nf; f++ {
			if home[f] != "" || len(famVals[f]) == 0 || bridgeTouch[f] {
				continue
			}
			single := true
			for g := 0; g < nf; g++ {
				if g != f && (gAll0.find(g) == gAll0.find(f) || gAll1.find(g) == gAll1.find(f)) {
					single = false
				}
			}
			ci, ok := campOf[famVals[f][0]]
			if !single || !ok {
				continue
			}
			id := out.Campaigns[ci].ID
			if of, taken := owner[id]; taken && of != f {
				fail("home-collision", "day %d: fam %d emitted under %s, home of fam %d", d, f, id, of)
				continue
			}
			home[f], owner[id] = id, f
			logf("day %d home fam %d = %s", d, f, id)
		}
		if verbose {
			logf("day %d out: %s aliases=%v", d, qShow(out), out.Aliases)
		}
		_ = touched
		prev, prevFamVals, prevCamps = out, famVals, curCamps
	}
	if ambig {
		res.amb = 1
	}
	return res
}

func qShow(out Output) string {
	var b strings.Builder
	for _, c := range out.Campaigns {
		fmt.Fprintf(&b, "[%s %q %v %v] ", c.ID, c.Name, actorsOf(c), c.Values)
	}
	return b.String()
}

func TestCampaignWorldSimulation(t *testing.T) {
	trials, err := strconv.Atoi(os.Getenv("SHARDLURE_CAMPAIGN_SIM"))
	if err != nil || trials <= 0 {
		t.Skip("opt-in: set SHARDLURE_CAMPAIGN_SIM=<trials> to run the identity world simulation")
	}
	base := int64(0)
	if s := os.Getenv("SHARDLURE_CAMPAIGN_SIM_BASE"); s != "" {
		base, _ = strconv.ParseInt(s, 10, 64)
	}
	mode := os.Getenv("SHARDLURE_CAMPAIGN_SIM_MODE")
	if s := os.Getenv("SHARDLURE_CAMPAIGN_SIM_SEED"); s != "" {
		seed, _ := strconv.ParseInt(s, 10, 64)
		res := qRun(seed, mode, true)
		for _, l := range res.log {
			t.Log(l)
		}
		t.Logf("fails: %v", res.fails)
		return
	}
	results := make([]*qResult, trials)
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < runtime.GOMAXPROCS(0); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				results[i] = qRun(base+int64(i)+1, mode, false)
			}
		}()
	}
	for i := 0; i < trials; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
	cats := map[string][]int64{}
	amb, lit, intent, neither := 0, 0, 0, 0
	orgCycles := map[int]int{}
	orgChurn := map[string]int{}
	firstMsg := map[string][]string{}
	for _, res := range results {
		amb += res.amb
		if res.ambLitOnly > 0 {
			lit++
		}
		if res.ambIntOnly > 0 {
			intent++
		}
		if res.ambNeither > 0 {
			neither++
		}
		for k, v := range res.orgCycles {
			orgCycles[k] += v
		}
		for k, v := range res.orgChurn {
			orgChurn[k] += v
		}
		for cat, msg := range res.fails {
			cats[cat] = append(cats[cat], res.seed)
			if len(firstMsg[cat]) < 3 {
				firstMsg[cat] = append(firstMsg[cat], fmt.Sprintf("seed %d: %s", res.seed, msg))
			}
		}
	}
	var keys []string
	for k := range cats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Logf("trials=%d mode=%q", trials, mode)
	for _, k := range keys {
		t.Logf("%-26s %4d trials, e.g. %v", k, len(cats[k]), firstMsg[k])
	}
	// ambLitOnly counts a trial's days where the literal check passed and the
	// intent check failed, so it feeds the "failing only intent" figure (and
	// vice versa). lit, intent and neither count trials with at least one such
	// day, not days, so the summary says trials.
	t.Logf("ambiguous-edit trials=%d (trials failing only literal=%d, only intent=%d, both=%d)", amb, intent, lit, neither)
	t.Logf("organic at-rest compared cycles by variant: %v", orgCycles)
	t.Logf("organic churn events: %v", orgChurn)
}
