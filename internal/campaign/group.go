// Package campaign groups attacker sessions that are very likely one
// operator. Sessions are the nodes: an actor is a HASSH cluster and can hold
// several unrelated tools, so linking whole actors would let one mixed actor
// bridge unrelated campaigns. Only strong evidence links (see the worker's
// filters); HASSH, client version and download host never do.
package campaign

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

type Occurrence struct {
	Kind, Value, Label, Family string // Family: classifier family for payloads
	SessionID, ActorID, IP     string
	FirstSeen, LastSeen        time.Time
}

type Assignment struct {
	Kind, Value, CampaignID string
	Seq                     int64
}

type Edit struct {
	ID                      int64
	CampaignID, Action, Arg string
}

type Input struct {
	Occurrences []Occurrence
	Assignments []Assignment
	Aliases     map[string]string
	Edits       []Edit
}

type Reason struct {
	Kind, Value, Label string
	FirstSeen          time.Time
}

type Member struct {
	ActorID       string
	Sessions, IPs int
	Reasons       []Reason
}

type Campaign struct {
	ID, AnchorKind, AnchorValue, SuggestedName, Name, Notes string
	FirstSeen, LastSeen                                     time.Time
	Sessions, IPs                                           int
	Kinds, Values                                           []string
	Members                                                 []Member
}

type Output struct {
	Campaigns   []Campaign
	Assignments []Assignment
	Aliases     map[string]string
}

// OutlawKey is the Outlaw/Dota "mdrfckr" key as injected on production
// (673 times in 30 days). Names come from values an attacker cannot forge;
// the key comment is free text and never names anything.
const OutlawKey = "SHA256:MkYY9qiVsFGBC5WkjoClCkwEFW5iSjcGQF7m4n4H7Cw"

var (
	knownKeys     = map[string]string{OutlawKey: "Outlaw/Dota"}
	knownFamilies = map[string]string{"redtail": "RedTail"}
)

func CampaignID(kind, value string) string {
	sum := sha256.Sum256([]byte(kind + ":" + value))
	return "c-" + hex.EncodeToString(sum[:])[:12]
}

// Resolve follows aliases to the current ID, bounded against cycles.
func Resolve(aliases map[string]string, id string) string {
	for i := 0; i < 64; i++ {
		next, ok := aliases[id]
		if !ok || next == id {
			return id
		}
		id = next
	}
	return id
}

func vkey(kind, value string) string { return kind + "\x00" + value }

type unionFind map[string]string

func (u unionFind) find(x string) string {
	for u[x] != x {
		u[x] = u[u[x]]
		x = u[x]
	}
	return x
}

func (u unionFind) union(a, b string) {
	ra, rb := u.find(a), u.find(b)
	switch {
	case ra == rb:
	case ra < rb: // deterministic root
		u[rb] = ra
	default:
		u[ra] = rb
	}
}

type component struct {
	idx    []int
	minSeq int64 // -1 when no value was assigned before
	id     string
}

func Group(in Input) Output {
	aliases := map[string]string{}
	for k, v := range in.Aliases {
		aliases[k] = v
	}
	// Assignments are kept as recorded (raw): a value remembers the campaign
	// it first belonged to, so a bridge that later breaks can hand each piece
	// back its own identity instead of moving a name to foreign evidence.
	raw := map[string]Assignment{}
	var maxSeq int64
	for _, a := range in.Assignments {
		raw[vkey(a.Kind, a.Value)] = a
		maxSeq = max(maxSeq, a.Seq)
	}

	// Edits apply in the order they were recorded, whatever order the caller
	// passes them in (a later rename wins).
	edits := append([]Edit(nil), in.Edits...)
	sort.SliceStable(edits, func(i, j int) bool { return edits[i].ID < edits[j].ID })

	// Edits that act before union, keyed by resolved campaign ID.
	ignored, removed, edited, mergedFrom := map[string]bool{}, map[string]map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, e := range edits {
		id := Resolve(aliases, e.CampaignID)
		switch e.Action {
		case "ignore_evidence":
			if k, v, ok := strings.Cut(e.Arg, ":"); ok {
				ignored[vkey(k, v)] = true
			}
		case "remove_actor":
			if removed[id] == nil {
				removed[id] = map[string]bool{}
			}
			removed[id][e.Arg] = true
			edited[id] = true
		case "rename", "notes":
			edited[id] = true
		case "merge":
			edited[id] = true
			// Only the IDs merged *from* keep their retired identity: the
			// edit's own ID and what it resolved to before the merge. The
			// merge target is an ordinary campaign that can still split
			// (marking it made every automatic bridge into it permanent).
			mergedFrom[e.CampaignID] = true
			if src := mergeSource(aliases, e.CampaignID, e.Arg); src != "" {
				mergedFrom[src] = true
			}
		}
	}
	var all []Occurrence
	for _, x := range in.Occurrences {
		if x.SessionID == "" || x.ActorID == "" || ignored[vkey(x.Kind, x.Value)] {
			continue
		}
		all = append(all, x)
	}
	sort.Slice(all, func(i, j int) bool { return occLess(all[i], all[j]) })

	// remove_actor applies before union, and must hold every cycle. A
	// per-value filter ("drop the actor where the value is assigned to the
	// edited campaign") only held once: the split pieces fell below two
	// actors and lost their assignments, or a piece minted a new ID and its
	// values no longer named the edited campaign, and the actor bridged
	// again. So the rule is structural: union everything, and wherever a
	// component reaches the edited campaign (a value assigned to it or to an
	// ID aliased into it) drop the removed actor's occurrences from that
	// whole component, then union again. A piece split out of the edited
	// campaign stays connected to it through the removed actor's own
	// sessions, so the actor is kept out of that piece too, and so is any
	// new evidence it brings. Each pass only shrinks components, and a
	// shrunken piece reaches no campaign its parent did not, so the second
	// pass drops nothing.
	active := make([]bool, len(all))
	for i := range active {
		active[i] = true
	}
	resolved := map[string]string{}
	resolve := func(id string) string {
		r, ok := resolved[id]
		if !ok {
			r = Resolve(aliases, id)
			resolved[id] = r
		}
		return r
	}
	var dropped []Occurrence
	for len(removed) > 0 {
		roots, members := components(all, active)
		changed := false
		for _, r := range roots {
			var sets []map[string]bool
			hit := map[string]bool{}
			for _, i := range members[r] {
				a, ok := raw[vkey(all[i].Kind, all[i].Value)]
				if !ok {
					continue
				}
				for _, id := range [2]string{a.CampaignID, resolve(a.CampaignID)} {
					if set := removed[id]; set != nil && !hit[id] {
						hit[id] = true
						sets = append(sets, set)
					}
				}
			}
			for _, i := range members[r] {
				for _, set := range sets {
					if set[all[i].ActorID] {
						active[i], changed = false, true
						break
					}
				}
			}
		}
		if !changed {
			break
		}
	}
	var occ []Occurrence
	for i, x := range all {
		if active[i] {
			occ = append(occ, x)
		} else {
			dropped = append(dropped, x)
		}
	}

	// Union sessions sharing a value.
	roots, compIdx := components(occ, nil)
	comps := map[string]*component{}
	for _, r := range roots {
		comps[r] = &component{idx: compIdx[r], minSeq: -1}
	}
	// Per component: the raw IDs its values carry, each with its earliest seq.
	type claim struct {
		raw, target string
		seq         int64
		direct      bool // raw ID is not retired
		merged      bool // raw ID was explicitly merged from
		viaMerge    bool // raw ID was absorbed into an ID merged from
	}
	claims := map[string][]claim{}
	for _, r := range roots {
		c := comps[r]
		best := map[string]int64{}
		for _, i := range c.idx {
			a, ok := raw[vkey(occ[i].Kind, occ[i].Value)]
			if !ok {
				continue
			}
			if s, seen := best[a.CampaignID]; !seen || a.Seq < s {
				best[a.CampaignID] = a.Seq
			}
			if c.minSeq < 0 || a.Seq < c.minSeq {
				c.minSeq = a.Seq
			}
		}
		for id, seq := range best {
			t := Resolve(aliases, id)
			claims[r] = append(claims[r], claim{raw: id, target: t, seq: seq, direct: t == id,
				merged: mergedFrom[id], viaMerge: !mergedFrom[id] && chainHits(aliases, id, mergedFrom)})
		}
		// An explicit merge outranks every automatic ID: a component holding
		// merged-from evidence stays in the merge target's lineage. Ranking a
		// direct claim first let a transient bridge from P to an unrelated
		// campaign D hand P's piece D's ID, rewrite P's assignment to it, and
		// lose the merge (and D's identity) for good once the bridge broke.
		sort.Slice(claims[r], func(i, j int) bool {
			a, b := claims[r][i], claims[r][j]
			if a.merged != b.merged {
				return a.merged
			}
			if a.direct != b.direct {
				return a.direct
			}
			if edited[a.target] != edited[b.target] {
				return edited[a.target]
			}
			if a.seq != b.seq {
				return a.seq < b.seq
			}
			return a.raw < b.raw
		})
	}
	hasDirect := map[string]bool{}
	for _, r := range roots {
		for _, cl := range claims[r] {
			hasDirect[r] = hasDirect[r] || cl.direct
		}
	}
	// Components with a direct claim choose first, oldest first; components
	// that reach an ID only through an alias come after, so a broken bridge
	// never lets the formerly bridged-in piece take the name.
	sort.Slice(roots, func(i, j int) bool {
		a, b := roots[i], roots[j]
		if hasDirect[a] != hasDirect[b] {
			return hasDirect[a]
		}
		ca, cb := comps[a], comps[b]
		switch {
		case ca.minSeq >= 0 && cb.minSeq >= 0 && ca.minSeq != cb.minSeq:
			return ca.minSeq < cb.minSeq
		case (ca.minSeq >= 0) != (cb.minSeq >= 0):
			return ca.minSeq >= 0
		}
		return ca.idx[0] < cb.idx[0]
	})
	reserved := map[string]bool{}
	for _, a := range raw {
		reserved[a.CampaignID] = true
	}
	for k, v := range aliases {
		reserved[k], reserved[v] = true, true
	}
	for id := range edited {
		reserved[id] = true
	}
	taken := map[string]bool{}
	for _, r := range roots {
		c := comps[r]
		for _, cl := range claims[r] {
			switch {
			case cl.merged:
				// An explicit merge: keep the retired ID; output resolves it
				// into the merge target, so the merge persists every cycle.
				c.id = cl.raw
			case cl.viaMerge:
				// Absorbed into merged-from evidence by an automatic bridge
				// that has since broken: the operator merged that evidence,
				// not this, so revive this piece's own ID rather than take
				// the merge target's.
				if !taken[cl.raw] {
					c.id = cl.raw
					delete(aliases, cl.raw)
				}
			case !taken[cl.target]:
				c.id = cl.target
			case !cl.direct && !taken[cl.raw]:
				// A bridge broke: revive this piece's own former ID.
				c.id = cl.raw
				delete(aliases, cl.raw)
			}
			if c.id != "" {
				break
			}
		}
		if c.id == "" {
			anchor := occ[c.idx[0]]
			c.id = uniqueID(anchor.Kind, anchor.Value, taken, reserved, aliases)
		}
		taken[c.id] = true
		reserved[c.id] = true
	}
	// Other direct IDs a component absorbed (a new bridge) retire into it.
	for _, r := range roots {
		c := comps[r]
		for _, cl := range claims[r] {
			if cl.direct && cl.raw != c.id && !taken[cl.raw] {
				aliases[cl.raw] = c.id
			}
		}
	}
	// Explicit merges, in edit order.
	for _, e := range edits {
		if e.Action != "merge" {
			continue
		}
		if from, to := Resolve(aliases, e.CampaignID), Resolve(aliases, e.Arg); from != to {
			aliases[from] = to
		}
	}

	// Collect occurrences per final campaign ID.
	members := map[string][]int{}
	compOf := map[int]string{}
	for _, r := range roots {
		c := comps[r]
		id := Resolve(aliases, c.id)
		members[id] = append(members[id], c.idx...)
		for _, i := range c.idx {
			compOf[i] = c.id
		}
	}
	names, notes := map[string]string{}, map[string]string{}
	for _, e := range edits {
		id := Resolve(aliases, e.CampaignID)
		switch e.Action {
		case "rename":
			names[id] = e.Arg
		case "notes":
			notes[id] = e.Arg
		}
	}
	idSet := map[string]bool{}
	for id := range members {
		idSet[id] = true
	}
	for id := range names {
		idSet[id] = true
	}
	for id := range notes {
		idSet[id] = true
	}
	ids := make([]string, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := Output{Aliases: aliases}
	emitted := map[string]bool{}
	for _, id := range ids {
		c := Campaign{ID: id, Name: names[id], Notes: notes[id]}
		idx := members[id]
		sort.Ints(idx)
		if len(idx) > 0 {
			fillCampaign(&c, occ, idx)
		}
		if len(c.Members) < 2 && c.Name == "" && c.Notes == "" {
			continue
		}
		emitted[id] = true
		out.Campaigns = append(out.Campaigns, c)
	}
	// Assignments, in occurrence (time) order so fresh sequence numbers mean
	// "oldest first". A value keeps its recorded ID unless its component had
	// to take a different identity (a split that minted or revived an ID).
	newAssign := map[string]Assignment{}
	for i, x := range occ {
		compID, ok := compOf[i]
		if !ok || !emitted[Resolve(aliases, compID)] {
			continue
		}
		k := vkey(x.Kind, x.Value)
		if _, done := newAssign[k]; done {
			continue
		}
		prev, had := raw[k]
		switch {
		case had && mergedFrom[prev.CampaignID]:
			// Merged-from evidence is never rewritten to another campaign's
			// ID, so the merge resolves into its target again every cycle.
			newAssign[k] = prev
		case had && (prev.CampaignID == compID || Resolve(aliases, prev.CampaignID) == Resolve(aliases, compID)):
			newAssign[k] = prev
		case had:
			newAssign[k] = Assignment{Kind: x.Kind, Value: x.Value, CampaignID: compID, Seq: prev.Seq}
		default:
			maxSeq++
			newAssign[k] = Assignment{Kind: x.Kind, Value: x.Value, CampaignID: compID, Seq: maxSeq}
		}
	}
	// A value whose campaign carries an operator edit keeps its assignment
	// even when its piece is not a campaign this cycle (or its occurrence was
	// dropped by remove_actor). Dropping it forgot which campaign the value
	// belonged to, so the removed actor bridged again next cycle under a
	// freshly minted ID that the edit did not reach.
	for _, set := range [2][]Occurrence{occ, dropped} {
		for _, x := range set {
			k := vkey(x.Kind, x.Value)
			if _, done := newAssign[k]; done {
				continue
			}
			if prev, had := raw[k]; had && (edited[prev.CampaignID] || edited[Resolve(in.Aliases, prev.CampaignID)] || edited[Resolve(aliases, prev.CampaignID)]) {
				newAssign[k] = prev
			}
		}
	}
	keys := make([]string, 0, len(newAssign))
	for k := range newAssign {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.Assignments = append(out.Assignments, newAssign[k])
	}
	return out
}

// occLess is a total order on occurrences (time first), so which duplicate
// supplies a label, family or suggested name never depends on input order.
func occLess(a, b Occurrence) bool {
	if !a.FirstSeen.Equal(b.FirstSeen) {
		return a.FirstSeen.Before(b.FirstSeen)
	}
	for _, p := range [...][2]string{{a.Kind, b.Kind}, {a.Value, b.Value}, {a.SessionID, b.SessionID}, {a.ActorID, b.ActorID},
		{a.Label, b.Label}, {a.Family, b.Family}, {a.IP, b.IP}} {
		if p[0] != p[1] {
			return p[0] < p[1]
		}
	}
	return a.LastSeen.Before(b.LastSeen)
}

// components unions sessions that share a value among the occurrences
// marked active (all when active is nil). It returns the component roots in
// order of first occurrence and each root's occurrence indexes, ascending.
func components(occ []Occurrence, active []bool) ([]string, map[string][]int) {
	u := unionFind{}
	firstOf := map[string]int{}
	for i, x := range occ {
		if active != nil && !active[i] {
			continue
		}
		if _, ok := u[x.SessionID]; !ok {
			u[x.SessionID] = x.SessionID
		}
		k := vkey(x.Kind, x.Value)
		if f, ok := firstOf[k]; ok {
			u.union(occ[f].SessionID, x.SessionID)
		} else {
			firstOf[k] = i
		}
	}
	members := map[string][]int{}
	var roots []string
	for i, x := range occ {
		if active != nil && !active[i] {
			continue
		}
		r := u.find(x.SessionID)
		if _, ok := members[r]; !ok {
			roots = append(roots, r)
		}
		members[r] = append(members[r], i)
	}
	return roots, members
}

// mergeSource is the ID a merge of from into to retired: the last ID on
// from's alias chain before it joins to's chain. On the merge's first cycle
// that is Resolve(from); later the merge alias itself is on the chain, and
// resolving would wrongly name the target. "" when from already resolves
// into to (nothing was merged).
func mergeSource(aliases map[string]string, from, to string) string {
	onTarget := map[string]bool{}
	for i, id := 0, to; i < 64; i++ {
		onTarget[id] = true
		next, ok := aliases[id]
		if !ok || next == id {
			break
		}
		id = next
	}
	prev := ""
	for i, id := 0, from; i < 64 && !onTarget[id]; i++ {
		prev = id
		next, ok := aliases[id]
		if !ok || next == id {
			break
		}
		id = next
	}
	return prev
}

// chainHits reports whether id's alias chain, past id itself, passes
// through an ID in set.
func chainHits(aliases map[string]string, id string, set map[string]bool) bool {
	for i := 0; i < 64; i++ {
		next, ok := aliases[id]
		if !ok || next == id {
			return false
		}
		if set[next] {
			return true
		}
		id = next
	}
	return false
}

// uniqueID mints an ID from the anchor value, never reusing an ID that is
// taken this pass, held by a stored assignment or edit, or retired.
func uniqueID(kind, value string, taken, reserved map[string]bool, aliases map[string]string) string {
	id := CampaignID(kind, value)
	for n := 1; taken[id] || reserved[id] || aliases[id] != ""; n++ {
		id = CampaignID(kind, fmt.Sprintf("%s#%d", value, n))
	}
	return id
}

// fillCampaign aggregates a campaign from its occurrences (idx sorted, so
// idx[0] is the oldest occurrence and the anchor).
func fillCampaign(c *Campaign, occ []Occurrence, idx []int) {
	type memberAgg struct {
		sessions, ips map[string]bool
		reasons       map[string]Reason
	}
	agg := map[string]*memberAgg{}
	sessions, ips, kinds, values := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for n, i := range idx {
		x := occ[i]
		if n == 0 {
			c.AnchorKind, c.AnchorValue = x.Kind, x.Value
		}
		if c.FirstSeen.IsZero() || x.FirstSeen.Before(c.FirstSeen) {
			c.FirstSeen = x.FirstSeen
		}
		if x.LastSeen.After(c.LastSeen) {
			c.LastSeen = x.LastSeen
		}
		sessions[x.SessionID], ips[x.IP], kinds[x.Kind], values[x.Value] = true, true, true, true
		m := agg[x.ActorID]
		if m == nil {
			m = &memberAgg{sessions: map[string]bool{}, ips: map[string]bool{}, reasons: map[string]Reason{}}
			agg[x.ActorID] = m
		}
		m.sessions[x.SessionID], m.ips[x.IP] = true, true
		k := vkey(x.Kind, x.Value)
		if r, ok := m.reasons[k]; !ok || x.FirstSeen.Before(r.FirstSeen) {
			m.reasons[k] = Reason{Kind: x.Kind, Value: x.Value, Label: x.Label, FirstSeen: x.FirstSeen}
		}
		if name := knownKeys[x.Value]; x.Kind == "ssh_key" && name != "" && c.SuggestedName == "" {
			c.SuggestedName = name
		}
		if name := knownFamilies[x.Family]; x.Kind == "payload" && name != "" && c.SuggestedName == "" {
			c.SuggestedName = name
		}
	}
	c.Sessions, c.IPs = len(sessions), len(ips)
	c.Kinds, c.Values = sortedKeys(kinds), sortedKeys(values)
	for _, a := range sortedKeys(func() map[string]bool {
		m := map[string]bool{}
		for k := range agg {
			m[k] = true
		}
		return m
	}()) {
		m := agg[a]
		mem := Member{ActorID: a, Sessions: len(m.sessions), IPs: len(m.ips)}
		for _, r := range m.reasons {
			mem.Reasons = append(mem.Reasons, r)
		}
		sort.Slice(mem.Reasons, func(i, j int) bool {
			x, y := mem.Reasons[i], mem.Reasons[j]
			if !x.FirstSeen.Equal(y.FirstSeen) {
				return x.FirstSeen.Before(y.FirstSeen)
			}
			if x.Kind != y.Kind {
				return x.Kind < y.Kind
			}
			return x.Value < y.Value
		})
		c.Members = append(c.Members, mem)
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
