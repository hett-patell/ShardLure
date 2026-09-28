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

// lineage is one campaign identity as this cycle sees it: an ID that no
// explicit merge retires (a merge rep), the component owning it, and the
// earliest-assigned value that grants ownership.
type lineage struct {
	root string
	seq  int64
	key  string
}

// component is one set of linked sessions after remove_actor and merge
// closure: its occurrence indexes (ascending), the lineages it owns and the
// campaign ID it ends up with.
type component struct {
	idx    []int
	owned  []string
	minSeq map[string]int64
	id     string
}

// Group derives campaigns from linking evidence. Its identity rules, each
// pinned by a test, are:
//
//  1. Lineage. Every assigned value names a lineage: its recorded ID resolved
//     through explicit merge aliases only. Automatic (bridge) aliases never
//     change what a value stands for.
//  2. Edits resolve by intent. An edit names the lineage whose ID it carries,
//     resolved through the merge edits before it; an automatic alias current
//     when the edit was issued does not widen it to the other side of a
//     bridge. A campaign shows the latest rename and notes issued on any
//     lineage it holds.
//  3. Merges are permanent. Every piece with pure evidence of a merged
//     lineage (a session holding only that lineage) is one campaign with the
//     lineage's owner, every cycle, so a merge outlives the evidence that was
//     live when it was made. Only a remove_actor that severed two pieces of
//     one former component keeps them apart, and a lone value of the
//     lineage inside a piece that belongs elsewhere is a bridge value, not a
//     claim.
//  4. Ownership. A lineage belongs to the component holding its
//     earliest-assigned value (the spec's split rule); a component with no
//     owned lineage mints. A component's ID is its owned lineage carrying an
//     operator edit, else the one that already carried the ID (a lineage that
//     deferred to a co-owned lineage last cycle defers again), else the
//     earliest assigned. The other owned lineages become automatic aliases,
//     rebuilt every cycle as a forest whose roots attach to the winner, so a
//     broken bridge needs no revival step and cannot leave a cycle behind.
//  5. Attribution. A value its component does not own is attributed to the
//     lineage it was seen with, per value and never transitively: the pure
//     sessions of actors that bridge nothing, and the lineages carried by
//     the actors of its sessions. One lineage across both stamps it; more
//     than one is decided by how many distinct actors carry each, and a tie
//     leaves it unassigned this cycle rather than stamped with a winner it
//     may not belong to.
//  6. remove_actor holds every cycle on the lineage it names: the actor is
//     dropped, before union, from every component that owns that lineage.
func Group(in Input) Output {
	raw := map[string]Assignment{}
	var maxSeq int64
	for _, a := range in.Assignments {
		raw[vkey(a.Kind, a.Value)] = a
		maxSeq = max(maxSeq, a.Seq)
	}
	edits := append([]Edit(nil), in.Edits...)
	sort.SliceStable(edits, func(i, j int) bool { return edits[i].ID < edits[j].ID })

	// Merge aliases come from the edits alone, in edit order, resolving each
	// side through the merges before it. A stored automatic alias never takes
	// part: "merge T into D" while D is bridged into K merges T with D, not
	// with K (an operator who wanted K would have named K).
	mergeAlias := map[string]string{}
	for _, e := range edits {
		if e.Action != "merge" || e.CampaignID == "" || e.Arg == "" {
			continue
		}
		if from, to := Resolve(mergeAlias, e.CampaignID), Resolve(mergeAlias, e.Arg); from != to {
			mergeAlias[from] = to
		}
	}
	repCache := map[string]string{}
	rep := func(id string) string {
		r, ok := repCache[id]
		if !ok {
			r = Resolve(mergeAlias, id)
			repCache[id] = r
		}
		return r
	}
	inGroup := map[string]bool{} // reps that some merge retired an ID into
	for from := range mergeAlias {
		inGroup[rep(from)] = true
	}

	ignored, removed, edited := map[string]bool{}, map[string]map[string]bool{}, map[string]bool{}
	names, notes := map[string]string{}, map[string]string{}
	nameID, noteID := map[string]int64{}, map[string]int64{}
	for _, e := range edits {
		id := rep(e.CampaignID)
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
		case "rename":
			names[id], nameID[id], edited[id] = e.Arg, e.ID, true
		case "notes":
			notes[id], noteID[id], edited[id] = e.Arg, e.ID, true
		case "merge":
			edited[id] = true
		}
	}
	lineageOf := func(x Occurrence) (string, Assignment, bool) {
		a, ok := raw[vkey(x.Kind, x.Value)]
		if !ok {
			return "", a, false
		}
		return rep(a.CampaignID), a, true
	}

	var all []Occurrence
	for _, x := range in.Occurrences {
		if x.SessionID == "" || x.ActorID == "" || ignored[vkey(x.Kind, x.Value)] {
			continue
		}
		all = append(all, x)
	}
	sort.Slice(all, func(i, j int) bool { return occLess(all[i], all[j]) })

	// parents: the session-only components before remove_actor. Two pieces
	// of one parent that end up apart were severed by a removal, so merge
	// closure (rule 3) must not join them again.
	parents := sessionUnion(all, nil)
	parentOf := func(i int) string { return parents.find(all[i].SessionID) }

	// remove_actor applies before union and must hold every cycle (rule 6).
	// It is structural: wherever a component reaches a removed-from lineage
	// (a value assigned to it), the removed actors' occurrences leave that
	// whole component, then union runs again. A piece split out of the
	// lineage stays connected to it through the actor's own sessions in this
	// pre-removal view, so the actor is kept out of that piece too, and so is
	// any new evidence it brings. Each pass only shrinks components.
	active := make([]bool, len(all))
	for i := range active {
		active[i] = true
	}
	for len(removed) > 0 {
		roots, members := unite(all, active, parentOf, lineageOf, inGroup)
		// A component reaches a lineage when it owns it (holds its
		// earliest-assigned value), not merely when it holds some value of it:
		// a stray value another piece owns is re-attributed this cycle, and
		// counting it would drop the actor now and let it back on the next
		// run over the very same input.
		reach := map[string]lineage{}
		for _, r := range roots {
			for _, i := range members[r] {
				l, a, ok := lineageOf(all[i])
				if !ok || removed[l] == nil {
					continue
				}
				k := vkey(all[i].Kind, all[i].Value)
				if cur, ok := reach[l]; !ok || a.Seq < cur.seq || a.Seq == cur.seq && k < cur.key {
					reach[l] = lineage{root: r, seq: a.Seq, key: k}
				}
			}
		}
		changed := false
		for _, r := range roots {
			var sets []map[string]bool
			for l, h := range reach {
				if h.root == r {
					sets = append(sets, removed[l])
				}
			}
			for _, i := range members[r] {
				for _, set := range sets {
					if active[i] && set[all[i].ActorID] {
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
	var occ, dropped []Occurrence
	occIdx := make([]int, 0, len(all)) // occ position -> all position
	for i, x := range all {
		if active[i] {
			occ = append(occ, x)
			occIdx = append(occIdx, i)
		} else {
			dropped = append(dropped, x)
		}
	}
	roots, members := unite(all, active, parentOf, lineageOf, inGroup)
	comps := map[string]*component{}
	for _, r := range roots {
		c := &component{minSeq: map[string]int64{}}
		for _, i := range members[r] {
			c.idx = append(c.idx, sort.SearchInts(occIdx, i))
		}
		comps[r] = c
	}
	// Ownership (rule 4): a lineage belongs to the component holding its
	// earliest-assigned value. Ranking whole components by their oldest value
	// let an older campaign briefly bridged to K walk off with K's ID.
	owner := map[string]lineage{}
	for _, r := range roots {
		c := comps[r]
		for _, i := range c.idx {
			l, a, ok := lineageOf(occ[i])
			if !ok {
				continue
			}
			if s, seen := c.minSeq[l]; !seen || a.Seq < s {
				c.minSeq[l] = a.Seq
			}
			k := vkey(occ[i].Kind, occ[i].Value)
			if cur, ok := owner[l]; !ok || a.Seq < cur.seq || a.Seq == cur.seq && k < cur.key {
				owner[l] = lineage{root: r, seq: a.Seq, key: k}
			}
		}
	}
	for _, r := range roots {
		c := comps[r]
		for l := range c.minSeq {
			if owner[l].root == r {
				c.owned = append(c.owned, l)
			}
		}
		// The spec's order: IDs carrying operator edits, then the earliest
		// assigned. Between those, a lineage that was already aliased into
		// another lineage of this component last cycle defers to it: the ID
		// two permanently linked campaigns show must not flip the day the
		// winner's oldest value ages out and the other side's turns out older.
		isOwned := map[string]bool{}
		for _, l := range c.owned {
			isOwned[l] = true
		}
		defers := func(l string) bool {
			for i, t := 0, l; i < 64; i++ {
				next, ok := in.Aliases[t]
				if !ok || next == t {
					return false
				}
				if isOwned[next] || isOwned[rep(next)] {
					return true
				}
				t = next
			}
			return false
		}
		sort.Slice(c.owned, func(i, j int) bool {
			a, b := c.owned[i], c.owned[j]
			if edited[a] != edited[b] {
				return edited[a]
			}
			if da, db := defers(a), defers(b); da != db {
				return db
			}
			if c.minSeq[a] != c.minSeq[b] {
				return c.minSeq[a] < c.minSeq[b]
			}
			return a < b
		})
	}
	reserved := map[string]bool{}
	for _, a := range raw {
		reserved[a.CampaignID] = true
	}
	for k, v := range in.Aliases {
		reserved[k], reserved[v] = true, true
	}
	for _, e := range edits {
		reserved[e.CampaignID] = true
		if e.Action == "merge" {
			reserved[e.Arg] = true
		}
	}
	for from, to := range mergeAlias {
		reserved[from], reserved[to] = true, true
	}
	// Aliases are rebuilt every cycle: the merge aliases, plus an automatic
	// alias for every owned lineage that did not become its component's ID.
	// An alias from an earlier bridge is simply not written again once the
	// pieces are apart, so a revival needs no bookkeeping and cannot leave a
	// cycle behind.
	aliases := map[string]string{}
	for from, to := range mergeAlias {
		aliases[from] = to
	}
	taken := map[string]bool{}
	for _, r := range roots {
		c := comps[r]
		if len(c.owned) > 0 {
			c.id = c.owned[0]
		} else {
			anchor := occ[c.idx[0]]
			c.id = uniqueID(anchor.Kind, anchor.Value, taken, reserved, aliases)
		}
		taken[c.id] = true
		// The alias forest inside a component is kept, not flattened: a
		// lineage that deferred to another co-owned lineage last cycle keeps
		// pointing at it, and only the former roots attach to the winner. A
		// transient bridge therefore does not erase which of two permanently
		// linked campaigns carried the ID; when the bridge ends the old root
		// is the only non-deferring lineage and takes the ID back.
		isOwned := map[string]bool{}
		for _, l := range c.owned {
			isOwned[l] = true
		}
		for _, l := range c.owned[min(1, len(c.owned)):] {
			aliases[l] = c.id
			if t, ok := in.Aliases[l]; ok {
				if t = rep(t); t != l && isOwned[t] && t != c.id {
					aliases[l] = t
				}
			}
		}
		for _, l := range c.owned[min(1, len(c.owned)):] {
			t, i := l, 0
			for ; i < len(c.owned) && t != c.id; i++ {
				t = aliases[t]
			}
			if t != c.id {
				aliases[l] = c.id // a stale chain that never reaches the winner
			}
		}
	}

	// Campaigns: one per component (its ID is never shared, so no two
	// components resolve to one ID), plus an empty one for every edited
	// lineage that no component owns, so a named campaign persists with no
	// active members.
	byRoot := map[string]string{}
	idSet := map[string]bool{}
	for _, r := range roots {
		byRoot[comps[r].id] = r
		idSet[comps[r].id] = true
	}
	for id := range names {
		if _, owned := owner[id]; !owned {
			idSet[id] = true
		}
	}
	for id := range notes {
		if _, owned := owner[id]; !owned {
			idSet[id] = true
		}
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
		if r, ok := byRoot[id]; ok {
			// A campaign shows the latest rename and notes issued on any
			// lineage it holds, not only on the one whose ID it carries: the
			// operator renamed the campaign they were looking at, and while
			// two lineages are one campaign that is this one. When they part,
			// each lineage takes its own edits with it.
			c.Name, c.Notes = latestEdit(names, nameID, comps[r].owned), latestEdit(notes, noteID, comps[r].owned)
			fillCampaign(&c, occ, comps[r].idx)
		}
		if len(c.Members) < 2 && c.Name == "" && c.Notes == "" {
			continue
		}
		emitted[id] = true
		out.Campaigns = append(out.Campaigns, c)
	}

	// Attribution (rule 5). A value whose lineage this component owns is
	// stable and keeps its assignment as recorded. Every other value in an
	// emitted component (new, or carried in from a lineage another piece
	// owns) is attributed to the lineage it was seen with.
	stamp := map[string]string{}
	stable := map[string]bool{}
	sessOcc := map[string][]int{}
	for i, x := range occ {
		sessOcc[x.SessionID] = append(sessOcc[x.SessionID], i)
	}
	for _, r := range roots {
		c := comps[r]
		if !emitted[c.id] {
			for _, i := range c.idx {
				if l, _, ok := lineageOf(occ[i]); ok && owner[l].root == r {
					stable[vkey(occ[i].Kind, occ[i].Value)] = true
				}
			}
			continue
		}
		attribute(occ, sessOcc, c, r, owner, lineageOf, rep, stable, stamp)
	}
	// Assignments, in occurrence (time) order so fresh sequence numbers mean
	// "oldest first". A value the removed actor alone carried keeps what it
	// had: forgetting it is how a removed actor bridged again under an ID the
	// edit did not reach.
	newAssign := map[string]Assignment{}
	for _, x := range occ {
		k := vkey(x.Kind, x.Value)
		if _, done := newAssign[k]; done {
			continue
		}
		switch id, stamped := stamp[k]; {
		case stable[k]:
			newAssign[k] = raw[k]
		case stamped:
			maxSeq++
			newAssign[k] = Assignment{Kind: x.Kind, Value: x.Value, CampaignID: id, Seq: maxSeq}
		}
	}
	present := map[string]bool{}
	for _, x := range occ {
		present[vkey(x.Kind, x.Value)] = true
	}
	for _, x := range dropped {
		k := vkey(x.Kind, x.Value)
		if prev, had := raw[k]; had && !present[k] {
			newAssign[k] = prev
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

// attribute decides the lineage of every value component c does not own
// (rule 5), writing the result into stamp and marking owned values stable.
//
// A component owning one lineage is that lineage: everything floating in it
// is stamped with the campaign ID. A component owning several (a bridge, an
// organic merge, or an explicit merge bridged to a third campaign) is read
// per value, never transitively: grouping floating values that share a
// session let one bridge-born value make a whole family ambiguous, and once
// its own evidence had aged out that family was stamped with the other side.
//
// Evidence is taken in two tiers. Sessions of a bridge actor (an actor whose
// sessions in this component carry stable values of two lineages: a
// third-party bridging tool, or the family member whose session joined the
// two sides) decide nothing: such a session looks pure exactly when the value
// it picked from one side is still floating, which is when it must not be
// believed.
//
//  1. Pure sessions: every session of a non-bridge actor whose stable values
//     all belong to one lineage. One lineage across them stamps the value;
//     two leave it unassigned (it is a bridge value).
//  2. Actor continuity: the lineage of the value's own non-bridge actors,
//     when they all carry one. This is what carries a family whose linking
//     sessions are mixed (an organic merge) or whose newest values were
//     picked by a bridge before anything stable co-occurred with them.
//
// A value with no evidence at all stays unassigned this cycle; stamping it
// with the campaign's own ID was how a transient third party's identity
// spread to values born inside a permanent merge. Rounds repeat while a tier
// stamps something, every floating value is read again each round, and
// stamps within a round apply together, so neither value order nor a
// conflict released by a later stamp can change the result.
func attribute(occ []Occurrence, sessOcc map[string][]int, c *component, root string, owner map[string]lineage,
	lineageOf func(Occurrence) (string, Assignment, bool), rep func(string) string, stable map[string]bool, stamp map[string]string) {
	lin, rawLin := map[string]string{}, map[string]string{} // value -> lineage, recorded ID
	valOcc := map[string][]int{}
	var floating, sessions []string
	seenS := map[string]bool{}
	for _, i := range c.idx {
		x := occ[i]
		if !seenS[x.SessionID] {
			seenS[x.SessionID] = true
			sessions = append(sessions, x.SessionID)
		}
		k := vkey(x.Kind, x.Value)
		if _, seen := valOcc[k]; !seen {
			if l, a, ok := lineageOf(x); ok && owner[l].root == root {
				lin[k], rawLin[k] = l, a.CampaignID
				stable[k] = true
			} else {
				floating = append(floating, k)
			}
		}
		valOcc[k] = append(valOcc[k], i)
	}
	if len(floating) == 0 {
		return
	}
	if len(c.owned) <= 1 {
		for _, k := range floating {
			stamp[k] = c.id
		}
		return
	}
	// Rounds: every floating value is read again each round against the
	// stable set as it stands, so a value blocked by a conflict is released
	// in the same cycle when a later stamp turns one of its sessions mixed.
	// Anything still floating at the end stays unassigned this cycle.
	for round := 0; round < 32 && len(floating) > 0; round++ {
		sessReps, actorReps := map[string]map[string]bool{}, map[string]map[string]bool{}
		actorRaw := map[string]map[string]bool{} // actor -> recorded IDs of its stable values
		for _, s := range sessions {
			for _, i := range sessOcc[s] {
				k := vkey(occ[i].Kind, occ[i].Value)
				l, ok := lin[k]
				if !ok {
					continue
				}
				if sessReps[s] == nil {
					sessReps[s] = map[string]bool{}
				}
				sessReps[s][l] = true
				a := occ[i].ActorID
				if actorReps[a] == nil {
					actorReps[a], actorRaw[a] = map[string]bool{}, map[string]bool{}
				}
				actorReps[a][l] = true
				actorRaw[a][rawLin[k]] = true
			}
		}
		newStamp := map[string]string{}
		var rest []string
		for _, k := range floating {
			pure, cont := map[string]bool{}, map[string]bool{}
			// votes: lineage -> recorded ID -> non-bridge actors of k's sessions
			// carrying it, for breaking a tier-1 conflict.
			votes := map[string]map[string]map[string]bool{}
			seenActor := map[string]bool{}
			for _, i := range valOcc[k] {
				x := occ[i]
				ar := actorReps[x.ActorID]
				if len(ar) < 2 {
					// Only a non-bridge actor's session is pure evidence.
					for l := range sessReps[x.SessionID] {
						pure[l] = true
					}
				}
				// Every actor votes with every lineage it carries: a bridge
				// actor is neutral between its two sides, but still outweighs
				// a third party against both of them.
				for l := range ar {
					cont[l] = true
				}
				if seenActor[x.ActorID] {
					continue
				}
				seenActor[x.ActorID] = true
				for raw := range actorRaw[x.ActorID] {
					l := rep(raw)
					if votes[l] == nil {
						votes[l] = map[string]map[string]bool{}
					}
					if votes[l][raw] == nil {
						votes[l][raw] = map[string]bool{}
					}
					votes[l][raw][x.ActorID] = true
				}
			}
			// Pure sessions and actor continuity are read together: one
			// lineage across both stamps the value; two or more is a conflict,
			// even when only one pure session exists. A lone pure session is
			// exactly what an unflagged bridging tool produces on the day it
			// picks a newborn, and the family's own actors, who carry the
			// other lineage, are the evidence against it.
			cands := map[string]bool{}
			for l := range pure {
				cands[l] = true
			}
			for l := range cont {
				cands[l] = true
			}
			var pick string
			switch {
			case len(cands) == 1:
				for l := range cands {
					pick = l
				}
			case len(cands) > 1:
				pick = actorMajority(votes)
			}
			if pick != "" {
				newStamp[k] = pick
			} else {
				rest = append(rest, k)
			}
		}
		for k, l := range newStamp {
			lin[k], rawLin[k], stamp[k] = l, l, l
		}
		floating = rest
		if len(newStamp) == 0 {
			break
		}
	}
}

// actorMajority breaks a tier-1 conflict by actor continuity: the lineage
// carried by strictly more of the distinct non-bridge actors that used the
// value wins, or "" on a tie. Two pure sessions naming different lineages are
// symmetric as co-occurrence ({v, a-value} and {v, b-value}) but not as
// actors: a family's actors all carry its lineage, in sessions with the value
// and in their other sessions, while a third-party tool that bridges two
// families is one actor, and it is exactly that actor whose sessions look
// pure while the value it picked from one side is still floating. Without
// this a family that lives on one stable value at a time is captured by its
// bridge partner the day that value ages out. Actors are counted per recorded
// ID and a lineage scores its best ID, not the sum: an explicit merge joins
// operators the evidence never showed together, and their pooled actor count
// says nothing about which side a value belongs to.
func actorMajority(pure map[string]map[string]map[string]bool) string {
	best, pick, tie := -1, "", false
	for _, l := range sortedKeys(func() map[string]bool {
		m := map[string]bool{}
		for l := range pure {
			m[l] = true
		}
		return m
	}()) {
		n := 0
		for _, actors := range pure[l] {
			n = max(n, len(actors))
		}
		switch {
		case n > best:
			best, pick, tie = n, l, false
		case n == best:
			tie = true
		}
	}
	if tie {
		return ""
	}
	return pick
}

// latestEdit returns the value of the most recent edit (by edit ID) recorded
// for any of the given lineages, or "" when none carries one.
func latestEdit(values map[string]string, ids map[string]int64, lineages []string) string {
	best, out := int64(-1), ""
	for _, l := range lineages {
		if id, ok := ids[l]; ok && id > best {
			best, out = id, values[l]
		}
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

// sessionUnion unions sessions that share a value among the occurrences
// marked active (all when active is nil).
func sessionUnion(occ []Occurrence, active []bool) unionFind {
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
	return u
}

// unite builds the components: sessions sharing a value, closed over
// explicit merges (rule 3). For every lineage some merge retired an ID into,
// the pieces holding its values are joined, one piece per pre-removal
// parent: the piece with the lineage's earliest value there. Two pieces of
// one parent were severed by remove_actor, and the merge must not undo that.
// It returns the roots in order of first occurrence and each root's
// occurrence indexes, ascending.
func unite(all []Occurrence, active []bool, parentOf func(int) string,
	lineageOf func(Occurrence) (string, Assignment, bool), inGroup map[string]bool) ([]string, map[string][]int) {
	u := sessionUnion(all, active)
	// Per recorded ID of a merged lineage: the piece holding its earliest
	// value (its owner) and that piece's parent.
	type best struct {
		seq            int64
		key, sess, par string
	}
	owners := map[string]best{}
	for i, x := range all {
		if active != nil && !active[i] {
			continue
		}
		l, a, ok := lineageOf(x)
		if !ok || !inGroup[l] {
			continue
		}
		k := vkey(x.Kind, x.Value)
		if cur, ok := owners[a.CampaignID]; !ok || a.Seq < cur.seq || a.Seq == cur.seq && k < cur.key {
			owners[a.CampaignID] = best{a.Seq, k, x.SessionID, parentOf(i)}
		}
	}
	// pure: piece -> lineages for which the piece has a session whose
	// assigned values all belong to that lineage.
	pure := map[string]map[string]bool{}
	sessLin := map[string]map[string]bool{}
	for i, x := range all {
		if active != nil && !active[i] {
			continue
		}
		if l, _, ok := lineageOf(x); ok {
			if sessLin[x.SessionID] == nil {
				sessLin[x.SessionID] = map[string]bool{}
			}
			sessLin[x.SessionID][l] = true
		}
	}
	for s, ls := range sessLin {
		if len(ls) != 1 {
			continue
		}
		r := u.find(s)
		if pure[r] == nil {
			pure[r] = map[string]bool{}
		}
		for l := range ls {
			pure[r][l] = true
		}
	}
	// A claim on a recorded ID stands when the piece owns it, or when the
	// piece lies in a different parent from the owner (nothing was severed
	// between them) and has a pure session of that lineage: evidence of the
	// merged campaign in its own right, as a merged-from operator's new
	// values are. A lone value of the lineage inside a piece that otherwise
	// belongs elsewhere is a bridge value, and is left to attribution. A
	// non-owner in the owner's own parent was split off by remove_actor and
	// its claim is void.
	standing := map[string]map[string]bool{} // rep -> sessions to join
	for i, x := range all {
		if active != nil && !active[i] {
			continue
		}
		l, a, ok := lineageOf(x)
		if !ok || !inGroup[l] {
			continue
		}
		own := owners[a.CampaignID]
		r := u.find(x.SessionID)
		if r == u.find(own.sess) || parentOf(i) != own.par && pure[r][l] {
			if standing[l] == nil {
				standing[l] = map[string]bool{}
			}
			standing[l][x.SessionID] = true
		}
	}
	for _, l := range sortedKeys(func() map[string]bool {
		m := map[string]bool{}
		for l := range standing {
			m[l] = true
		}
		return m
	}()) {
		ss := sortedKeys(standing[l])
		for _, s := range ss[1:] {
			u.union(ss[0], s)
		}
	}
	members := map[string][]int{}
	var roots []string
	for i, x := range all {
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
