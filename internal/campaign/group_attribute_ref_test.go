package campaign

import "context"

// attributeReference is attribute as it stood before I-1 (the per-value
// enumeration of every lineage each actor carries: quadratic on a bridge
// actor carrying many lineages), kept verbatim as the oracle for
// TestAttributionMatchesReference. It is never used outside tests.
//
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
func attributeReference(_ context.Context, occ []Occurrence, sessOcc map[string][]int, c *component, root string, owner map[string]lineage,
	lineageOf func(Occurrence) (string, Assignment, bool), rep func(string) string, stable map[string]bool, stamp map[string]string) error {
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
		return nil
	}
	if len(c.owned) <= 1 {
		for _, k := range floating {
			stamp[k] = c.id
		}
		return nil
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
				pick = actorMajorityReference(votes)
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
	return nil
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
func actorMajorityReference(pure map[string]map[string]map[string]bool) string {
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
