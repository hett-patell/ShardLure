package campaign

import (
	"math/rand"
	"reflect"
	"testing"
	"time"
)

var t0 = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

func o(kind, value, session, actor string, day int) Occurrence {
	return Occurrence{Kind: kind, Value: value, SessionID: session, ActorID: actor, IP: "ip-" + session,
		FirstSeen: t0.AddDate(0, 0, day), LastSeen: t0.AddDate(0, 0, day)}
}

func byID(out Output) map[string]Campaign {
	m := map[string]Campaign{}
	for _, c := range out.Campaigns {
		m[c.ID] = c
	}
	return m
}

func actorsOf(c Campaign) []string {
	var a []string
	for _, m := range c.Members {
		a = append(a, m.ActorID)
	}
	return a
}

// A mixed actor (one HASSH, several tools) must not bridge campaigns.
func TestSessionsNotActorsAreLinked(t *testing.T) {
	out := Group(Input{Occurrences: []Occurrence{
		o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "m1", "mixed", 1),
		o("payload", "P", "b1", "b", 2), o("payload", "P", "m2", "mixed", 3),
	}})
	if len(out.Campaigns) != 2 {
		t.Fatalf("want 2 campaigns, got %+v", out.Campaigns)
	}
	for _, c := range out.Campaigns {
		if len(c.Members) != 2 {
			t.Fatalf("campaign %s members %v", c.ID, actorsOf(c))
		}
	}
}

func TestCoOccurrenceInOneSessionLinks(t *testing.T) {
	out := Group(Input{Occurrences: []Occurrence{
		o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "x1", "x", 1), o("payload", "P", "x1", "x", 1), o("payload", "P", "b1", "b", 2),
	}})
	if len(out.Campaigns) != 1 || len(out.Campaigns[0].Members) != 3 {
		t.Fatalf("got %+v", out.Campaigns)
	}
}

func TestSuggestedNamesFromUnforgeableIndicators(t *testing.T) {
	out := Group(Input{Occurrences: []Occurrence{o("ssh_key", OutlawKey, "a1", "a", 0), o("ssh_key", OutlawKey, "b1", "b", 1)}})
	if out.Campaigns[0].SuggestedName != "Outlaw/Dota" {
		t.Fatalf("got %q", out.Campaigns[0].SuggestedName)
	}
	fake, fake2 := o("ssh_key", "SHA256:other", "c1", "c", 0), o("ssh_key", "SHA256:other", "d1", "d", 0)
	fake.Label, fake2.Label = "mdrfckr", "mdrfckr"
	if out := Group(Input{Occurrences: []Occurrence{fake, fake2}}); out.Campaigns[0].SuggestedName != "" {
		t.Fatal("a forged comment produced a suggested name")
	}
	p1, p2 := o("payload", "R", "e1", "e", 0), o("payload", "R", "f1", "f", 0)
	p1.Family, p2.Family = "redtail", "redtail"
	if out := Group(Input{Occurrences: []Occurrence{p1, p2}}); out.Campaigns[0].SuggestedName != "RedTail" {
		t.Fatal("classifier family did not suggest RedTail")
	}
}

// Identity survives a bridge from older evidence: the edited campaign keeps
// its ID and name.
func TestIdentitySurvivesBridgeAndKeepsEdits(t *testing.T) {
	first := Group(Input{Occurrences: []Occurrence{o("ssh_key", "K", "a1", "a", 5), o("ssh_key", "K", "b1", "b", 6)}})
	named := first.Campaigns[0].ID
	second := Group(Input{
		Occurrences: []Occurrence{o("ssh_key", "K", "a1", "a", 5), o("ssh_key", "K", "b1", "b", 6),
			o("payload", "OLD", "c1", "c", 0), o("payload", "OLD", "b1", "b", 6)},
		Assignments: first.Assignments, Aliases: first.Aliases,
		Edits: []Edit{{ID: 1, CampaignID: named, Action: "rename", Arg: "Kit"}},
	})
	c, ok := byID(second)[named]
	if len(second.Campaigns) != 1 || !ok || c.Name != "Kit" || len(c.Members) != 3 {
		t.Fatalf("got %+v", second.Campaigns)
	}
}

// Ignoring the bridging value keeps the ID on the piece that still holds the
// earliest-assigned value, with the notes attached.
func TestIgnoreKeepsIdentityAndNotes(t *testing.T) {
	occ := []Occurrence{o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "b1", "b", 1), o("payload", "P", "b1", "b", 1), o("payload", "P", "c1", "c", 2), o("payload", "P", "d1", "d", 3)}
	first := Group(Input{Occurrences: occ})
	id := first.Campaigns[0].ID
	second := Group(Input{Occurrences: occ, Assignments: first.Assignments, Aliases: first.Aliases,
		Edits: []Edit{{ID: 1, Action: "ignore_evidence", Arg: "ssh_key:K"}, {ID: 2, CampaignID: id, Action: "notes", Arg: "n"}}})
	if c, ok := byID(second)[id]; !ok || c.Notes != "n" || !reflect.DeepEqual(actorsOf(c), []string{"b", "c", "d"}) {
		t.Fatalf("got %+v", second.Campaigns)
	}
}

// remove_actor applies before union: the removed bridge no longer links.
func TestRemoveActorSplitsAFalseMerge(t *testing.T) {
	// b1 carries both K and P, so it bridges a and c into one campaign.
	occ := []Occurrence{o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "b1", "b", 1), o("payload", "P", "b1", "b", 2), o("payload", "P", "c1", "c", 3)}
	first := Group(Input{Occurrences: occ})
	if len(first.Campaigns) != 1 {
		t.Fatalf("b1 must bridge K and P: %+v", first.Campaigns)
	}
	id := first.Campaigns[0].ID
	second := Group(Input{Occurrences: occ, Assignments: first.Assignments, Aliases: first.Aliases,
		Edits: []Edit{{ID: 1, CampaignID: id, Action: "remove_actor", Arg: "b"}}})
	for _, c := range second.Campaigns {
		if len(c.Members) > 1 {
			t.Fatalf("a and c still linked without b: %+v", c)
		}
	}
}

func TestMergeEditResolvesThroughAliases(t *testing.T) {
	occ := []Occurrence{o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "b1", "b", 0), o("payload", "P", "c1", "c", 1), o("payload", "P", "d1", "d", 1)}
	first := Group(Input{Occurrences: occ})
	var k, p string
	for id, c := range byID(first) {
		if c.AnchorValue == "K" {
			k = id
		} else {
			p = id
		}
	}
	out := Group(Input{Occurrences: occ, Assignments: first.Assignments, Aliases: first.Aliases,
		Edits: []Edit{{ID: 1, CampaignID: p, Action: "notes", Arg: "from P"}, {ID: 2, CampaignID: p, Action: "merge", Arg: k}}})
	c, ok := byID(out)[k]
	if len(out.Campaigns) != 1 || !ok || len(c.Members) != 4 || c.Notes != "from P" || out.Aliases[p] != k {
		t.Fatalf("got %+v aliases %v", out.Campaigns, out.Aliases)
	}
}

func TestNamedCampaignPersistsWithoutMembers(t *testing.T) {
	out := Group(Input{Edits: []Edit{{ID: 1, CampaignID: "c-000000000001", Action: "rename", Arg: "Old op"}}})
	if len(out.Campaigns) != 1 || out.Campaigns[0].Name != "Old op" || len(out.Campaigns[0].Members) != 0 {
		t.Fatalf("got %+v", out.Campaigns)
	}
}

func TestGroupIsDeterministic(t *testing.T) {
	occ := []Occurrence{o("ssh_key", "K", "a1", "a", 3), o("ssh_key", "K", "b1", "b", 1), o("payload", "P", "b1", "b", 1),
		o("payload", "P", "c1", "c", 2), o("script", "S", "c1", "c", 2), o("script", "S", "d1", "d", 0)}
	want := Group(Input{Occurrences: occ})
	for i := 0; i < 50; i++ {
		if got := Group(Input{Occurrences: occ}); !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d differs", i)
		}
	}
}

// feed runs another regroup cycle with the previous output's identity.
func feed(prev Output, occ []Occurrence, edits []Edit) Output {
	return Group(Input{Occurrences: occ, Assignments: prev.Assignments, Aliases: prev.Aliases, Edits: edits})
}

// A merge must survive later regroups (it used to split again next cycle).
func TestMergePersistsAcrossCycles(t *testing.T) {
	occ := []Occurrence{o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "b1", "b", 0), o("payload", "P", "c1", "c", 1), o("payload", "P", "d1", "d", 1)}
	first := Group(Input{Occurrences: occ})
	var k, p string
	for id, c := range byID(first) {
		if c.AnchorValue == "K" {
			k = id
		} else {
			p = id
		}
	}
	edits := []Edit{{ID: 1, CampaignID: p, Action: "merge", Arg: k}}
	out := feed(first, occ, edits)
	for i := 0; i < 3; i++ {
		out = feed(out, occ, edits)
		if len(out.Campaigns) != 1 || out.Campaigns[0].ID != k || len(out.Campaigns[0].Members) != 4 {
			t.Fatalf("cycle %d: merge undone: %+v", i, out.Campaigns)
		}
	}
}

// A renamed campaign's name must not move to evidence it never contained
// after a bridge forms and then breaks.
func TestNameDoesNotDriftAfterBridgeAndSplit(t *testing.T) {
	pq := []Occurrence{o("payload", "P", "p1", "p", 5), o("payload", "P", "q1", "q", 5)}
	k := []Occurrence{o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "b1", "b", 1)}
	// Both campaigns exist first; K's evidence is older, so its seq is lower.
	first := Group(Input{Occurrences: append(append([]Occurrence{}, k...), pq...)})
	var named string
	for id, c := range byID(first) {
		if c.AnchorValue == "P" {
			named = id
		}
	}
	edits := []Edit{{ID: 1, CampaignID: named, Action: "rename", Arg: "Q-op"}}
	// Older key evidence K appears and one session bridges it to P.
	bridged := append(append([]Occurrence{}, pq...), o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "b1", "b", 1), o("ssh_key", "K", "p1", "p", 5))
	second := feed(first, bridged, edits)
	if len(second.Campaigns) != 1 || second.Campaigns[0].Name != "Q-op" {
		t.Fatalf("bridge: %+v", second.Campaigns)
	}
	// The bridge breaks (the operator ignores K in p1's context by removing it from the data).
	split := append(append([]Occurrence{}, pq...), o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "b1", "b", 1))
	third := feed(second, split, edits)
	for _, c := range third.Campaigns {
		hasP := false
		for _, v := range c.Values {
			if v == "P" {
				hasP = true
			}
		}
		if c.Name == "Q-op" && !hasP {
			t.Fatalf("name drifted to %+v", c)
		}
	}
	if c, ok := byID(third)[named]; !ok || c.Name != "Q-op" {
		t.Fatalf("named campaign lost: %+v", third.Campaigns)
	}
	var kID string
	for id, c := range byID(first) {
		if c.AnchorValue == "K" {
			kID = id
		}
	}
	if c, ok := byID(third)[kID]; !ok || c.Values[0] != "K" {
		t.Fatalf("the K campaign did not get its own ID back: %+v", third.Campaigns)
	}
	// And it is a fixed point.
	if fourth := feed(third, split, edits); !reflect.DeepEqual(fourth.Campaigns, third.Campaigns) {
		t.Fatalf("not a fixed point:\n%+v\n%+v", third.Campaigns, fourth.Campaigns)
	}
}

// A split piece that mints a new ID keeps it, so an operator can rename it.
func TestMintedIDIsStableAndRenameable(t *testing.T) {
	occ := []Occurrence{o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "b1", "b", 1), o("payload", "P", "b1", "b", 1), o("payload", "P", "c1", "c", 2), o("payload", "P", "d1", "d", 3)}
	first := Group(Input{Occurrences: occ})
	// Split by dropping the bridging session b1's payload.
	split := []Occurrence{o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "b1", "b", 1), o("payload", "P", "c1", "c", 2), o("payload", "P", "d1", "d", 3)}
	second := feed(first, split, nil)
	if len(second.Campaigns) != 2 {
		t.Fatalf("split: %+v", second.Campaigns)
	}
	var minted string
	for _, c := range second.Campaigns {
		if c.ID != first.Campaigns[0].ID {
			minted = c.ID
		}
	}
	edits := []Edit{{ID: 1, CampaignID: minted, Action: "rename", Arg: "New"}}
	third := feed(second, split, edits)
	if c, ok := byID(third)[minted]; !ok || c.Name != "New" {
		t.Fatalf("rename of minted campaign lost: %+v", third.Campaigns)
	}
}

// A minted ID must never collide with an ID another campaign holds.
func TestMintedIDDoesNotStealAHeldID(t *testing.T) {
	heldValue := "Q"
	held := CampaignID("payload", "P") // the ID a fresh P campaign would mint
	in := Input{
		Occurrences: []Occurrence{o("payload", "P", "p1", "p", 0), o("payload", "P", "p2", "x", 0), o("payload", heldValue, "q1", "q", 1), o("payload", heldValue, "q2", "y", 1)},
		Assignments: []Assignment{{Kind: "payload", Value: heldValue, CampaignID: held, Seq: 1}},
		Edits:       []Edit{{ID: 1, CampaignID: held, Action: "rename", Arg: "Q-op"}},
	}
	out := Group(in)
	c, ok := byID(out)[held]
	if !ok || c.Name != "Q-op" || c.Values[0] != heldValue {
		t.Fatalf("held ID stolen: %+v", out.Campaigns)
	}
}

// New sequence numbers follow time, so "earliest assigned" means oldest.
func TestFreshSequenceFollowsTime(t *testing.T) {
	out := Group(Input{Occurrences: []Occurrence{o("payload", "Z", "z1", "a", 0), o("payload", "Z", "z2", "b", 0), o("payload", "A", "a1", "c", 9), o("payload", "A", "a2", "d", 9)}})
	seq := map[string]int64{}
	for _, a := range out.Assignments {
		seq[a.Value] = a.Seq
	}
	if !(seq["Z"] < seq["A"]) {
		t.Fatalf("older value Z got seq %d >= A's %d", seq["Z"], seq["A"])
	}
}

func TestGroupIsDeterministicUnderShuffle(t *testing.T) {
	occ := []Occurrence{o("ssh_key", "K", "a1", "a", 3), o("ssh_key", "K", "b1", "b", 1), o("payload", "P", "b1", "b", 1),
		o("payload", "P", "c1", "c", 2), o("script", "S", "c1", "c", 2), o("script", "S", "d1", "d", 0), o("payload", "Q", "e1", "e", 4), o("payload", "Q", "f1", "f", 4)}
	want := Group(Input{Occurrences: occ})
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 50; i++ {
		sh := append([]Occurrence(nil), occ...)
		r.Shuffle(len(sh), func(a, b int) { sh[a], sh[b] = sh[b], sh[a] })
		if got := Group(Input{Occurrences: sh}); !reflect.DeepEqual(got, want) {
			t.Fatalf("shuffle %d differs", i)
		}
	}
}

// settle runs cycles of regroup with the same data and edits, checking inv
// after each, that shuffled input gives the same output, and finally that one
// more cycle changes nothing (the persisted identity is a fixed point).
func settle(t *testing.T, prev Output, occ []Occurrence, edits []Edit, cycles int, inv func(cycle int, out Output)) Output {
	t.Helper()
	r := rand.New(rand.NewSource(7))
	out := prev
	for i := 0; i < cycles; i++ {
		in := out
		out = feed(in, occ, edits)
		sh := append([]Occurrence(nil), occ...)
		r.Shuffle(len(sh), func(a, b int) { sh[a], sh[b] = sh[b], sh[a] })
		as := append([]Assignment(nil), in.Assignments...)
		r.Shuffle(len(as), func(a, b int) { as[a], as[b] = as[b], as[a] })
		ed := append([]Edit(nil), edits...)
		r.Shuffle(len(ed), func(a, b int) { ed[a], ed[b] = ed[b], ed[a] })
		if got := Group(Input{Occurrences: sh, Assignments: as, Aliases: in.Aliases, Edits: ed}); !reflect.DeepEqual(got, out) {
			t.Fatalf("cycle %d: shuffled input differs:\n%+v\n%+v", i, got, out)
		}
		inv(i, out)
	}
	if next := feed(out, occ, edits); !reflect.DeepEqual(next, out) {
		t.Fatalf("not a fixed point:\n%+v\n%+v", out, next)
	}
	return out
}

func hasActor(c Campaign, actor string) bool {
	for _, a := range actorsOf(c) {
		if a == actor {
			return true
		}
	}
	return false
}

// noActor fails if actor is a member of any campaign, and if any campaign
// holds both of the pair the removed actor used to bridge.
func noActor(t *testing.T, actor, x, y string) func(int, Output) {
	return func(cycle int, out Output) {
		t.Helper()
		for _, c := range out.Campaigns {
			if hasActor(c, actor) {
				t.Fatalf("cycle %d: removed actor %s is back in %s %v", cycle, actor, c.ID, actorsOf(c))
			}
			if hasActor(c, x) && hasActor(c, y) {
				t.Fatalf("cycle %d: %s and %s re-bridged in %s", cycle, x, y, c.ID)
			}
		}
	}
}

// remove_actor must hold every cycle, not only the first. Here both pieces
// fall below two actors, so neither is a campaign; their evidence must still
// remember the edited campaign or the actor bridges again next cycle.
func TestRemoveActorPersistsWhenBothPiecesAreSmall(t *testing.T) {
	occ := []Occurrence{o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "b1", "b", 1), o("payload", "P", "b1", "b", 2), o("payload", "P", "c1", "c", 3)}
	first := Group(Input{Occurrences: occ})
	edits := []Edit{{ID: 1, CampaignID: first.Campaigns[0].ID, Action: "remove_actor", Arg: "b"}}
	settle(t, first, occ, edits, 3, noActor(t, "b", "a", "c"))
}

// Both pieces survive the removal: the older keeps the ID, the other mints
// one. The minted piece came out of the edited campaign, so the removed actor
// must not join it either.
func TestRemoveActorPersistsWhenBothPiecesSurvive(t *testing.T) {
	occ := []Occurrence{o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "a2", "a2", 0), o("ssh_key", "K", "b1", "b", 1),
		o("payload", "P", "b1", "b", 2), o("payload", "P", "c1", "c", 3), o("payload", "P", "d1", "d", 3)}
	first := Group(Input{Occurrences: occ})
	id := first.Campaigns[0].ID
	edits := []Edit{{ID: 1, CampaignID: id, Action: "remove_actor", Arg: "b"}}
	var minted string
	settle(t, first, occ, edits, 3, func(cycle int, out Output) {
		noActor(t, "b", "a", "c")(cycle, out)
		if len(out.Campaigns) != 2 {
			t.Fatalf("cycle %d: want the K and P pieces, got %+v", cycle, out.Campaigns)
		}
		if c, ok := byID(out)[id]; !ok || !reflect.DeepEqual(actorsOf(c), []string{"a", "a2"}) {
			t.Fatalf("cycle %d: the older piece lost the edited ID: %+v", cycle, out.Campaigns)
		}
		for _, c := range out.Campaigns {
			if c.ID != id && minted == "" {
				minted = c.ID
			}
			if c.ID != id && c.ID != minted {
				t.Fatalf("cycle %d: the split piece changed ID %s -> %s", cycle, minted, c.ID)
			}
		}
	})
}

// Evidence that arrives after the removal (the actor keeps attacking with
// the same key and payload) must not bridge the campaign either.
func TestRemoveActorHoldsAgainstNewEvidence(t *testing.T) {
	occ := []Occurrence{o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "a2", "a2", 0), o("ssh_key", "K", "b1", "b", 1),
		o("payload", "P", "b1", "b", 2), o("payload", "P", "c1", "c", 3), o("payload", "P", "d1", "d", 3)}
	first := Group(Input{Occurrences: occ})
	edits := []Edit{{ID: 1, CampaignID: first.Campaigns[0].ID, Action: "remove_actor", Arg: "b"}}
	removed := feed(first, occ, edits)
	later := append(append([]Occurrence{}, occ...),
		o("ssh_key", "K", "b2", "b", 5),                                  // only the key
		o("payload", "P", "b3", "b", 6),                                  // only the payload
		o("ssh_key", "K", "b4", "b", 7), o("payload", "P", "b4", "b", 7), // a fresh bridge
		o("script", "S", "b4", "b", 7), o("script", "S", "e1", "e", 7)) // and a new value pulled in through it
	settle(t, removed, later, edits, 3, func(cycle int, out Output) {
		noActor(t, "b", "a", "c")(cycle, out)
		for _, c := range out.Campaigns {
			if hasActor(c, "e") {
				t.Fatalf("cycle %d: e joined through the removed actor: %v", cycle, actorsOf(c))
			}
		}
	})
}

// A merge target is an ordinary campaign: an automatic bridge into it must
// break again when the bridging evidence goes, and the bridged-in piece gets
// its own ID back.
func TestMergeTargetSplitsAfterTransientBridge(t *testing.T) {
	all := []Occurrence{o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "b1", "b", 0),
		o("payload", "P", "c1", "c", 1), o("payload", "P", "d1", "d", 1),
		o("script", "W", "e1", "e", 2), o("script", "W", "f1", "f", 2)}
	first := Group(Input{Occurrences: all})
	ids := map[string]string{}
	for _, c := range first.Campaigns {
		ids[c.AnchorValue] = c.ID
	}
	edits := []Edit{{ID: 1, CampaignID: ids["P"], Action: "merge", Arg: ids["K"]}}
	merged := feed(feed(first, all, edits), all, edits)
	bridged := feed(merged, append(append([]Occurrence{}, all...), o("script", "W", "a1", "a", 3)), edits)
	if len(bridged.Campaigns) != 1 {
		t.Fatalf("the bridge did not join W: %+v", bridged.Campaigns)
	}
	settle(t, bridged, all, edits, 3, func(cycle int, out Output) {
		k, okK := byID(out)[ids["K"]]
		w, okW := byID(out)[ids["W"]]
		if len(out.Campaigns) != 2 || !okK || !okW ||
			!reflect.DeepEqual(actorsOf(k), []string{"a", "b", "c", "d"}) || !reflect.DeepEqual(actorsOf(w), []string{"e", "f"}) {
			t.Fatalf("cycle %d: W did not split off the merge target: %+v", cycle, out.Campaigns)
		}
	})
}

// remove_actor on a campaign that absorbed another by merge still splits the
// false bridge, and the merge itself survives.
func TestRemoveActorSplitsAMergedCampaign(t *testing.T) {
	occ := []Occurrence{o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "b1", "b", 1), o("payload", "P", "b1", "b", 2), o("payload", "P", "c1", "c", 3),
		o("script", "S", "x1", "x", 4), o("script", "S", "y1", "y", 4)}
	first := Group(Input{Occurrences: occ})
	var kid, sid string
	for _, c := range first.Campaigns {
		if c.AnchorValue == "S" {
			sid = c.ID
		} else {
			kid = c.ID
		}
	}
	edits := []Edit{{ID: 1, CampaignID: sid, Action: "merge", Arg: kid}}
	merged := feed(feed(first, occ, edits), occ, edits)
	edits = append(edits, Edit{ID: 2, CampaignID: kid, Action: "remove_actor", Arg: "b"})
	settle(t, merged, occ, edits, 3, func(cycle int, out Output) {
		noActor(t, "b", "a", "c")(cycle, out)
		if c, ok := byID(out)[kid]; len(out.Campaigns) != 1 || !ok || !reflect.DeepEqual(actorsOf(c), []string{"a", "x", "y"}) {
			t.Fatalf("cycle %d: want the merged campaign without b and c: %+v", cycle, out.Campaigns)
		}
	})
}

// Occurrences that differ only in label, family or IP must not let input
// order decide what a campaign shows.
func TestOccurrenceTieBreakIsTotal(t *testing.T) {
	x1, x2 := o("payload", "K", "a1", "a", 0), o("payload", "K", "a1", "a", 0)
	x1.Label, x2.Label = "one", "two"
	x1.Family, x2.Family = "", "redtail"
	x1.IP, x2.IP = "ip-2", "ip-1"
	y := o("payload", "K", "b1", "b", 0)
	want := Group(Input{Occurrences: []Occurrence{x1, x2, y}})
	for _, in := range [][]Occurrence{{x2, y, x1}, {y, x1, x2}, {x2, x1, y}} {
		if got := Group(Input{Occurrences: in}); !reflect.DeepEqual(got, want) {
			t.Fatalf("input order changed the output:\n%+v\n%+v", got, want)
		}
	}
}

// Edits apply in ID (recorded) order whatever order they are passed in.
func TestEditsApplyInIDOrder(t *testing.T) {
	id := CampaignID("payload", "X")
	edits := []Edit{{ID: 2, CampaignID: id, Action: "rename", Arg: "second"}, {ID: 1, CampaignID: id, Action: "rename", Arg: "first"}}
	if out := Group(Input{Edits: edits}); len(out.Campaigns) != 1 || out.Campaigns[0].Name != "second" {
		t.Fatalf("got %+v", out.Campaigns)
	}
}

// An explicit merge persists every cycle, even when a session briefly
// bridges the merged-from evidence to an unrelated campaign D. While the
// bridge exists the combined component is K's (the operator's merge outranks
// an automatic ID); when it breaks, K holds its merged evidence again and D
// gets its own ID back.
func TestMergeSurvivesTransientBridgeToAnotherCampaign(t *testing.T) {
	all := []Occurrence{o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "b1", "b", 0),
		o("payload", "P", "c1", "c", 1), o("payload", "P", "d1", "d", 1),
		o("script", "D", "e1", "e", 2), o("script", "D", "f1", "f", 2)}
	first := Group(Input{Occurrences: all})
	ids := map[string]string{}
	for _, c := range first.Campaigns {
		ids[c.AnchorValue] = c.ID
	}
	edits := []Edit{{ID: 1, CampaignID: ids["P"], Action: "merge", Arg: ids["K"]}}
	merged := feed(feed(first, all, edits), all, edits)
	// c2 carries P and D together.
	bridge := append(append([]Occurrence{}, all...), o("script", "D", "c2", "c", 3), o("payload", "P", "c2", "c", 3))
	bridged := settle(t, merged, bridge, edits, 3, func(cycle int, out Output) {
		k, ok := byID(out)[ids["K"]]
		if len(out.Campaigns) != 1 || !ok || !reflect.DeepEqual(actorsOf(k), []string{"a", "b", "c", "d", "e", "f"}) {
			t.Fatalf("bridge cycle %d: want one campaign under K: %+v", cycle, out.Campaigns)
		}
		for _, a := range out.Assignments {
			if a.Value == "P" && a.CampaignID != ids["P"] {
				t.Fatalf("bridge cycle %d: merged-from value P rewritten to %s", cycle, a.CampaignID)
			}
		}
	})
	settle(t, bridged, all, edits, 3, func(cycle int, out Output) {
		k, okK := byID(out)[ids["K"]]
		d, okD := byID(out)[ids["D"]]
		if len(out.Campaigns) != 2 || !okK || !okD ||
			!reflect.DeepEqual(actorsOf(k), []string{"a", "b", "c", "d"}) || !reflect.DeepEqual(actorsOf(d), []string{"e", "f"}) {
			t.Fatalf("after bridge cycle %d: merge or D's identity lost: %+v", cycle, out.Campaigns)
		}
	})
}

// mergedKPD sets up campaigns K, P and D and merges P into K.
func mergedKPD() ([]Occurrence, map[string]string, []Edit, Output) {
	all := []Occurrence{o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "b1", "b", 0),
		o("payload", "P", "c1", "c", 1), o("payload", "P", "d1", "d", 1),
		o("script", "D", "e1", "e", 2), o("script", "D", "f1", "f", 2)}
	first := Group(Input{Occurrences: all})
	ids := map[string]string{}
	for _, c := range first.Campaigns {
		ids[c.AnchorValue] = c.ID
	}
	edits := []Edit{{ID: 1, CampaignID: ids["P"], Action: "merge", Arg: ids["K"]}}
	return all, ids, edits, feed(feed(first, all, edits), all, edits)
}

// kAndDSeparate checks that after a bridge breaks K holds its merged
// evidence (a, b, c, d) and D is back under its own ID without them.
func kAndDSeparate(t *testing.T, ids map[string]string) func(int, Output) {
	return func(cycle int, out Output) {
		t.Helper()
		k, okK := byID(out)[ids["K"]]
		d, okD := byID(out)[ids["D"]]
		if !okK || !okD || !reflect.DeepEqual(actorsOf(k), []string{"a", "b", "c", "d"}) || !reflect.DeepEqual(actorsOf(d), []string{"e", "f"}) {
			t.Fatalf("after bridge cycle %d: merge or D's identity lost: %+v", cycle, out.Campaigns)
		}
	}
}

// Evidence first seen while P was bridged to D must not inherit P's merged
// status: here D's actors pick up a new payload Y during the bridge.
func TestValueFirstSeenInBridgeDoesNotInheritMerge(t *testing.T) {
	all, ids, edits, merged := mergedKPD()
	withY := append(append([]Occurrence{}, all...), o("script", "D", "e3", "e", 4), o("payload", "Y", "e3", "e", 4), o("payload", "Y", "f3", "f", 4))
	bridge := append(append([]Occurrence{}, withY...), o("script", "D", "c2", "c", 3), o("payload", "P", "c2", "c", 3))
	bridged := settle(t, merged, bridge, edits, 3, func(cycle int, out Output) {
		if k, ok := byID(out)[ids["K"]]; len(out.Campaigns) != 1 || !ok || !hasActor(k, "e") {
			t.Fatalf("bridge cycle %d: want one campaign under K: %+v", cycle, out.Campaigns)
		}
	})
	settle(t, bridged, withY, edits, 3, kAndDSeparate(t, ids))
}

// The bridge itself is a new value X (c3 carries P and X, e3 carries D and
// X). When c3 ages out, X stays with D and must not drag D into K.
func TestBridgeThroughNewValueDoesNotInheritMerge(t *testing.T) {
	all, ids, edits, merged := mergedKPD()
	after := append(append([]Occurrence{}, all...), o("script", "D", "e3", "e", 4), o("payload", "X", "e3", "e", 4))
	bridge := append(append([]Occurrence{}, after...), o("payload", "P", "c3", "c", 4), o("payload", "X", "c3", "c", 4))
	bridged := settle(t, merged, bridge, edits, 3, func(cycle int, out Output) {
		if k, ok := byID(out)[ids["K"]]; len(out.Campaigns) != 1 || !ok || !hasActor(k, "e") {
			t.Fatalf("bridge cycle %d: want one campaign under K: %+v", cycle, out.Campaigns)
		}
	})
	settle(t, bridged, after, edits, 3, kAndDSeparate(t, ids))
}

// A merged piece outlives its target's own evidence and picks up a value only
// ever seen with merged evidence. That value is written under the merge
// target itself, and the target must never be aliased back into the
// merged-from ID (an alias cycle).
func TestMergedPieceOutlivesItsTargetWithoutAliasCycle(t *testing.T) {
	all, ids, edits, merged := mergedKPD()
	rest := append(append([]Occurrence{}, all[2:]...), // K's own evidence aged out
		o("payload", "P", "c5", "c", 6), o("payload", "Y", "c5", "c", 6), o("payload", "Y", "d5", "d", 6))
	settle(t, merged, rest, edits, 3, func(cycle int, out Output) {
		for from := range out.Aliases {
			seen := map[string]bool{}
			for id := from; ; {
				if seen[id] {
					t.Fatalf("cycle %d: alias cycle through %s: %v", cycle, id, out.Aliases)
				}
				seen[id] = true
				next, ok := out.Aliases[id]
				if !ok || next == id {
					break
				}
				id = next
			}
		}
		if k, ok := byID(out)[ids["K"]]; !ok || !reflect.DeepEqual(actorsOf(k), []string{"c", "d"}) {
			t.Fatalf("cycle %d: the merged piece left K: %+v", cycle, out.Campaigns)
		}
		for _, a := range out.Assignments {
			if a.Value == "Y" && a.CampaignID != ids["K"] {
				t.Fatalf("cycle %d: Y written under %s, want the merge target", cycle, a.CampaignID)
			}
		}
	})
}

// noAliasCycle fails if any alias chain in out loops.
func noAliasCycle(t *testing.T, cycle int, out Output) {
	t.Helper()
	for from := range out.Aliases {
		seen := map[string]bool{}
		for id := from; ; {
			if seen[id] {
				t.Fatalf("cycle %d: alias cycle through %s: %v", cycle, id, out.Aliases)
			}
			seen[id] = true
			next, ok := out.Aliases[id]
			if !ok || next == id {
				break
			}
			id = next
		}
	}
}

// Two merges, P into K and Q into D. P's actors pick up Y, then a session
// bridges K's own evidence with Q. Retiring K into the bridged piece while
// P's piece also held K (through Y) once produced {P->K, K->P}: an alias
// cycle. Only the piece holding K's earliest value may retire it, and the
// guard checks the whole chain. When the bridge breaks, K and D separate
// again with their merges intact.
func TestBridgeBetweenMergeTargetsHasNoAliasCycle(t *testing.T) {
	all := []Occurrence{o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "b1", "b", 0),
		o("payload", "P", "c1", "c", 1), o("payload", "P", "d1", "d", 1),
		o("script", "D", "e1", "e", 2), o("script", "D", "f1", "f", 2),
		o("script", "Q", "g1", "g", 3), o("script", "Q", "h1", "h", 3)}
	first := Group(Input{Occurrences: all})
	ids := map[string]string{}
	for _, c := range first.Campaigns {
		ids[c.AnchorValue] = c.ID
	}
	edits := []Edit{{ID: 1, CampaignID: ids["P"], Action: "merge", Arg: ids["K"]}, {ID: 2, CampaignID: ids["Q"], Action: "merge", Arg: ids["D"]}}
	merged := feed(feed(first, all, edits), all, edits)
	withY := append(append([]Occurrence{}, all...), o("payload", "P", "c2", "c", 4), o("payload", "Y", "c2", "c", 4), o("payload", "Y", "d2", "d", 4))
	afterY := settle(t, merged, withY, edits, 3, func(cycle int, out Output) {
		for _, a := range out.Assignments {
			if a.Value == "Y" && a.CampaignID != ids["K"] {
				t.Fatalf("cycle %d: Y seen only with merged evidence was written under %s, want the merge target", cycle, a.CampaignID)
			}
		}
	})
	bridge := append(append([]Occurrence{}, withY...), o("ssh_key", "K", "z1", "z", 5), o("script", "Q", "z1", "z", 5))
	bridged := settle(t, afterY, bridge, edits, 3, func(cycle int, out Output) {
		noAliasCycle(t, cycle, out)
		if len(out.Campaigns) != 1 || len(out.Campaigns[0].Members) != 9 {
			t.Fatalf("bridge cycle %d: want one campaign of nine actors: %+v", cycle, out.Campaigns)
		}
	})
	settle(t, bridged, withY, edits, 3, func(cycle int, out Output) {
		noAliasCycle(t, cycle, out)
		k, okK := byID(out)[ids["K"]]
		d, okD := byID(out)[ids["D"]]
		if len(out.Campaigns) != 2 || !okK || !okD ||
			!reflect.DeepEqual(actorsOf(k), []string{"a", "b", "c", "d"}) || !reflect.DeepEqual(actorsOf(d), []string{"e", "f", "g", "h"}) {
			t.Fatalf("after bridge cycle %d: merges or identities lost: %+v", cycle, out.Campaigns)
		}
	})
}

// D is older than K, and P is merged into K. A session of K's actor bridges
// K and D; while bridged, D's actors pick up a new value Y. Y must be
// written under D (the identity it was seen with), never under the bridged
// component's winner: stamped with K's ID it handed D's older piece a direct
// claim on K after the break, and D walked off with K's ID and merge.
func TestValueSeenWithOlderCampaignDuringBridgeStaysWithIt(t *testing.T) {
	all := []Occurrence{o("script", "D", "e1", "e", 0), o("script", "D", "f1", "f", 0),
		o("ssh_key", "K", "a1", "a", 1), o("ssh_key", "K", "b1", "b", 1),
		o("payload", "P", "c1", "c", 2), o("payload", "P", "d1", "d", 2)}
	first := Group(Input{Occurrences: all})
	ids := map[string]string{}
	for _, c := range first.Campaigns {
		ids[c.AnchorValue] = c.ID
	}
	edits := []Edit{{ID: 1, CampaignID: ids["P"], Action: "merge", Arg: ids["K"]}}
	merged := feed(feed(first, all, edits), all, edits)
	withY := append(append([]Occurrence{}, all...), o("script", "D", "e3", "e", 4), o("payload", "Y", "e3", "e", 4), o("payload", "Y", "f3", "f", 4))
	bridge := append(append([]Occurrence{}, withY...), o("ssh_key", "K", "a2", "a", 3), o("script", "D", "a2", "a", 3))
	bridged := settle(t, merged, bridge, edits, 3, func(cycle int, out Output) {
		if k, ok := byID(out)[ids["K"]]; len(out.Campaigns) != 1 || !ok || len(k.Members) != 6 {
			t.Fatalf("bridge cycle %d: want one campaign under K: %+v", cycle, out.Campaigns)
		}
		for _, a := range out.Assignments {
			if a.Value == "Y" && a.CampaignID != ids["D"] {
				t.Fatalf("bridge cycle %d: Y seen only with D written under %s", cycle, a.CampaignID)
			}
		}
	})
	settle(t, bridged, withY, edits, 3, func(cycle int, out Output) {
		k, okK := byID(out)[ids["K"]]
		d, okD := byID(out)[ids["D"]]
		if len(out.Campaigns) != 2 || !okK || !okD ||
			!reflect.DeepEqual(actorsOf(k), []string{"a", "b", "c", "d"}) || !reflect.DeepEqual(actorsOf(d), []string{"e", "f"}) {
			t.Fatalf("after bridge cycle %d: merge or D's identity lost: %+v", cycle, out.Campaigns)
		}
	})
}

// The spec's split rule: when two pieces claim one ID, the piece holding
// that ID's earliest-assigned value keeps it. Here stored assignments put
// K's value K (seq 2) and Y (seq 3) both under K's ID, and Y sits with the
// older campaign D. D's piece is older overall, but K's earliest value is in
// K's piece, so K keeps its ID and name; Y is rewritten to D.
func TestSplitAwardsIDToHolderOfItsEarliestValue(t *testing.T) {
	did, kid := CampaignID("script", "D"), CampaignID("ssh_key", "K")
	occ := []Occurrence{o("script", "D", "e1", "e", 0), o("script", "D", "f1", "f", 0),
		o("ssh_key", "K", "a1", "a", 1), o("ssh_key", "K", "b1", "b", 1),
		o("script", "D", "e3", "e", 4), o("payload", "Y", "e3", "e", 4), o("payload", "Y", "f3", "f", 4)}
	prev := Output{Assignments: []Assignment{
		{Kind: "script", Value: "D", CampaignID: did, Seq: 1},
		{Kind: "ssh_key", Value: "K", CampaignID: kid, Seq: 2},
		{Kind: "payload", Value: "Y", CampaignID: kid, Seq: 3},
	}, Aliases: map[string]string{}}
	edits := []Edit{{ID: 1, CampaignID: kid, Action: "rename", Arg: "Kname"}}
	settle(t, prev, occ, edits, 3, func(cycle int, out Output) {
		k, okK := byID(out)[kid]
		d, okD := byID(out)[did]
		if len(out.Campaigns) != 2 || !okK || !okD || k.Name != "Kname" || d.Name != "" ||
			!reflect.DeepEqual(actorsOf(k), []string{"a", "b"}) || !reflect.DeepEqual(actorsOf(d), []string{"e", "f"}) {
			t.Fatalf("cycle %d: K's ID did not stay with K's earliest value: %+v", cycle, out.Campaigns)
		}
		for _, a := range out.Assignments {
			if a.Value == "Y" && a.CampaignID != did {
				t.Fatalf("cycle %d: Y still assigned to %s, want D", cycle, a.CampaignID)
			}
		}
	})
}

// campOf returns the campaign holding actor, or an empty Campaign.
func campOf(out Output, actor string) Campaign {
	for _, c := range out.Campaigns {
		if hasActor(c, actor) {
			return c
		}
	}
	return Campaign{}
}

// R1: an explicit merge outlives the evidence that was live when it was made.
// P is merged into K and P's operator keeps working with a new payload P2;
// when P's old sessions age out, P2's piece must still be K.
func TestMergeSurvivesSourceEvidenceTurnover(t *testing.T) {
	k := []Occurrence{o("ssh_key", "K", "k1", "a1", 0), o("ssh_key", "K", "k2", "a2", 0)}
	p := []Occurrence{o("payload", "P", "p1", "b1", 1), o("payload", "P", "p2", "b2", 1)}
	out := Group(Input{Occurrences: append(append([]Occurrence{}, k...), p...)})
	kid, pid := campOf(out, "a1").ID, campOf(out, "b1").ID
	edits := []Edit{{ID: 1, CampaignID: pid, Action: "merge", Arg: kid}, {ID: 2, CampaignID: pid, Action: "rename", Arg: "P-ops"}}
	out = feed(out, append(append([]Occurrence{}, k...), p...), edits)
	withP2 := append(append(append([]Occurrence{}, k...), p...),
		o("payload", "P", "p3", "b1", 2), o("payload", "P2", "p3", "b1", 2), o("payload", "P2", "p4", "b2", 3))
	out = feed(out, withP2, edits)
	rest := append(append([]Occurrence{}, k...), o("payload", "P2", "p4", "b2", 3), o("payload", "P2", "p5", "b1", 4))
	settle(t, out, rest, edits, 3, func(cycle int, out Output) {
		c := campOf(out, "b1")
		if len(out.Campaigns) != 1 || c.ID != kid || c.Name != "P-ops" || !reflect.DeepEqual(actorsOf(c), []string{"a1", "a2", "b1", "b2"}) {
			t.Fatalf("cycle %d: merge lost after P aged out: %+v", cycle, out.Campaigns)
		}
	})
}

// R2: a long bridge through a shared script X outlives both sides' pre-bridge
// evidence. Each side's new value is attributed to the side it was seen with,
// so after the break K keeps its ID and name and D never takes them.
func TestBridgeTurnoverDoesNotSwapIdentities(t *testing.T) {
	base := []Occurrence{o("ssh_key", "K", "k1", "a1", 0), o("ssh_key", "K", "k2", "a2", 0),
		o("payload", "D", "d1", "b1", 1), o("payload", "D", "d2", "b2", 1)}
	out := Group(Input{Occurrences: base})
	kid, did := campOf(out, "a1").ID, campOf(out, "b1").ID
	edits := []Edit{{ID: 1, CampaignID: kid, Action: "rename", Arg: "K-ops"}}
	bridge := []Occurrence{
		o("script", "X", "x1", "a1", 2), o("ssh_key", "K", "x1", "a1", 2),
		o("script", "X", "x2", "b1", 2), o("payload", "D", "x2", "b1", 2),
		o("payload", "D2", "x3", "b2", 3), o("script", "X", "x3", "b2", 3), o("payload", "D2", "d3", "b1", 3), o("payload", "D", "d3", "b1", 3),
		o("ssh_key", "K2", "x4", "a2", 4), o("script", "X", "x4", "a2", 4), o("ssh_key", "K2", "k3", "a1", 4), o("ssh_key", "K", "k3", "a1", 4),
	}
	out = feed(out, append(append([]Occurrence{}, base...), bridge...), edits)
	drop := func(occ []Occurrence, keep func(Occurrence) bool) []Occurrence {
		var out []Occurrence
		for _, x := range occ {
			if keep(x) {
				out = append(out, x)
			}
		}
		return out
	}
	noD := append(drop(append(append([]Occurrence{}, base...), bridge...), func(x Occurrence) bool { return x.Value != "D" }), o("payload", "D2", "d4", "b2", 5))
	out = feed(out, noD, edits)
	noK := append(drop(noD, func(x Occurrence) bool { return x.Value != "K" }), o("ssh_key", "K2", "k4", "a2", 6))
	out = feed(out, noK, edits)
	after := append(drop(noK, func(x Occurrence) bool { return x.SessionID[0] != 'x' }), o("payload", "D2", "d5", "b1", 7), o("ssh_key", "K2", "k5", "a1", 7))
	settle(t, out, after, edits, 3, func(cycle int, out Output) {
		ck, cd := campOf(out, "a1"), campOf(out, "b1")
		if ck.ID != kid || ck.Name != "K-ops" || cd.ID != did || cd.Name != "" {
			t.Fatalf("cycle %d: identities swapped after turnover: K=%s %q D=%s %q", cycle, ck.ID, ck.Name, cd.ID, cd.Name)
		}
	})
}

// bridgedKD builds K, D and T, then bridges K and D through one session.
func bridgedKD(t *testing.T) (base, bridge []Occurrence, out Output, kid, did, tid string) {
	t.Helper()
	base = []Occurrence{o("ssh_key", "K", "k1", "a1", 0), o("ssh_key", "K", "k2", "a2", 0),
		o("payload", "D", "d1", "b1", 1), o("payload", "D", "d2", "b2", 1),
		o("script", "T", "t1", "c1", 2), o("script", "T", "t2", "c2", 2)}
	out = Group(Input{Occurrences: base})
	kid, did, tid = campOf(out, "a1").ID, campOf(out, "b1").ID, campOf(out, "c1").ID
	bridge = []Occurrence{o("ssh_key", "K", "z1", "z", 3), o("payload", "D", "z1", "z", 3)}
	out = feed(out, append(append([]Occurrence{}, base...), bridge...), nil)
	if Resolve(out.Aliases, did) != kid && Resolve(out.Aliases, kid) != did {
		t.Fatalf("setup: K and D not bridged: %v", out.Aliases)
	}
	return
}

// R3/R4: a merge names an ID that is only an automatic alias at the time. The
// merge binds the lineage named, not the bridge's other side: once the bridge
// ends, K is on its own again in both directions of the edit.
func TestMergeNamingBridgedIDDoesNotFuseThirdCampaign(t *testing.T) {
	for _, dir := range []string{"T into D", "D into T"} {
		base, bridge, out, kid, did, tid := bridgedKD(t)
		e := Edit{ID: 1, CampaignID: tid, Action: "merge", Arg: did}
		if dir == "D into T" {
			e = Edit{ID: 1, CampaignID: did, Action: "merge", Arg: tid}
		}
		edits := []Edit{e}
		out = feed(out, append(append([]Occurrence{}, base...), bridge...), edits)
		settle(t, out, base, edits, 3, func(cycle int, out Output) {
			k, d, tt := campOf(out, "a1"), campOf(out, "b1"), campOf(out, "c1")
			if k.ID != kid || d.ID == kid || d.ID != tt.ID {
				t.Fatalf("%s cycle %d: K=%s D=%s T=%s (K %s)", dir, cycle, k.ID, d.ID, tt.ID, kid)
			}
		})
	}
}

// R5: P merged into K, K renamed, a3 removed from K. When K's own evidence
// ages out, the merge, the name and the removal all stay with K's operator.
func TestMergeTargetKeepsIDNameAndRemovalThroughTurnover(t *testing.T) {
	k := []Occurrence{o("ssh_key", "K", "k1", "a1", 0), o("ssh_key", "K", "k2", "a2", 0), o("ssh_key", "K", "k3", "a3", 0)}
	p := []Occurrence{o("payload", "P", "p1", "b1", 1), o("payload", "P", "p2", "b2", 1)}
	out := Group(Input{Occurrences: append(append([]Occurrence{}, k...), p...)})
	kid, pid := campOf(out, "a1").ID, campOf(out, "b1").ID
	edits := []Edit{{ID: 1, CampaignID: pid, Action: "merge", Arg: kid}, {ID: 2, CampaignID: kid, Action: "rename", Arg: "K-ops"},
		{ID: 3, CampaignID: kid, Action: "remove_actor", Arg: "a3"}}
	all := append(append([]Occurrence{}, k...), p...)
	out = feed(out, all, edits)
	all = append(all, o("payload", "P", "p3", "b1", 2), o("payload", "P2", "p3", "b1", 2))
	out = feed(out, all, edits)
	all = append(all, o("ssh_key", "K", "k4", "a1", 3), o("ssh_key", "K2", "k4", "a1", 3))
	out = feed(out, all, edits)
	rest := []Occurrence{
		o("payload", "P", "p3", "b1", 2), o("payload", "P2", "p3", "b1", 2), o("payload", "P2", "p4", "b2", 4),
		o("ssh_key", "K2", "k4", "a1", 3), o("ssh_key", "K2", "k5", "a2", 4), o("ssh_key", "K2", "k6", "a3", 4),
	}
	settle(t, out, rest, edits, 3, func(cycle int, out Output) {
		c := campOf(out, "a1")
		if len(out.Campaigns) != 1 || c.ID != kid || c.Name != "K-ops" || !reflect.DeepEqual(actorsOf(c), []string{"a1", "a2", "b1", "b2"}) {
			t.Fatalf("cycle %d: K's operator lost ID, name or removal: %+v", cycle, out.Campaigns)
		}
	})
}
