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
