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
	ign := []Edit{{ID: 1, Action: "ignore_evidence", Arg: "payload:P"}, {ID: 2, Action: "ignore_evidence", Arg: "ssh_key:K"}}
	_ = ign
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
