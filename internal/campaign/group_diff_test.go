package campaign

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
)

// randomWorld builds an Input with the structures attribution has to read:
// a pool of values, sessions and actors (some sessions shared by two actors,
// some actors spanning many sessions, so bridge actors and multi-actor
// sessions both occur), identity carried over from up to three prior cycles
// of the reference, and random edits (merges, so one lineage can hold several
// recorded IDs; renames; remove_actor; ignore_evidence).
func randomWorld(r *rand.Rand) Input {
	nv, ns, na := 2+r.Intn(12), 2+r.Intn(14), 2+r.Intn(8)
	kinds := []string{"ssh_key", "payload", "script"}
	sessActor := make([]string, ns)
	for s := range sessActor {
		sessActor[s] = fmt.Sprintf("act%d", r.Intn(na))
	}
	gen := func(day int) []Occurrence {
		var occ []Occurrence
		n := 1 + r.Intn(3*nv)
		for i := 0; i < n; i++ {
			v, s := r.Intn(nv), r.Intn(ns)
			a := sessActor[s]
			if r.Intn(10) == 0 { // a session with two actors, as the reference tolerates
				a = fmt.Sprintf("act%d", r.Intn(na))
			}
			occ = append(occ, o(kinds[v%len(kinds)], fmt.Sprintf("V%d", v), fmt.Sprintf("s%d", s), a, day+r.Intn(3)))
		}
		return occ
	}
	var prev Output
	prev.Aliases = map[string]string{}
	var edits []Edit
	cycles := r.Intn(4)
	for c := 0; c < cycles; c++ {
		in := Input{Occurrences: gen(c * 3), Assignments: prev.Assignments, Aliases: prev.Aliases, Edits: edits}
		out, err := group(context.Background(), in, attributeReference)
		if err != nil {
			panic(err)
		}
		prev = out
		ids := make([]string, 0, len(out.Campaigns))
		for _, c := range out.Campaigns {
			ids = append(ids, c.ID)
		}
		for _, a := range out.Assignments {
			ids = append(ids, a.CampaignID)
		}
		for e := 0; e < r.Intn(3) && len(ids) > 0; e++ {
			id := ids[r.Intn(len(ids))]
			var edit Edit
			switch r.Intn(5) {
			case 0:
				edit = Edit{CampaignID: id, Action: "merge", Arg: ids[r.Intn(len(ids))]}
			case 1:
				edit = Edit{CampaignID: id, Action: "rename", Arg: fmt.Sprintf("name%d", r.Intn(9))}
			case 2:
				edit = Edit{CampaignID: id, Action: "remove_actor", Arg: fmt.Sprintf("act%d", r.Intn(na))}
			case 3:
				edit = Edit{Action: "ignore_evidence", Arg: fmt.Sprintf("%s:V%d", kinds[r.Intn(3)], r.Intn(nv))}
			default:
				edit = Edit{CampaignID: id, Action: "notes", Arg: "n"}
			}
			edit.ID = int64(len(edits) + 1)
			edits = append(edits, edit)
		}
	}
	return Input{Occurrences: gen(cycles * 3), Assignments: prev.Assignments, Aliases: prev.Aliases, Edits: edits}
}

// The linear attribution (I-1) must produce exactly what the quadratic
// reference did, on random worlds, on the audit's bridge chain and on a
// shape with two heavy bridge actors plus a distinct light actor per value
// (the memoised tally's other branch).
func TestAttributionMatchesReference(t *testing.T) {
	check := func(name string, in Input) {
		t.Helper()
		want, err := group(context.Background(), in, attributeReference)
		if err != nil {
			t.Fatal(err)
		}
		got, err := group(context.Background(), in, attribute)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: attribution differs from the reference\n got %+v\nwant %+v", name, got, want)
		}
	}
	r := rand.New(rand.NewSource(11))
	for i := 0; i < 3000; i++ {
		check(fmt.Sprintf("world %d", i), randomWorld(r))
	}
	for _, m := range []int{3, 17, 200} {
		in := bridgeChain(m)
		check(fmt.Sprintf("chain m=%d", m), in)
		out := groupT(in)
		check(fmt.Sprintf("chain m=%d second cycle", m), Input{Occurrences: in.Occurrences, Assignments: out.Assignments, Aliases: out.Aliases})
	}
	// Two bridge actors carrying every lineage, and each new value shared
	// with its own light actor whose one stable value sits on one side.
	var occ []Occurrence
	for i := 0; i < 40; i++ {
		k := fmt.Sprintf("K%d", i)
		occ = append(occ, o("ssh_key", k, fmt.Sprintf("a%d", i), fmt.Sprintf("actorA%d", i), 0), o("ssh_key", k, fmt.Sprintf("b%d", i), fmt.Sprintf("actorB%d", i), 0))
	}
	first := groupT(Input{Occurrences: occ})
	for i := 0; i < 40; i++ {
		for _, b := range []string{"bridge1", "bridge2"} {
			s := b + fmt.Sprint(i)
			occ = append(occ, o("ssh_key", fmt.Sprintf("K%d", i), s, b, 1), o("ssh_key", fmt.Sprintf("K%d", (i+1)%40), s, b, 1), o("payload", fmt.Sprintf("F%d", i), s, b, 1))
		}
		occ = append(occ, o("payload", fmt.Sprintf("F%d", i), fmt.Sprintf("l%d", i), fmt.Sprintf("actorA%d", (i*7)%40), 2))
	}
	check("two heavy bridges", Input{Occurrences: occ, Assignments: first.Assignments, Aliases: first.Aliases})
}

// A cancelled context stops Group before it produces a grouping (the worker
// must never reach SaveGrouping with it), whether cancelled up front or
// during the attribution rounds.
func TestGroupStopsOnCancelledContext(t *testing.T) {
	in := bridgeChain(50)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := Group(ctx, in); !errors.Is(err, context.Canceled) || len(out.Campaigns) != 0 || len(out.Assignments) != 0 {
		t.Fatalf("Group with a cancelled context = %+v, %v; want an empty output and context.Canceled", out, err)
	}
	// Cancelled once attribution starts (the fourth check on this input is
	// the first round's): the per-round check must see it.
	late := &cancelAfter{Context: context.Background(), calls: 3}
	if _, err := Group(late, in); !errors.Is(err, context.Canceled) {
		t.Fatalf("Group with a context cancelled mid-way = %v, want context.Canceled", err)
	}
	if late.calls >= 0 {
		t.Fatalf("the cancellation was never observed (%d checks left)", late.calls)
	}
}

// cancelAfter reports Canceled from Err once it has been asked calls times.
type cancelAfter struct {
	context.Context
	calls int
}

func (c *cancelAfter) Err() error {
	c.calls--
	if c.calls < 0 {
		return context.Canceled
	}
	return nil
}
