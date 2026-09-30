package campaign

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// Input.Unreadable (final audit I-1): a value whose evidence could not be
// read this cycle keeps the assignment it had, like a value only a removed
// actor carried. It is not carried when it has no assignment, when an edit
// ignores it, or when it has an occurrence after all (then attribution
// decides as usual), and feeding the output back reaches a fixed point.
func TestGroupCarriesUnreadableAssignments(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	occ := func(kind, value, session, actor string) Occurrence {
		return Occurrence{Kind: kind, Value: value, SessionID: session, ActorID: actor, IP: "i", FirstSeen: now, LastSeen: now}
	}
	assignments := []Assignment{
		{Kind: "ssh_key", Value: "K", CampaignID: "c-1", Seq: 1},
		{Kind: "payload", Value: "P", CampaignID: "c-1", Seq: 2}, // unreadable, carried
		{Kind: "payload", Value: "Q", CampaignID: "c-2", Seq: 3}, // unreadable, ignored by an edit: not carried
		{Kind: "payload", Value: "S", CampaignID: "c-3", Seq: 4}, // readable this cycle: Group decides, the listing is inert
	}
	in := Input{
		Occurrences: []Occurrence{occ("ssh_key", "K", "s1", "a"), occ("ssh_key", "K", "s2", "b"), occ("payload", "S", "s1", "a"), occ("payload", "S", "s2", "b")},
		Assignments: assignments,
		Edits:       []Edit{{ID: 1, CampaignID: "c-1", Action: "rename", Arg: "Keep"}, {ID: 2, Action: "ignore_evidence", Arg: "payload:Q"}},
		Unreadable:  []ValueRef{{Kind: "payload", Value: "P"}, {Kind: "payload", Value: "Q"}, {Kind: "payload", Value: "R"}},
	}
	out, err := Group(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	// Listing a value that has an occurrence changes nothing: attribution
	// decides it (here S's lineage c-3 is owned by the component and kept as
	// recorded, aliased into c-1), exactly as without the listing.
	withS := in
	withS.Unreadable = append(append([]ValueRef(nil), in.Unreadable...), ValueRef{Kind: "payload", Value: "S"})
	if alt, err := Group(ctx, withS); err != nil || !reflect.DeepEqual(alt, out) {
		t.Fatalf("listing a present value changed the output (err %v):\n out=%+v\n alt=%+v", err, out.Assignments, alt.Assignments)
	}
	got := map[string]string{}
	for _, a := range out.Assignments {
		got[vkey(a.Kind, a.Value)] = a.CampaignID
	}
	if got[vkey("payload", "P")] != "c-1" {
		t.Fatalf("unreadable P not carried: %v", out.Assignments)
	}
	if _, ok := got[vkey("payload", "Q")]; ok {
		t.Fatalf("ignored Q carried: %v", out.Assignments)
	}
	if _, ok := got[vkey("payload", "R")]; ok {
		t.Fatalf("never-assigned R invented: %v", out.Assignments)
	}
	if got[vkey("ssh_key", "K")] != "c-1" || got[vkey("payload", "S")] != "c-3" || out.Aliases["c-3"] != "c-1" {
		t.Fatalf("readable values not attributed as usual: %v aliases %v", out.Assignments, out.Aliases)
	}
	if len(out.Campaigns) != 1 || out.Campaigns[0].ID != "c-1" || out.Campaigns[0].Name != "Keep" {
		t.Fatalf("campaigns %+v", out.Campaigns)
	}
	again, err := Group(ctx, Input{Occurrences: in.Occurrences, Assignments: out.Assignments, Aliases: out.Aliases, Edits: in.Edits, Unreadable: in.Unreadable})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again, out) {
		t.Fatalf("not a fixed point:\n out=%+v\n again=%+v", out.Assignments, again.Assignments)
	}
	// Readable again: P joins c-1's sessions and keeps c-1 (stable), so the
	// campaign shows the same ID with the payload as a reason.
	back := Input{Occurrences: append(in.Occurrences, occ("payload", "P", "s1", "a"), occ("payload", "P", "s2", "b")),
		Assignments: out.Assignments, Aliases: out.Aliases, Edits: in.Edits}
	final, err := Group(ctx, back)
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Campaigns) != 1 || final.Campaigns[0].ID != "c-1" {
		t.Fatalf("campaign re-keyed once readable: %+v", final.Campaigns)
	}
	for _, a := range final.Assignments {
		if a.Kind == "payload" && a.Value == "P" && a.CampaignID != "c-1" {
			t.Fatalf("P moved: %+v", final.Assignments)
		}
	}
}
