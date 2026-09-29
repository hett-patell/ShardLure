package campaign

import (
	"reflect"
	"testing"
)

// M-3: an edit row with no campaign ID (only a corrupted or hand-edited
// database can hold one; the API refuses it) must be skipped, not honoured.
// A rename with ID "" used to emit a campaign whose ID is "", which
// SaveGrouping rejects whole, so one bad row froze every regroup. An
// ignore_evidence names a value, not a campaign, and still applies.
func TestGroupSkipsEditsWithoutCampaignID(t *testing.T) {
	occ := []Occurrence{o("ssh_key", "K", "a1", "a", 0), o("ssh_key", "K", "b1", "b", 1), o("payload", "P", "b1", "b", 1), o("payload", "P", "c1", "c", 2)}
	want := groupT(Input{Occurrences: occ})
	if len(want.Campaigns) != 1 || len(want.Campaigns[0].Members) != 3 {
		t.Fatalf("precondition: b1 bridges K and P: %+v", want.Campaigns)
	}
	bad := []Edit{
		{ID: 1, CampaignID: "", Action: "rename", Arg: "ghost"},
		{ID: 2, CampaignID: "", Action: "notes", Arg: "ghost"},
		{ID: 3, CampaignID: "", Action: "remove_actor", Arg: "b"},
		{ID: 4, CampaignID: "", Action: "merge", Arg: want.Campaigns[0].ID},
		{ID: 5, CampaignID: want.Campaigns[0].ID, Action: "merge", Arg: ""},
	}
	got := groupT(Input{Occurrences: occ, Assignments: want.Assignments, Aliases: want.Aliases, Edits: bad})
	for _, c := range got.Campaigns {
		if c.ID == "" {
			t.Fatalf("a campaign with an empty ID was emitted: %+v", got.Campaigns)
		}
	}
	if !reflect.DeepEqual(got.Campaigns, want.Campaigns) || !reflect.DeepEqual(got.Aliases, want.Aliases) {
		t.Fatalf("malformed edits changed the grouping:\n got %+v %v\nwant %+v %v", got.Campaigns, got.Aliases, want.Campaigns, want.Aliases)
	}
	// ignore_evidence carries no campaign ID by design and must still apply.
	ignored := groupT(Input{Occurrences: occ, Assignments: want.Assignments, Aliases: want.Aliases,
		Edits: append(bad, Edit{ID: 6, Action: "ignore_evidence", Arg: "payload:P"})})
	for _, c := range ignored.Campaigns {
		for _, v := range c.Values {
			if v == "P" {
				t.Fatalf("ignore_evidence without a campaign ID was dropped: %+v", ignored.Campaigns)
			}
		}
	}
}
