package campaign

import "testing"

// An empty rename clears the operator's name: the campaign falls back to its
// suggested name, and the latest rename still wins, empty or not.
func TestEmptyRenameClearsName(t *testing.T) {
	occ := []Occurrence{o("ssh_key", OutlawKey, "s1", "a", 0), o("ssh_key", OutlawKey, "s2", "b", 1)}
	first := groupT(Input{Occurrences: occ})
	id := campOf(first, "a").ID
	edits := []Edit{{ID: 1, CampaignID: id, Action: "rename", Arg: "Mine"}, {ID: 2, CampaignID: id, Action: "rename", Arg: ""}}
	c := campOf(feed(first, occ, edits), "a")
	if c.ID != id || c.Name != "" || c.SuggestedName != "Outlaw/Dota" {
		t.Fatalf("cleared: %+v", c)
	}
	edits = append(edits, Edit{ID: 3, CampaignID: id, Action: "rename", Arg: "Again"})
	if c := campOf(feed(first, occ, edits), "a"); c.Name != "Again" {
		t.Fatalf("rename after clear: %+v", c)
	}
}

// Only a name or notes keep a campaign with no members. A cleared name is no
// name, so it must stop pinning the campaign; notes still pin it.
func TestClearedNameDoesNotPinMemberlessCampaign(t *testing.T) {
	const id = "c-000000000001"
	out := groupT(Input{Edits: []Edit{{ID: 1, CampaignID: id, Action: "rename", Arg: "Old op"}, {ID: 2, CampaignID: id, Action: "rename", Arg: ""}}})
	if len(out.Campaigns) != 0 {
		t.Fatalf("cleared name still pins: %+v", out.Campaigns)
	}
	out = groupT(Input{Edits: []Edit{{ID: 1, CampaignID: id, Action: "rename", Arg: "Old op"}, {ID: 2, CampaignID: id, Action: "notes", Arg: "keep"},
		{ID: 3, CampaignID: id, Action: "rename", Arg: ""}}})
	if len(out.Campaigns) != 1 || out.Campaigns[0].Name != "" || out.Campaigns[0].Notes != "keep" {
		t.Fatalf("notes no longer pin a cleared campaign: %+v", out.Campaigns)
	}
}

// Across merged lineages the most recent rename wins (rule: last rename wins),
// and a clear is a rename: clearing on the campaign clears a name an older
// merged lineage carried, and a later rename on either lineage wins again.
func TestClearAcrossMergedLineages(t *testing.T) {
	k := []Occurrence{o("ssh_key", "K", "k1", "a1", 0), o("ssh_key", "K", "k2", "a2", 0)}
	p := []Occurrence{o("payload", "P", "p1", "b1", 1), o("payload", "P", "p2", "b2", 1)}
	occ := append(append([]Occurrence{}, k...), p...)
	first := groupT(Input{Occurrences: occ})
	kid, pid := campOf(first, "a1").ID, campOf(first, "b1").ID
	edits := []Edit{{ID: 1, CampaignID: pid, Action: "rename", Arg: "P-ops"}, {ID: 2, CampaignID: pid, Action: "merge", Arg: kid},
		{ID: 3, CampaignID: kid, Action: "rename", Arg: ""}}
	out := feed(first, occ, edits)
	if c := campOf(out, "b1"); len(out.Campaigns) != 1 || c.ID != kid || c.Name != "" {
		t.Fatalf("clear on the merged campaign did not clear P's older name: %+v", out.Campaigns)
	}
	edits = append(edits, Edit{ID: 4, CampaignID: pid, Action: "rename", Arg: "Back"})
	if c := campOf(feed(out, occ, edits), "b1"); c.Name != "Back" {
		t.Fatalf("later rename on the merged-from lineage lost: %+v", c)
	}
}
