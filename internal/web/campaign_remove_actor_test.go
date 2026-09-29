package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/networkshard/shardlure/internal/store"
)

// remove_actor must name an actor the campaign actually holds: its own
// members, or those of a campaign merged into it (the merge may not have been
// regrouped yet), or, for a merged-away ID, those of the campaign it now
// shows as. Anything else is a typo or a stale dialog, and the append-only
// ledger would keep a removal that can never mean anything.
func TestCampaignRemoveActorRequiresMembership(t *testing.T) {
	s, st := hasshTestServer(t)
	mux := http.NewServeMux()
	s.registerCampaignRoutes(mux)
	const k, p, x = "c-00000000000a", "c-00000000000b", "c-00000000000c"
	rows := []store.CampaignRow{
		{ID: k, Members: []store.CampaignMemberRow{{ActorID: "cowrie:k1", Reasons: "[]"}}},
		{ID: p, Members: []store.CampaignMemberRow{{ActorID: "cowrie:p1", Reasons: "[]"}}},
		{ID: x, Members: []store.CampaignMemberRow{{ActorID: "cowrie:x1", Reasons: "[]"}}},
	}
	if err := st.SaveGrouping(context.Background(), rows, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	// P merged into K; the worker has not regrouped yet, so P is still live.
	if rec := postCampaignEdit(mux, url.Values{"id": {p}, "action": {"merge"}, "arg": {k}}); rec.Code != http.StatusOK {
		t.Fatalf("merge = %d %s", rec.Code, rec.Body.String())
	}
	for _, c := range []struct {
		id, actor string
		ok        bool
	}{
		{k, "cowrie:k1", true},  // own member
		{k, "cowrie:p1", true},  // member of a campaign merged into K
		{p, "cowrie:k1", true},  // P now shows as K
		{k, "cowrie:x1", false}, // member of an unrelated campaign
		{x, "cowrie:k1", false},
		{k, "cowrie:nobody", false},
	} {
		rec := postCampaignEdit(mux, url.Values{"id": {c.id}, "action": {"remove_actor"}, "arg": {c.actor}})
		if c.ok && rec.Code != http.StatusOK {
			t.Errorf("remove %s from %s = %d %q, want 200", c.actor, c.id, rec.Code, rec.Body.String())
		}
		if !c.ok && (rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not a member")) {
			t.Errorf("remove %s from %s = %d %q, want 400 not a member", c.actor, c.id, rec.Code, rec.Body.String())
		}
	}
	// Once regrouped (P aliased into K, P's members under K) the rule holds.
	rows = []store.CampaignRow{
		{ID: k, Members: []store.CampaignMemberRow{{ActorID: "cowrie:k1", Reasons: "[]"}, {ActorID: "cowrie:p1", Reasons: "[]"}}},
		{ID: x, Members: []store.CampaignMemberRow{{ActorID: "cowrie:x1", Reasons: "[]"}}},
	}
	edits, err := st.CampaignEdits(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveGrouping(context.Background(), rows, nil, map[string]string{p: k}, edits[len(edits)-1].ID); err != nil {
		t.Fatal(err)
	}
	if rec := postCampaignEdit(mux, url.Values{"id": {p}, "action": {"remove_actor"}, "arg": {"cowrie:p1"}}); rec.Code != http.StatusOK {
		t.Fatalf("remove via merged-away ID after regroup = %d %q", rec.Code, rec.Body.String())
	}
	// Recorded literally, as submitted.
	edits, err = st.CampaignEdits(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	last := edits[len(edits)-1]
	if last.CampaignID != p || last.Arg != "cowrie:p1" {
		t.Fatalf("recorded %s/%s, want the literal %s/cowrie:p1", last.CampaignID, last.Arg, p)
	}
}
