package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// A refusal names the ID it could not find, so the operator can tell a stale
// dialog (unknown campaign) from a mistyped merge target.
func TestCampaignEditRefusalNamesUnknownID(t *testing.T) {
	_, mux := campaignServer(t)
	rec := postCampaignEdit(mux, url.Values{"id": {"c-ffffffffffff"}, "action": {"rename"}, "arg": {"x"}})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unknown campaign c-ffffffffffff") {
		t.Fatalf("unknown campaign = %d %q", rec.Code, rec.Body.String())
	}
	rec = postCampaignEdit(mux, url.Values{"id": {"c-0123456789ab"}, "action": {"merge"}, "arg": {"c-eeeeeeeeeeee"}})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unknown merge target c-eeeeeeeeeeee") {
		t.Fatalf("unknown merge target = %d %q", rec.Code, rec.Body.String())
	}
}

// An empty rename clears the operator's name (the campaign falls back to its
// suggested name); whitespace alone is the same clear. It is recorded as a
// rename with an empty arg, so Group's "latest rename wins" applies to it.
func TestCampaignEditEmptyRenameClearsName(t *testing.T) {
	s, mux := campaignServer(t)
	for _, arg := range []string{"", "   "} {
		if rec := postCampaignEdit(mux, url.Values{"id": {"c-0123456789ab"}, "action": {"rename"}, "arg": {arg}}); rec.Code != http.StatusOK {
			t.Fatalf("clear name %q = %d %q", arg, rec.Code, rec.Body.String())
		}
	}
	edits, err := s.st.CampaignEdits(context.Background())
	if err != nil || len(edits) != 2 || edits[0].Action != "rename" || edits[0].Arg != "" || edits[1].Arg != "" {
		t.Fatalf("edits %+v %v", edits, err)
	}
	// A clear still needs a real campaign.
	if rec := postCampaignEdit(mux, url.Values{"id": {"c-ffffffffffff"}, "action": {"rename"}, "arg": {""}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("clear on unknown campaign = %d", rec.Code)
	}
}
