package web

import (
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
