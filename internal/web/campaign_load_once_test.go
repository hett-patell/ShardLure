package web

import (
	"regexp"
	"strings"
	"testing"
)

// Final audit M5: the campaigns block ends with an unconditional first load
// (the palette searches both lists on every tab), so the Red tab's deep-link
// line must not load them again; a #tab=red page load fetched each twice.
// The single fetch per list on a #tab=red load was checked in a browser;
// this pins that exactly one top-level statement loads each list.
func TestCampaignListsLoadOncePerPage(t *testing.T) {
	topLevel := regexp.MustCompile(`(?m)^[^ \t/\n].*\brefresh(Campaigns|Scripts)\(\).*$`)
	var lines []string
	for _, l := range topLevel.FindAllString(intelHTML, -1) {
		// Definitions and the tab/window/poll hooks are not page-load calls.
		if strings.HasPrefix(l, "async function") || strings.HasPrefix(l, "onWindowChange(") {
			continue
		}
		lines = append(lines, l)
	}
	if len(lines) != 1 || lines[0] != "refreshCampaigns(); refreshScripts();" {
		t.Fatalf("page-load calls of the campaign lists = %q, want the one unconditional load", lines)
	}
}
