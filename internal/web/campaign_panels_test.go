package web

import (
	"regexp"
	"strings"
	"testing"
)

func TestCampaignPanelsFollowFrontendContracts(t *testing.T) {
	for _, id := range []string{`id="panel-campaigns"`, `id="panel-scripts"`, `id="campaigns-table"`, `id="scripts-table"`, `id="cm-close"`} {
		if !strings.Contains(intelHTML, id) {
			t.Errorf("missing %s", id)
		}
	}
	if !regexp.MustCompile(`<dialog class="sess-modal" id="campaign-modal" aria-labelledby="cm-title">\s*<div class="sm-card">`).MatchString(intelHTML) {
		t.Error("campaign detail must reuse the labelled sess-modal dialog markup")
	}
	start := strings.Index(intelHTML, "// ==== Campaigns and scripts")
	end := strings.Index(intelHTML, "// ==== end campaigns and scripts")
	if start < 0 || end < start {
		t.Fatal("campaign JS block markers missing")
	}
	block := intelHTML[start:end]
	if strings.Contains(block, "onclick") || strings.Contains(block, "onkeydown") {
		t.Error("campaign JS must use data-* attributes and delegated listeners, not inline handlers")
	}
	for _, fn := range []string{"function refreshCampaigns", "function refreshScripts", "function openCampaign", "function openScript", "function campaignEdit"} {
		if !strings.Contains(block, fn) {
			t.Errorf("missing %s", fn)
		}
	}
}
