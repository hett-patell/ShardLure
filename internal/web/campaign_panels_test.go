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

// TestCampaignReloadKeepsMergeTarget pins two fixes in the post-edit reload
// (there is no JS harness, so the lines are asserted as text). A pending merge
// target must be carried as the object scheduleCampaignReload reads
// (target.id/target.merged); assigning the bare ID string lost it, leaving
// the dialog on the merged-away source. And a reload must defer while an
// edit POST for its view is still in flight.
func TestCampaignReloadKeepsMergeTarget(t *testing.T) {
	start := strings.Index(intelHTML, "// ==== Campaigns and scripts")
	end := strings.Index(intelHTML, "// ==== end campaigns and scripts")
	if start < 0 || end < start {
		t.Fatal("campaign JS block markers missing")
	}
	block := intelHTML[start:end]
	if strings.Contains(block, "target = _cmPending.target;") {
		t.Error("pending merge target assigned as a bare string: target.id reads undefined")
	}
	for _, want := range []string{
		"if (_cmPending.merged) target = { id: _cmPending.target, merged: true };",
		"if (_cmFlight.view === entry.view && _cmFlight.n > 0) return;",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("missing %q", want)
		}
	}
}

// The dialog offers "clear name" (an empty rename) and empties the field
// before sending, so the saved baseline matches and the reload is not held
// back as unsaved typing. Asserted as text: there is no JS harness.
func TestCampaignDialogClearsName(t *testing.T) {
	start := strings.Index(intelHTML, "// ==== Campaigns and scripts")
	end := strings.Index(intelHTML, "// ==== end campaigns and scripts")
	block := intelHTML[start:end]
	for _, want := range []string{
		"actionButton('clear_name', 'clear name', { id: c.id }",
		"document.getElementById('cm-name').value = '';\n    campaignEdit(b.dataset.id || '', 'rename', '', '');",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("missing %q", want)
		}
	}
}

// A hung edit POST kept _cmFlight.n above zero, so every reload for that
// view deferred forever. The POST now aborts after 15 s and takes the normal
// failure path, which releases the flight count and reschedules the reload.
func TestCampaignEditFetchTimesOut(t *testing.T) {
	start := strings.Index(intelHTML, "async function campaignEdit(")
	end := strings.Index(intelHTML, "function closeCampaign(")
	if start < 0 || end < start {
		t.Fatal("campaignEdit not found")
	}
	fn := intelHTML[start:end]
	for _, want := range []string{"new AbortController()", "ctl.abort()", "signal: ctl.signal", "CAMPAIGN_EDIT_TIMEOUT_MS", "clearTimeout(abortTimer)"} {
		if !strings.Contains(fn, want) {
			t.Errorf("campaignEdit missing %q", want)
		}
	}
	if !strings.Contains(intelHTML, "const CAMPAIGN_EDIT_TIMEOUT_MS = 15000;") {
		t.Error("edit timeout constant missing")
	}
}
