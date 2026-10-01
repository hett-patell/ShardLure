package web

import (
	"regexp"
	"strings"
	"testing"
)

// The campaign/script dialog's behaviour is tested by running the page's JS
// under node (campaign_dialog_node_test.go). What stays here is structure
// node cannot see: the markup, the CSS a browser lays out, and page-wide
// contracts from CLAUDE.md.

func campaignJSBlock(t *testing.T) string {
	t.Helper()
	start := strings.Index(intelHTML, "// ==== Campaigns and scripts")
	end := strings.Index(intelHTML, "// ==== end campaigns and scripts")
	if start < 0 || end < start {
		t.Fatal("campaign JS block markers missing")
	}
	return intelHTML[start:end]
}

func TestCampaignPanelsFollowFrontendContracts(t *testing.T) {
	for _, id := range []string{`id="panel-campaigns"`, `id="panel-scripts"`, `id="campaigns-table"`, `id="scripts-table"`, `id="cm-close"`} {
		if !strings.Contains(intelHTML, id) {
			t.Errorf("missing %s", id)
		}
	}
	if !regexp.MustCompile(`<dialog class="sess-modal" id="campaign-modal" aria-labelledby="cm-title">\s*<div class="sm-card">`).MatchString(intelHTML) {
		t.Error("campaign detail must reuse the labelled sess-modal dialog markup")
	}
	block := campaignJSBlock(t)
	if strings.Contains(block, "onclick") || strings.Contains(block, "onkeydown") {
		t.Error("campaign JS must use data-* attributes and delegated listeners, not inline handlers")
	}
	// The regroup-hold re-check rides the existing list poll: one timer only.
	if strings.Count(intelHTML, "setInterval(") != 1 {
		t.Error("intel.html must keep exactly one setInterval (inside pollEvery)")
	}
	// rowOpens relies on the first-cell button's native keyboard activation.
	rs := strings.Index(block, "function rowOpens(")
	re := strings.Index(block[rs:], "\n}\n")
	if rs < 0 || re < 0 || strings.Contains(block[rs:rs+re], "keydown") {
		t.Error("rowOpens must rely on the button's native keyboard activation")
	}
	if !strings.Contains(intelHTML, ".row-open {") {
		t.Error(".row-open style missing")
	}
}

// At 760 px the member table outgrew the dialog (a 39-character actor ID has
// no break opportunity under overflow-wrap:break-word) and pushed "remove"
// off-screen. The ID and reason cells wrap anywhere and the action cell stays
// whole. Layout is a browser property (checked there); the rules and the cell
// classes they target are pinned here.
func TestCampaignDialogFitsAt760(t *testing.T) {
	for _, want := range []string{
		".cm-table td.cm-wrap { overflow-wrap: anywhere; }",
		".cm-table td.cm-nw, .cm-table td.cm-act { white-space: nowrap; }",
	} {
		if !strings.Contains(intelHTML, want) {
			t.Errorf("missing %q", want)
		}
	}
	block := campaignJSBlock(t)
	for _, cls := range []string{`class="cm-wrap"`, `class="cm-nw"`, `class="cm-act"`} {
		if !strings.Contains(block, cls) {
			t.Errorf("campaign rows no longer carry %s", cls)
		}
	}
}

// The command palette (outside the campaign block, so outside the node
// harness) finds a script by any listed variant's fingerprint, by prefix and
// only for a hex query of 8+ characters; plain text searches the display.
func TestPaletteFindsScriptVariants(t *testing.T) {
	for _, want := range []string{
		"var vfps = (f.variants || []).map(function (v) { return String(v.fingerprint || ''); });",
		"action: function () { setActiveView('red'); openScript(fp); closePalette(); }",
		"var fpQuery = /^[0-9a-f]{8,64}$/.test(q);",
		"filter(function (v) { return v.indexOf(q) === 0; })[0];",
	} {
		if !strings.Contains(intelHTML, want) {
			t.Errorf("palette missing %q", want)
		}
	}
	if strings.Contains(intelHTML, "vfps.join(' ')") || strings.Contains(intelHTML, "return v.indexOf(q) >= 0; })[0] || f.family") {
		t.Error("the palette still substring-matches fingerprints")
	}
}
