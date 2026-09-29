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
	// The scripts panel is empty for the 10-30 minutes of a script rebuild
	// (families are deleted first and rebuilt by the first regroup after the
	// hold): it must render the server's regroup block as an explanation, in
	// both the meta line and the empty-table row, not a blank table.
	fs := strings.Index(block, "function refreshScripts")
	fe := strings.Index(block[fs:], "\n}\n")
	if fs < 0 || fe < 0 {
		t.Fatal("refreshScripts body not found")
	}
	body := block[fs : fs+fe]
	for _, want := range []string{"d.regroup", "regroupText(d.regroup)", "regroupWhen(d.regroup)", "noteRegroup(d.regroup)", "scripts are being rebuilt", "no settled scripts yet"} {
		if !strings.Contains(body, want) {
			t.Errorf("refreshScripts does not carry %q", want)
		}
	}
	if strings.Contains(body, "regroupText(d.regroup) + '</td>") || !strings.Contains(body, "esc('scripts are being rebuilt") {
		t.Error("the rebuild note must go through esc() before innerHTML")
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

// The dialog offers "clear name" (an empty rename) and empties the field only
// once the clear succeeded, so a refused or timed-out clear leaves the field
// as it was and a successful one does not block the reload as unsaved typing.
// Asserted as text: there is no JS harness.
func TestCampaignDialogClearsName(t *testing.T) {
	start := strings.Index(intelHTML, "// ==== Campaigns and scripts")
	end := strings.Index(intelHTML, "// ==== end campaigns and scripts")
	block := intelHTML[start:end]
	for _, want := range []string{
		"actionButton('clear_name', 'clear name', { id: c.id }",
		"if (saved === '' && n && n.value === _cmRendered.name) n.value = '';",
		"    campaignEdit(b.dataset.id || '', 'rename', '', '');\n    return;",
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

// At 760 px the member table outgrew the dialog (a 39-character actor ID has
// no break opportunity under overflow-wrap:break-word) and pushed "remove"
// off-screen. The ID and reason cells now wrap anywhere and the action cell
// stays whole; checked in a browser, pinned here as text. Capped lists say
// "showing N of M" from the API's totals.
func TestCampaignDialogFitsAndDisclosesCaps(t *testing.T) {
	for _, want := range []string{
		".cm-table td.cm-wrap { overflow-wrap: anywhere; }",
		".cm-table td.cm-nw, .cm-table td.cm-act { white-space: nowrap; }",
		`'<tr><td class="cm-wrap">' + actionButton('actor'`,
		`'</td><td class="cm-act">' +` + "\n      actionButton('remove_actor'",
		"ofTotal((c.members || []).length, c.membersTotal)",
		"['HASSH', c.hasshes, c.hasshesTotal], ['clients', c.clients, c.clientsTotal], ['download hosts', c.hosts, c.hostsTotal]",
	} {
		if !strings.Contains(intelHTML, want) {
			t.Errorf("missing %q", want)
		}
	}
}

// During a script-rebuild hold the edit response and the list carry
// regroup.held; the dialog must say why the edit has not applied, park its
// 6 s reload, and release it from the list poll once the hold ends.
func TestCampaignDialogExplainsRegroupHold(t *testing.T) {
	start := strings.Index(intelHTML, "// ==== Campaigns and scripts")
	end := strings.Index(intelHTML, "// ==== end campaigns and scripts")
	block := intelHTML[start:end]
	for _, want := range []string{
		// fix-D M6: the hold follows an upgrade or a manual
		// `scripts --rebuild`, so the note names neither.
		"'campaigns are waiting for a script rebuild (' + regroupWhen(g) + ')'",
		"'recorded — ' + regroupText(g) + '; your edit applies then'",
		"if (regroup && regroup.held) {",
		"noteRegroup(d.regroup);",
		"scheduleCampaignReload(h.view, h.target);",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Count(intelHTML, "setInterval(") != 1 {
		t.Error("the hold re-check must ride the existing list poll, not a new timer")
	}
	if strings.Contains(block, "after an upgrade (") || strings.Contains(block, "rebuilding after an upgrade") {
		t.Error("the rebuild note still blames an upgrade; a manual --rebuild holds too")
	}
}

// fix-D M4: Esc closes a native <dialog> without calling closeCampaign, so the
// cleanup (drop the parked hold reload, cancel the pending reload but still
// refresh the lists) hangs off the dialog's 'close' event, which every close
// path fires, and closeCampaign only closes.
func TestCampaignDialogEscRunsCloseCleanup(t *testing.T) {
	start := strings.Index(intelHTML, "function campaignDialogClosed(")
	end := strings.Index(intelHTML, "document.getElementById('cm-close')")
	if start < 0 || end < start {
		t.Fatal("campaignDialogClosed not found before the close-button listener")
	}
	fn := intelHTML[start:end]
	for _, want := range []string{
		"if (document.getElementById('campaign-modal').open) return;",
		"_cmHeld = null;",
		"clearTimeout(_cmPending.timer);",
		"if (m.open) m.close(); // fires 'close' -> campaignDialogClosed",
		"document.getElementById('campaign-modal').addEventListener('close', campaignDialogClosed);",
	} {
		if !strings.Contains(fn, want) {
			t.Errorf("missing %q", want)
		}
	}
}

// fix-D M5: the clickable Campaigns/Scripts rows were <tr tabindex="0"
// aria-label>, announced as rows (not controls) with the label hiding the
// cell text. Each row's first cell is now a real button; the row stays
// clickable through the one delegated listener, and no keydown shim remains.
func TestCampaignRowsOpenThroughAButton(t *testing.T) {
	start := strings.Index(intelHTML, "// ==== Campaigns and scripts")
	end := strings.Index(intelHTML, "// ==== end campaigns and scripts")
	block := intelHTML[start:end]
	if strings.Contains(block, `<tr tabindex="0"`) || strings.Contains(block, `aria-label="open campaign`) || strings.Contains(block, `aria-label="open script `) {
		t.Error("a clickable row is still a focusable <tr> with an aria-label override")
	}
	for _, want := range []string{
		`'<td><button type="button" class="row-open">' + esc(name) + '</button></td>`,
		`'<td><button type="button" class="row-open"><code>' + esc(first) + '</code></button></td>`,
	} {
		if !strings.Contains(block, want) {
			t.Errorf("missing %q", want)
		}
	}
	rs := strings.Index(block, "function rowOpens(")
	re := strings.Index(block[rs:], "\n}\n")
	if rs < 0 || re < 0 || strings.Contains(block[rs:rs+re], "keydown") {
		t.Error("rowOpens must rely on the button's native keyboard activation")
	}
	if !strings.Contains(intelHTML, ".row-open {") {
		t.Error(".row-open style missing")
	}
}

// fix-D I1: a Scripts row counts the whole family but its dialog lists one
// fingerprint's sessions. The dialog says which ("this variant: N of M family
// sessions"), lists every variant with its session count as an openable
// button, discloses a capped session list, and the palette finds a script by
// any variant's fingerprint.
func TestScriptDialogReachesEveryVariant(t *testing.T) {
	start := strings.Index(intelHTML, "async function openScript(")
	end := strings.Index(intelHTML[start:], "\n}\n")
	if start < 0 || end < 0 {
		t.Fatal("openScript not found")
	}
	fn := intelHTML[start : start+end]
	for _, want := range []string{
		"'this variant: ' + fmt(total) + ' of ' + fmt(d.familySessions) + ' family sessions",
		"actionButton('script', fp.slice(0, 16), { fp: fp }, 'open script variant ' + fp.slice(0, 12))",
		"variants in this family",
		"ofTotal(shown, total)",
		"esc(fmt(v.sessions || 0))",
	} {
		if !strings.Contains(fn, want) {
			t.Errorf("openScript missing %q", want)
		}
	}
	for _, want := range []string{
		"var vfps = (f.variants || []).map(function (v) { return String(v.fingerprint || ''); });",
		"action: function () { setActiveView('red'); openScript(fp); closePalette(); }",
		// Re-review: fingerprints match only a hex query of 8+ characters,
		// by prefix; plain text searches the display only.
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
