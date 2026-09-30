package web

import (
	"strings"
	"testing"
)

// Behavioural tests for the campaign/script dialog state machine. Each runs
// the page's own campaign JS block under node (runCampaignJS, see
// campaign_node_harness_test.go) and asserts what the code does, not how its
// source is spelled (final audit M3: the earlier pins matched exact JS lines,
// so a reformat failed them and a broken edit that kept the lines passed).

const campaignJSCommon = `
  const ID = 'c-0123456789ab', TGT = 'c-ba9876543210';
  const campaignGets = () => requests.filter(r => r.method === 'GET' && r.url.startsWith('/api/intel/campaign?'))
    .map(r => decodeURIComponent(r.url.split('id=')[1].split('&')[0]));
  const status = () => document.getElementById('cm-status').textContent;
  const settle = async () => { for (let i = 0; i < 8; i++) await tick(); };
  const openDialog = () => { showCampaignDialog('campaign ' + ID); _cmRendered = { name: '', notes: '', merge: '' };
    for (const f of ['cm-name', 'cm-notes', 'cm-merge']) document.getElementById(f).value = ''; };
  const edit = async (action, arg, reply) => {
    if (action === 'notes') document.getElementById('cm-notes').value = arg;
    if (action === 'merge') document.getElementById('cm-merge').value = arg;
    const p = campaignEdit(ID, action, arg, arg); await tick(); pendingPost(reply); await p;
  };
  const click = dataset => listeners['campaign-modal:click'][0]({ target: { id: 'btn', closest: () => ({ dataset }) } });
`

// fix-D M4 re-review: an edit POST in flight when the dialog closes (Esc
// fires only the native 'close' event) must not park a hold reload or
// schedule a reload into the closed dialog when its reply lands.
func TestCampaignEditLandingAfterEscParksNothing(t *testing.T) {
	out := runCampaignJS(t, campaignJSCommon+`
  const out = {};
  for (const held of [true, false]) {
    openDialog();
    const p = campaignEdit(ID, 'notes', 'n', 'n');
    document.getElementById('campaign-modal').close(); // Esc
    await tick();                                      // the close event runs
    pendingPost(jsonReply({ applying: true, regroup: held ? { held: true, phase: 'settling' } : null }));
    await p;
    out[held ? 'held' : 'free'] = { open: document.getElementById('campaign-modal').open, cmHeld: _cmHeld, cmPending: _cmPending };
  }
  console.log(JSON.stringify(out));
`)
	var got map[string]struct {
		Open      bool `json:"open"`
		CmHeld    any  `json:"cmHeld"`
		CmPending any  `json:"cmPending"`
	}
	decodeJS(t, out, &got)
	for _, k := range []string{"held", "free"} {
		g, ok := got[k]
		if !ok || g.Open || g.CmHeld != nil || g.CmPending != nil {
			t.Errorf("%s: a reply landing after Esc touched the closed dialog: %+v", k, g)
		}
	}
}

// fix-D M4: Esc (the native close) runs the whole cleanup: the parked hold
// reload and the pending reload are dropped, the view is retired, and the
// lists still refresh once for the edit's result, without reopening anything.
func TestCampaignDialogEscRunsCloseCleanup(t *testing.T) {
	out := runCampaignJS(t, campaignJSCommon+`
  openDialog();
  await edit('notes', 'n', jsonReply({}));
  const hadPending = !!_cmPending;
  _cmHeld = { view: _cmView, target: { id: ID } };
  const view = _cmView;
  document.getElementById('campaign-modal').close();
  await tick();
  const res = { hadPending, pending: _cmPending, held: _cmHeld, retired: _cmView > view, reloads: liveTimers(6000) };
  const lists = requests.filter(r => r.url.startsWith('/api/intel/campaigns?')).length;
  fire(6000); await settle();
  res.listRefreshes = requests.filter(r => r.url.startsWith('/api/intel/campaigns?')).length - lists;
  res.reopened = campaignGets();
  console.log(JSON.stringify(res));
`)
	var got struct {
		HadPending    bool     `json:"hadPending"`
		Pending       any      `json:"pending"`
		Held          any      `json:"held"`
		Retired       bool     `json:"retired"`
		Reloads       int      `json:"reloads"`
		ListRefreshes int      `json:"listRefreshes"`
		Reopened      []string `json:"reopened"`
	}
	decodeJS(t, out, &got)
	if !got.HadPending || got.Pending != nil || got.Held != nil || !got.Retired || got.Reloads != 1 || got.ListRefreshes != 1 || len(got.Reopened) != 0 {
		t.Fatalf("Esc cleanup: %+v (%s)", got, out)
	}
}

// A hung edit POST kept _cmFlight.n above zero, so every reload of that view
// deferred forever. The POST aborts after CAMPAIGN_EDIT_TIMEOUT_MS and takes
// the failure path: the flight count is released, the status says it timed
// out, and the reload it deferred runs.
func TestCampaignEditFetchTimesOut(t *testing.T) {
	out := runCampaignJS(t, campaignJSCommon+`
  openDialog();
  await edit('notes', 'a', jsonReply({}));             // schedules the reload
  const p = campaignEdit(ID, 'notes', 'b', 'b');       // hangs
  await tick();
  fire(6000);                                          // the reload defers: a POST is in flight
  const deferred = campaignGets().length === 0 && _cmFlight.n === 1;
  fire(CAMPAIGN_EDIT_TIMEOUT_MS);                      // the abort
  await p;
  const res = { deferred, status: status(), flight: _cmFlight.n, rescheduled: liveTimers(6000), timeout: CAMPAIGN_EDIT_TIMEOUT_MS };
  fire(6000); await settle();
  res.reopened = campaignGets();
  console.log(JSON.stringify(res));
`)
	var got struct {
		Deferred    bool     `json:"deferred"`
		Status      string   `json:"status"`
		Flight      int      `json:"flight"`
		Rescheduled int      `json:"rescheduled"`
		Timeout     int      `json:"timeout"`
		Reopened    []string `json:"reopened"`
	}
	decodeJS(t, out, &got)
	if got.Timeout != 15000 || !got.Deferred || got.Flight != 0 || got.Rescheduled != 1 ||
		!strings.HasPrefix(got.Status, "edit timed out after 15 s") || len(got.Reopened) != 1 || got.Reopened[0] != "c-0123456789ab" {
		t.Fatalf("timed-out edit: %+v", got)
	}
}

// A merge followed by another edit before the reload: the pending merge
// target wins (the source ID has been merged away), carried as the object
// the reload reads, so the reload opens the target. Assigning the bare ID
// string once lost it and left the dialog on the merged-away source.
func TestCampaignReloadKeepsMergeTarget(t *testing.T) {
	out := runCampaignJS(t, campaignJSCommon+`
  openDialog();
  await edit('merge', TGT, jsonReply({}));
  await edit('notes', 'n', jsonReply({}));
  const res = { target: _cmPending.target, merged: _cmPending.merged, reloads: liveTimers(6000) };
  replyGet = () => jsonReply({ id: TGT, members: [] });
  fire(6000); await settle();
  res.opened = campaignGets();
  console.log(JSON.stringify(res));
`)
	var got struct {
		Target  string   `json:"target"`
		Merged  bool     `json:"merged"`
		Reloads int      `json:"reloads"`
		Opened  []string `json:"opened"`
	}
	decodeJS(t, out, &got)
	if got.Target != "c-ba9876543210" || !got.Merged || got.Reloads != 1 || len(got.Opened) != 1 || got.Opened[0] != "c-ba9876543210" {
		t.Fatalf("merge target lost: %+v", got)
	}
}

// "clear name" records an empty rename and empties the field only once the
// server accepted it; a refused clear leaves the field (and the name) as it
// was, so nothing is lost and the reload is not blocked as unsaved typing.
func TestCampaignDialogClearsName(t *testing.T) {
	out := runCampaignJS(t, campaignJSCommon+`
  const res = {};
  for (const ok of [true, false]) {
    openDialog();
    document.getElementById('cm-name').value = 'Outlaw';
    _cmRendered.name = 'Outlaw';
    click({ action: 'clear_name', id: ID });
    await tick();
    const body = requests[requests.length - 1].body;
    pendingPost(ok ? jsonReply({}) : { ok: false, status: 400, text: async () => 'nope' });
    await settle();
    res[ok ? 'ok' : 'refused'] = { body, field: document.getElementById('cm-name').value, rendered: _cmRendered.name, status: status(), dirty: cmDirty() };
  }
  console.log(JSON.stringify(res));
`)
	type result struct {
		Body, Field, Rendered, Status string
		Dirty                         bool
	}
	var got map[string]result
	decodeJS(t, out, &got)
	if g := got["ok"]; g.Body != "id=c-0123456789ab&action=rename&arg=" || g.Field != "" || g.Rendered != "" || g.Dirty || g.Status != "applying…" {
		t.Errorf("accepted clear: %+v", g)
	}
	if g := got["refused"]; g.Field != "Outlaw" || g.Rendered != "Outlaw" || g.Status != "edit refused: nope (400)" {
		t.Errorf("refused clear: %+v", g)
	}
}

// During a script-rebuild hold the edit response carries regroup.held: the
// dialog says why the edit has not applied and parks its reload (no 6 s
// timer); the list poll keeps it parked while the hold lasts and releases it
// once the hold ends, and the released reload reopens the campaign.
func TestCampaignDialogExplainsRegroupHold(t *testing.T) {
	out := runCampaignJS(t, campaignJSCommon+`
  openDialog();
  await edit('notes', 'n', jsonReply({ applying: true, regroup: { held: true, phase: 'settling' } }));
  const res = { held: { status: status(), parked: _cmHeld && _cmHeld.target.id, reloads: liveTimers(6000) } };
  replyGet = () => jsonReply({ campaigns: [], total: 0, regroup: { held: true, phase: 'recording', progress: 0.5 } });
  await refreshCampaigns();
  res.still = { status: status(), parked: _cmHeld && _cmHeld.target.id, reloads: liveTimers(6000), meta: document.getElementById('campaigns-meta').textContent };
  replyGet = url => url.startsWith('/api/intel/campaigns?') ? jsonReply({ campaigns: [], total: 0, regroup: { held: false } }) : jsonReply({ id: ID, members: [] });
  await refreshCampaigns();
  res.released = { status: status(), parked: _cmHeld && _cmHeld.target.id, reloads: liveTimers(6000) };
  fire(6000); await settle();
  res.opened = campaignGets();
  console.log(JSON.stringify(res));
`)
	type phase struct {
		Status  string `json:"status"`
		Parked  string `json:"parked"`
		Reloads int    `json:"reloads"`
		Meta    string `json:"meta"`
	}
	var got struct {
		Held, Still, Released phase
		Opened                []string
	}
	decodeJS(t, out, &got)
	if got.Held.Status != "recorded — campaigns are waiting for a script rebuild (settling); your edit applies then" || got.Held.Parked != "c-0123456789ab" || got.Held.Reloads != 0 {
		t.Errorf("parked: %+v", got.Held)
	}
	if !strings.Contains(got.Still.Status, "(recording 50%)") || got.Still.Parked == "" || got.Still.Reloads != 0 ||
		got.Still.Meta != "0 campaigns · campaigns are waiting for a script rebuild (recording 50%)" {
		t.Errorf("still held: %+v", got.Still)
	}
	if got.Released.Status != "applying…" || got.Released.Parked != "" || got.Released.Reloads != 1 {
		t.Errorf("released: %+v", got.Released)
	}
	if len(got.Opened) != 1 || got.Opened[0] != "c-0123456789ab" {
		t.Errorf("released reload opened %v", got.Opened)
	}
	// The hold text names neither an upgrade nor a manual rebuild (fix-D M6).
	for _, s := range []string{got.Held.Status, got.Still.Status} {
		if strings.Contains(s, "upgrade") {
			t.Errorf("hold note blames an upgrade: %q", s)
		}
	}
}

// The campaign dialog discloses every capped list ("showing N of M") and a
// list at its total shows no note.
func TestCampaignDialogDisclosesCaps(t *testing.T) {
	out := runCampaignJS(t, campaignJSCommon+`
  replyGet = () => jsonReply({ id: ID, members: [{ actorId: 'cowrie:a', reasons: [] }], membersTotal: 600,
    hasshes: ['h1'], hasshesTotal: 3, clients: ['SSH-2.0-x'], clientsTotal: 1, hosts: ['198.51.100.7'], hostsTotal: 9 });
  await openCampaign(ID);
  console.log(JSON.stringify({ body: document.getElementById('cm-body').innerHTML }));
`)
	var got struct{ Body string }
	decodeJS(t, out, &got)
	for _, want := range []string{
		`members <span class="cm-more">(showing 1 of 600)</span>`,
		`<b>HASSH:</b> h1 <span class="cm-more">(showing 1 of 3)</span>`,
		`<b>clients:</b> SSH-2.0-x</div>`,
		`<b>download hosts:</b> 198.51.100.7 <span class="cm-more">(showing 1 of 9)</span>`,
	} {
		if !strings.Contains(got.Body, want) {
			t.Errorf("dialog body missing %q", want)
		}
	}
}

// Rows open through a real first-cell button (not a focusable <tr> with an
// aria-label), attacker-chosen names render as text, and a click anywhere on
// the row opens it through the one delegated listener.
func TestCampaignRowsOpenThroughAButton(t *testing.T) {
	out := runCampaignJS(t, campaignJSCommon+`
  replyGet = url => url.startsWith('/api/intel/campaigns?')
    ? jsonReply({ campaigns: [{ id: ID, name: '<img src=x onerror=alert(1)>', kinds: ['ssh_key'] }], total: 1 })
    : jsonReply({ families: [{ family: 'f'.repeat(64), display: '<svg onload=alert(2)>\nx', variants: [] }], total: 1 });
  await refreshCampaigns(); await refreshScripts();
  const res = { campaigns: document.querySelector('#campaigns-table tbody').innerHTML, scripts: document.querySelector('#scripts-table tbody').innerHTML };
  listeners['#campaigns-table tbody:click'][0]({ target: { closest: () => ({ getAttribute: () => ID }) } });
  await settle();
  res.opened = campaignGets();
  console.log(JSON.stringify(res));
`)
	var got struct {
		Campaigns, Scripts string
		Opened             []string
	}
	decodeJS(t, out, &got)
	if !strings.Contains(got.Campaigns, `<tr data-campaign="c-0123456789ab"><td><button type="button" class="row-open">&lt;img src=x onerror=alert(1)&gt;</button></td>`) {
		t.Errorf("campaign row: %s", got.Campaigns)
	}
	if !strings.Contains(got.Scripts, `<td><button type="button" class="row-open"><code>&lt;svg onload=alert(2)&gt;</code></button></td>`) {
		t.Errorf("script row: %s", got.Scripts)
	}
	for _, s := range []string{got.Campaigns, got.Scripts} {
		if strings.Contains(s, "tabindex") || strings.Contains(s, "aria-label") {
			t.Errorf("row is still a focusable <tr> with an aria-label override: %s", s)
		}
	}
	if len(got.Opened) != 1 || got.Opened[0] != "c-0123456789ab" {
		t.Errorf("row click opened %v", got.Opened)
	}
}

// The scripts panel is empty for the 10-30 minutes of a script rebuild: it
// explains the hold in the meta line and the empty-table row instead of a
// blank table that reads as data loss.
func TestScriptsPanelExplainsRebuild(t *testing.T) {
	out := runCampaignJS(t, campaignJSCommon+`
  const res = {};
  for (const held of [true, false]) {
    replyGet = () => jsonReply({ families: [], total: 0, regroup: held ? { held: true, phase: 'settling' } : null });
    await refreshScripts();
    res[held ? 'held' : 'free'] = { meta: document.getElementById('scripts-meta').textContent, body: document.querySelector('#scripts-table tbody').innerHTML };
  }
  console.log(JSON.stringify(res));
`)
	var got map[string]struct{ Meta, Body string }
	decodeJS(t, out, &got)
	if g := got["held"]; g.Meta != "0 script families · campaigns are waiting for a script rebuild (settling)" ||
		!strings.Contains(g.Body, "scripts are being rebuilt; families return when the rebuilt scripts settle (settling)") {
		t.Errorf("held: %+v", g)
	}
	if g := got["free"]; g.Meta != "0 script families" || !strings.Contains(g.Body, "no settled scripts yet") {
		t.Errorf("free: %+v", g)
	}
}

// fix-D I1: a Scripts row counts the whole family but its dialog lists one
// fingerprint's sessions. The dialog says which ("this variant: N of M
// family sessions"), lists every other variant as an openable button (the
// shown one as plain text), discloses a capped session list, and a variant
// button opens that variant.
func TestScriptDialogReachesEveryVariant(t *testing.T) {
	out := runCampaignJS(t, campaignJSCommon+`
  const fp = n => String(n).repeat(64);
  replyGet = () => jsonReply({ fingerprint: fp(2), family: fp(1), display: 'cd /tmp', sessions: [{ sessionId: 's1', actorId: 'cowrie:a', srcIp: '198.51.100.1' }],
    sessionsTotal: 4, actors: ['cowrie:a'], familySessions: 13, familyActors: 3,
    variants: [{ fingerprint: fp(1), sessions: 9 }, { fingerprint: fp(2), sessions: 4 }], variantsTotal: 2 });
  await openScript(fp(2));
  const res = { sub: document.getElementById('cm-sub').textContent, body: document.getElementById('cm-body').innerHTML };
  click({ action: 'script', fp: fp(1) });
  await settle();
  res.fetched = requests.filter(r => r.url.startsWith('/api/intel/script?')).map(r => r.url.split('fp=')[1].split('&')[0]);
  console.log(JSON.stringify(res));
`)
	var got struct {
		Sub, Body string
		Fetched   []string
	}
	decodeJS(t, out, &got)
	one, two := strings.Repeat("1", 64), strings.Repeat("2", 64)
	if got.Sub != "this variant: 4 of 13 family sessions · family: 2 variants, 3 actors" {
		t.Errorf("sub = %q", got.Sub)
	}
	for _, want := range []string{
		`data-action="script" data-fp="` + one + `" aria-label="open script variant 111111111111">1111111111111111</button></td><td class="num">9 sessions</td><td>representative</td>`,
		`<code>2222222222222222</code></td><td class="num">4 sessions</td><td>shown</td>`,
		`sessions of this variant <span class="cm-more">(showing 1 of 4)</span>`,
	} {
		if !strings.Contains(got.Body, want) {
			t.Errorf("dialog body missing %q", want)
		}
	}
	if len(got.Fetched) != 2 || got.Fetched[0] != two || got.Fetched[1] != one {
		t.Errorf("variant button fetched %v", got.Fetched)
	}
}
