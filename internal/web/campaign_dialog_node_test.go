package web

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// campaignDialogHarness is a minimal DOM for the campaign/script JS block: just
// enough elements, a <dialog> whose close() fires 'close' asynchronously like
// the browser's, a controllable fetch and inert timers.
const campaignDialogHarness = `
const listeners = {};
function el(id) {
  return { id, open: false, textContent: '', innerHTML: '', value: '', dataset: {},
    addEventListener(type, fn) { (listeners[id + ':' + type] ||= []).push(fn); },
    showModal() { this.open = true; },
    close() { this.open = false; setImmediate(() => (listeners[id + ':close'] || []).forEach(fn => fn({}))); },
    closest() { return null; }, querySelector() { return null; } };
}
const els = {};
globalThis.document = {
  getElementById(id) { return (els[id] ||= el(id)); },
  querySelector(sel) { return (els[sel] ||= el(sel)); },
};
globalThis.esc = s => String(s == null ? '' : s);
globalThis.fmt = n => String(n);
const timers = [];
globalThis.setTimeout = (fn, ms) => { timers.push({ fn, ms }); return timers.length; };
globalThis.clearTimeout = () => {};
let pendingPost = null;
globalThis.fetch = (url, opts) => {
  if (opts && opts.method === 'POST') return new Promise(res => { pendingPost = res; });
  return Promise.resolve({ ok: false, status: 503, text: async () => '' });
};
`

// TestCampaignEditLandingAfterEscParksNothing pins the re-review of fix-D M4:
// an edit POST in flight when the dialog closes (Esc fires only the native
// 'close' event) must not park a hold reload or schedule a reload into the
// closed dialog when its reply lands. Runs the page's own JS under node.
func TestCampaignEditLandingAfterEscParksNothing(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	start := strings.Index(intelHTML, "// ==== Campaigns and scripts")
	end := strings.Index(intelHTML, "// ==== end campaigns and scripts")
	if start < 0 || end < start {
		t.Fatal("campaign JS block markers missing")
	}
	scenario := `
(async () => {
  const out = {};
  for (const held of [true, false]) {
    showCampaignDialog('campaign c-0123456789ab');
    _cmRendered = { name: '', notes: '', merge: '' };
    const edit = campaignEdit('c-0123456789ab', 'notes', 'n', 'n');
    document.getElementById('campaign-modal').close(); // Esc
    await new Promise(r => setImmediate(r));           // the close event runs
    pendingPost({ ok: true, status: 200, json: async () => ({ applying: true, regroup: held ? { held: true, phase: 'settling' } : null }) });
    await edit;
    out[held ? 'held' : 'free'] = { open: document.getElementById('campaign-modal').open, cmHeld: _cmHeld, cmPending: _cmPending };
  }
  console.log(JSON.stringify(out));
})().catch(e => { console.error(e); process.exit(1); });
`
	script := campaignDialogHarness + intelHTML[start:end] + scenario
	path := filepath.Join(t.TempDir(), "harness.js")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := exec.Command(node, path).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, raw)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var got map[string]struct {
		Open      bool `json:"open"`
		CmHeld    any  `json:"cmHeld"`
		CmPending any  `json:"cmPending"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &got); err != nil {
		t.Fatalf("harness output %q: %v", raw, err)
	}
	for _, k := range []string{"held", "free"} {
		g, ok := got[k]
		if !ok || g.Open || g.CmHeld != nil || g.CmPending != nil {
			t.Errorf("%s: a reply landing after Esc touched the closed dialog: %+v", k, g)
		}
	}
}
