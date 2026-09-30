package web

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// campaignJSHarness is a minimal DOM for the page's campaign/script JS block,
// so tests drive the real code instead of pinning its source text: elements
// created on first lookup, a <dialog> whose close() fires 'close'
// asynchronously like the browser's, a recording fetch whose GET replies a
// scenario sets (replyGet) and whose POSTs stay pending until the scenario
// resolves them (pendingPost) or their AbortSignal fires, and manual timers
// (fire(ms) runs every live timer of that delay once). esc and fmt are the
// page's own definitions, prepended by runCampaignJS.
const campaignJSHarness = `
const listeners = {};
function el(id) {
  return { id, open: false, textContent: '', innerHTML: '', value: '', dataset: {},
    addEventListener(type, fn) { (listeners[id + ':' + type] ||= []).push(fn); },
    showModal() { this.open = true; },
    close() { this.open = false; setImmediate(() => (listeners[id + ':close'] || []).forEach(fn => fn({}))); },
    closest() { return null; }, querySelector() { return null; }, getAttribute() { return null; } };
}
const els = {};
globalThis.document = {
  getElementById(id) { return (els[id] ||= el(id)); },
  querySelector(sel) { return (els[sel] ||= el(sel)); },
};
const timers = [];
globalThis.setTimeout = (fn, ms) => { timers.push({ fn, ms, done: false }); return timers.length; };
globalThis.clearTimeout = id => { if (timers[id - 1]) timers[id - 1].done = true; };
globalThis.liveTimers = ms => timers.filter(t => !t.done && t.ms === ms).length;
globalThis.fire = ms => { for (const t of timers.slice()) if (!t.done && t.ms === ms) { t.done = true; t.fn(); } };
globalThis.tick = () => new Promise(r => setImmediate(r));
const requests = [];
let pendingPost = null;
globalThis.replyGet = () => ({ ok: false, status: 503, text: async () => '' });
globalThis.jsonReply = body => ({ ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) });
globalThis.fetch = (url, opts) => {
  const method = (opts && opts.method) || 'GET';
  requests.push({ url: String(url), method, body: opts && opts.body ? String(opts.body) : '' });
  if (method === 'POST') return new Promise((res, rej) => {
    pendingPost = res;
    if (opts.signal) opts.signal.addEventListener('abort', () => { const e = new Error('aborted'); e.name = 'AbortError'; rej(e); });
  });
  return Promise.resolve(replyGet(String(url)));
};
`

var pageHelperRe = regexp.MustCompile(`(?m)^const (ESC_MAP|esc|fmt) = .*$`)

// requireNode returns node's path. Without it the behavioural tests skip
// loudly; under CI (CI is set on GitHub Actions) a missing node fails, so the
// suite can never pass there with these tests silently not run.
func requireNode(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err == nil {
		return node
	}
	if os.Getenv("CI") != "" {
		t.Fatal("node not found on PATH with CI set: the campaign/script JS behaviour tests must run in CI (add actions/setup-node)")
	}
	t.Skip("SKIPPED: node not found on PATH, so the campaign/script JS behaviour tests did NOT run; install node (18+) to run them")
	return ""
}

// runCampaignJS runs the harness, the page's esc/fmt, the campaign JS block
// and scenario (the body of an async function) under node, and returns the
// last line the scenario printed.
func runCampaignJS(t *testing.T, scenario string) string {
	t.Helper()
	node := requireNode(t)
	start := strings.Index(intelHTML, "// ==== Campaigns and scripts")
	end := strings.Index(intelHTML, "// ==== end campaigns and scripts")
	if start < 0 || end < start {
		t.Fatal("campaign JS block markers missing")
	}
	helpers := pageHelperRe.FindAllString(intelHTML, -1)
	if len(helpers) != 3 {
		t.Fatalf("page esc/fmt definitions: found %d of 3", len(helpers))
	}
	script := campaignJSHarness + strings.Join(helpers, "\n") + "\n" + intelHTML[start:end] +
		"\n(async () => {\n" + scenario + "\n})().catch(e => { console.error(e); process.exit(1); });\n"
	path := filepath.Join(t.TempDir(), "harness.js")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := exec.Command(node, path).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, raw)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	return lines[len(lines)-1]
}

func decodeJS(t *testing.T, out string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(out), v); err != nil {
		t.Fatalf("harness output %q: %v", out, err)
	}
}
