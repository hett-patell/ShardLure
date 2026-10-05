package web

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// bazaarCandidatesJSBlock is the panel's candidates code in intel.html, from
// its section marker to the next section.
func bazaarCandidatesJSBlock(t *testing.T) string {
	t.Helper()
	js := inlineScripts(intelHTML)
	start := strings.Index(js, "// ---- MalwareBazaar candidates")
	end := strings.Index(js, "// ==== Widget functions")
	if start < 0 || end < start {
		t.Fatal("intel.html: MalwareBazaar candidates block not found")
	}
	return js[start:end]
}

// bazaarJSHarness is a minimal DOM for that block: elements created on first
// lookup, a recording fetch that answers every upload "inserted", confirm()
// always yes, and immediate timers.
const bazaarJSHarness = `
const els = {};
function el(id) {
  return { id, textContent: '', innerHTML: '', dataset: {}, style: {}, disabled: false,
    querySelectorAll() { return []; }, addEventListener() {} };
}
globalThis.document = {
  getElementById(id) { return (els[id] ||= el(id)); },
  querySelector(sel) { return (els[sel] ||= el(sel)); },
};
globalThis.window = { confirm: () => true };
globalThis.setTimeout = fn => { fn(); return 0; };
const posts = [];
globalThis.fetch = (url, opts) => {
  if (opts && opts.method === 'POST') posts.push(String(url));
  return Promise.resolve({ ok: true, json: async () => ({ status: 'inserted', mbUrl: 'https://bazaar.abuse.ch/sample/x/' }) });
};
var _bazaarSharedSet = {};
var _uploadAllRunning = false;
let refreshed = 0;
function refreshPayloads() { refreshed++; }
function openPayload() {}
function fmtBytesShort(n) { return n + 'B'; }
function fmtShortTime(s) { return s; }
`

func runBazaarJS(t *testing.T, scenario string) string {
	t.Helper()
	node := requireNode(t)
	helpers := pageHelperRe.FindAllString(intelHTML, -1)
	script := bazaarJSHarness + strings.Join(helpers, "\n") + "\n" + bazaarCandidatesJSBlock(t) +
		"\n(async () => {\n" + scenario + "\n})().catch(e => { console.error(e); process.exit(1); });\n"
	path := filepath.Join(t.TempDir(), "bazaar.js")
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

const hostileCandidates = `
const ELIG = 'aa' + '"><img src=x onerror=alert(1)>';
const cands = [
  { sha256: ELIG, sizeBytes: 900, fileKind: 'ELF', family: '<b>XMRig</b>', origin: 'quarantine_fetch', lastFetchAt: '2026-10-05T00:00:00Z', eligible: true },
  { sha256: 'bb', sizeBytes: 400, fileKind: 'SSH key', origin: '<i>cowrie</i>', eligible: false, reason: 'benign content (<script>x</script>)' },
];
`

// TestBazaarCandidatesRenderVetDecision drives the real renderer: every
// attacker-influenced field is escaped, only eligible rows get an Upload
// button, only when a key is configured, and rejected rows show Vet's reason.
func TestBazaarCandidatesRenderVetDecision(t *testing.T) {
	var out struct {
		Armed, Unarmed, Meta, AllBtn, AllBtnOff string
		Gate                                    map[string]string
	}
	decodeJS(t, runBazaarJS(t, hostileCandidates+`
  renderBazaarCandidates({ candidates: cands, candidatesTotal: 5, configured: true });
  const armed = document.querySelector('#bazaar-cand-table tbody').innerHTML;
  const meta = document.getElementById('bazaar-cand-meta').textContent;
  const allBtn = document.getElementById('bazaar-upload-all-btn').style.display;
  const gate = _bazaarGate;
  renderBazaarCandidates({ candidates: cands, candidatesTotal: 2, configured: false });
  const unarmed = document.querySelector('#bazaar-cand-table tbody').innerHTML;
  console.log(JSON.stringify({ Armed: armed, Unarmed: unarmed, Meta: meta, AllBtn: allBtn,
    AllBtnOff: document.getElementById('bazaar-upload-all-btn').style.display, Gate: gate }));
`), &out)

	for _, raw := range []string{"<img", "<b>", "<i>", "<script>"} {
		if strings.Contains(out.Armed, raw) {
			t.Errorf("unescaped %q in the candidates table:\n%s", raw, out.Armed)
		}
	}
	rows := strings.Split(out.Armed, "</tr>")
	if len(rows) < 2 || !strings.Contains(rows[0], "uploadBazaarCandidate") {
		t.Errorf("eligible row has no Upload button:\n%s", rows[0])
	}
	if len(rows) >= 2 && strings.Contains(rows[1], "uploadBazaarCandidate") {
		t.Errorf("rejected row got an Upload button:\n%s", rows[1])
	}
	// The hash opens the inspector, so it must be keyboard-reachable.
	if n := strings.Count(out.Armed, `<button type="button" class="bz-sha-btn"`); n != 2 {
		t.Errorf("%d hash buttons, want one per row (a click-only <td> is not keyboard operable)", n)
	}
	if n := strings.Count(out.Armed, "uploadBazaarCandidate"); n != 1 {
		t.Errorf("%d Upload buttons, want 1 (the eligible row only)", n)
	}
	if !strings.Contains(out.Armed, "benign content (&lt;script&gt;x&lt;/script&gt;)") {
		t.Error("rejected row does not show Vet's reason")
	}
	if strings.Contains(out.Unarmed, "uploadBazaarCandidate") {
		t.Error("Upload button rendered with no abuse.ch key configured")
	}
	if !strings.Contains(out.Meta, "1 eligible of 2") || !strings.Contains(out.Meta, "showing 2 of 5") {
		t.Errorf("meta does not disclose eligibility and truncation: %q", out.Meta)
	}
	if out.AllBtn != "" || out.AllBtnOff != "none" {
		t.Errorf("Upload-all visibility: armed=%q unarmed=%q, want shown then hidden", out.AllBtn, out.AllBtnOff)
	}
	if out.Gate["bb"] == "" || len(out.Gate) != 1 {
		t.Errorf("_bazaarGate (the library's reason label) = %v, want only the rejected sha", out.Gate)
	}
}

// TestBazaarPendingLabelDisclosesTruncation: pending counts eligible samples
// among the capped candidates only, so a truncated pool reads "N+".
func TestBazaarPendingLabelDisclosesTruncation(t *testing.T) {
	var out []string
	decodeJS(t, runBazaarJS(t, hostileCandidates+`
  console.log(JSON.stringify([
    bazaarPendingLabel({ stats: { pending: 1 }, candidates: cands, candidatesTotal: 2 }),
    bazaarPendingLabel({ stats: { pending: 1 }, candidates: cands, candidatesTotal: 250 }),
    bazaarPendingLabel({}),
  ]));
`), &out)
	if len(out) != 3 || out[0] != "1" || out[1] != "1+" || out[2] != "0" {
		t.Errorf("pending labels = %v, want [1 1+ 0]", out)
	}
}

// TestBazaarUploadAllSendsOnlyEligible pins that the batch button posts the
// eligible rows and nothing else (the server re-checks each with Vet anyway).
func TestBazaarUploadAllSendsOnlyEligible(t *testing.T) {
	var out struct {
		Posts     []string
		Refreshed int
	}
	decodeJS(t, runBazaarJS(t, hostileCandidates+`
  renderBazaarCandidates({ candidates: cands, candidatesTotal: 2, configured: true });
  await uploadAllBazaarCandidates(document.getElementById('bazaar-upload-all-btn'));
  console.log(JSON.stringify({ Posts: posts, Refreshed: refreshed }));
`), &out)
	if len(out.Posts) != 1 || !strings.Contains(out.Posts[0], "/api/intel/bazaar/upload?sha=aa") {
		t.Errorf("upload-all posted %v, want exactly the eligible sample", out.Posts)
	}
	if out.Refreshed != 1 {
		t.Errorf("refreshPayloads called %d times after the batch, want 1 (the single poll path)", out.Refreshed)
	}
}

// TestBazaarCandidatesPanelContract pins what node cannot see: the table
// markup, its phone breakpoint, and that the panel is fed by refreshPayloads'
// existing fetch rather than a poller of its own.
func TestBazaarCandidatesPanelContract(t *testing.T) {
	if !strings.Contains(intelHTML, `id="bazaar-cand-table"`) {
		t.Fatal("intel.html: #panel-bazaar has no candidates table")
	}
	phone := strings.Join(mediaBlocks(styleBlock(t, intelHTML), "(max-width: 760px)"), "\n")
	if !strings.Contains(phone, "#bazaar-cand-table { min-width: 860px; }") {
		t.Error("candidates table needs its own wider min-width in the 760px layout (six fixed columns take 592px)")
	}
	// Muting by opacity scales --dim below the 4.5:1 floor the tokens are sized to.
	if regexp.MustCompile(`#bazaar-cand-table[^{]*\{[^}]*opacity`).MatchString(styleBlock(t, intelHTML)) {
		t.Error("candidates table mutes rows with opacity; use the --dim token")
	}
	if !strings.Contains(inlineScripts(intelHTML), "textContent = bazaarPendingLabel(d)") {
		t.Error("the pending tile does not use bazaarPendingLabel")
	}
	js := inlineScripts(intelHTML)
	render := regexp.MustCompile(`(?s)\nfunction renderBazaar\(d\) \{.*?\n\}`).FindString(js)
	if !strings.Contains(render, "renderBazaarCandidates(d);") {
		t.Error("renderBazaar does not render the candidates")
	}
	if strings.Contains(bazaarCandidatesJSBlock(t), "pollEvery(") {
		t.Error("the candidates block added a poller; the panel must ride refreshPayloads")
	}
	// The single poll path: refreshPayloads fetches /api/intel/bazaar and hands
	// the response to renderBazaar on the Red tab's existing 30 s cadence.
	pay := regexp.MustCompile(`(?s)async function refreshPayloads\(\) \{.*?\n\}`).FindString(js)
	if !strings.Contains(pay, "/api/intel/bazaar?") || !strings.Contains(pay, "renderBazaar(bd)") {
		t.Error("refreshPayloads no longer feeds the bazaar panel")
	}
}
