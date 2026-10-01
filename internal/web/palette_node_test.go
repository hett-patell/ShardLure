package web

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// paletteJS returns intel.html's buildPalette function, which lives outside
// the campaign block the node harness loads.
func paletteJS(t *testing.T) string {
	t.Helper()
	start := strings.Index(intelHTML, "function buildPalette(q) {")
	if start < 0 {
		t.Fatal("buildPalette not found")
	}
	end := strings.Index(intelHTML[start:], "\n}\n")
	if end < 0 {
		t.Fatal("buildPalette end not found")
	}
	return intelHTML[start : start+end+2]
}

// Final re-review, web item 2: the list carries each family's 50 largest
// variants, so the palette could not find a variant ranked below that. A
// full fingerprint now always opens (the dialog resolves any fingerprint
// server-side), a listed prefix still opens its variant, and an unlisted
// prefix states the limit instead of reading as "no such script".
func TestPaletteReachesUnlistedVariants(t *testing.T) {
	node := requireNode(t)
	listed := strings.Repeat("a", 64)
	variant := "b" + strings.Repeat("1", 63)
	unlisted := "c" + strings.Repeat("2", 63)
	script := `var _lastIntel = null, _lastSessions = [], _lastPayloads = [], _lastCampaigns = [];
var opened = [];
function setActiveView() {}
function closePalette() {}
function openScript(fp) { opened.push(fp); }
function campaignDisplayName(c) { return c.id; }
var _lastScripts = [{ family: '` + listed + `', display: 'wget x', sessions: 3, variants: [{ fingerprint: '` + listed + `' }, { fingerprint: '` + variant + `' }] }];
` + paletteJS(t) + `
function run(q) { var items = buildPalette(q).filter(function (i) { return i.group === 'Scripts'; }); items.forEach(function (i) { i.action(); }); return items.map(function (i) { return i.label; }); }
var out = {};
out.full = run('` + unlisted + `'); out.fullOpened = opened.slice(); opened = [];
out.listed = run('` + variant[:12] + `'); out.listedOpened = opened.slice(); opened = [];
out.prefix = run('` + unlisted[:12] + `'); out.prefixOpened = opened.slice(); opened = [];
out.fullListed = run('` + variant + `'); out.fullListedOpened = opened.slice();
console.log(JSON.stringify(out));
`
	path := filepath.Join(t.TempDir(), "palette.js")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := exec.Command(node, path).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, raw)
	}
	var got struct {
		Full, FullOpened, Listed, ListedOpened, Prefix, PrefixOpened, FullListed, FullListedOpened []string
	}
	decodeJS(t, strings.TrimSpace(string(raw)), &got)
	if len(got.FullOpened) != 1 || got.FullOpened[0] != unlisted {
		t.Errorf("full unlisted fingerprint: items %q opened %q, want it opened", got.Full, got.FullOpened)
	}
	if len(got.ListedOpened) != 1 || got.ListedOpened[0] != variant {
		t.Errorf("listed variant prefix: items %q opened %q", got.Listed, got.ListedOpened)
	}
	if len(got.PrefixOpened) != 0 || len(got.Prefix) != 1 || !strings.Contains(got.Prefix[0], "no listed variant") {
		t.Errorf("unlisted prefix: items %q opened %q, want one hint and nothing opened", got.Prefix, got.PrefixOpened)
	}
	if len(got.FullListed) != 1 || len(got.FullListedOpened) != 1 || got.FullListedOpened[0] != variant {
		t.Errorf("full listed fingerprint: items %q opened %q, want only the listed row", got.FullListed, got.FullListedOpened)
	}
}
