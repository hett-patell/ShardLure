package web

import (
	"crypto/sha256"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// These tests pin the frontend contracts from docs/FRONTEND-UI-AUDIT-2026-09-07.md.
// Every finding there was first reproduced in a real browser against the
// pre-fix build (see the audit's remediation section), then fixed; each test
// below reads the embedded asset so the shipped dashboard cannot regress
// silently. They are deliberately literal string/regexp checks on the HTML
// and CSS — the point is to fail the build the moment someone re-adds an
// `outline: none`, an inline grid template or a click-only panel header, not
// to model the DOM.

// styleBlock returns the page's own <style> sheet.
func styleBlock(t *testing.T, page string) string {
	t.Helper()
	i := strings.Index(page, "<style>")
	j := strings.Index(page, "</style>")
	if i < 0 || j < i {
		t.Fatal("page has no <style> block")
	}
	return page[i+len("<style>") : j]
}

var (
	inlineScriptRe = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	anyScriptRe    = regexp.MustCompile(`(?s)<script\b.*?</script>`)
)

// inlineScripts concatenates every inline <script> body on the page.
func inlineScripts(page string) string {
	var b strings.Builder
	for _, m := range inlineScriptRe.FindAllStringSubmatch(page, -1) {
		b.WriteString(m[1])
		b.WriteString("\n")
	}
	return b.String()
}

// markupOnly strips scripts so JS string literals are not mistaken for tags.
func markupOnly(page string) string { return anyScriptRe.ReplaceAllString(page, "") }

// mediaBlocks returns the bodies of every `@media <query> { … }` block.
func mediaBlocks(css, query string) []string {
	var out []string
	needle := "@media " + query
	for start := 0; ; {
		i := strings.Index(css[start:], needle)
		if i < 0 {
			return out
		}
		i += start
		open := strings.Index(css[i:], "{")
		if open < 0 {
			return out
		}
		open += i
		depth, j := 0, open
		for ; j < len(css); j++ {
			switch css[j] {
			case '{':
				depth++
			case '}':
				depth--
			}
			if depth == 0 {
				break
			}
		}
		out = append(out, css[open+1:j])
		start = j
	}
}

var pages = map[string]string{"index.html": indexHTML, "intel.html": intelHTML}

// ── 3.1 collapsible panels ─────────────────────────────────────────────────

func TestCollapsiblePanelsAreKeyboardOperable(t *testing.T) {
	if strings.Contains(intelHTML, `onclick="this.parentElement.classList.toggle('collapsed')"`) {
		t.Fatal("a panel head still toggles on a div click: not focusable, no aria-expanded")
	}
	re := regexp.MustCompile(`<h2><button type="button" class="panel-toggle" aria-expanded="true" aria-controls="([a-z-]+)">`)
	m := re.FindAllStringSubmatch(intelHTML, -1)
	if len(m) != 3 {
		t.Fatalf("found %d panel-toggle buttons, want 3 (ioc, ttp, payloads)", len(m))
	}
	for _, mm := range m {
		if !strings.Contains(intelHTML, `class="panel-body" id="`+mm[1]+`"`) {
			t.Errorf("aria-controls=%q points at no .panel-body", mm[1])
		}
	}
	css := styleBlock(t, intelHTML)
	collapsed := regexp.MustCompile(`(?s)\.panel-collapse\.collapsed \.panel-body \{[^}]*\}`).FindString(css)
	if !strings.Contains(collapsed, "visibility: hidden") {
		t.Error("collapsed panel body must be visibility:hidden, or its buttons stay in the tab order")
	}
	js := inlineScripts(intelHTML)
	if !strings.Contains(js, "btn.setAttribute('aria-expanded'") {
		t.Error("toggle handler does not maintain aria-expanded")
	}
}

// ── 3.3 focus visibility ───────────────────────────────────────────────────

func TestFocusRingIsNeverSuppressed(t *testing.T) {
	outlineNone := regexp.MustCompile(`outline:\s*none`)
	for name, page := range pages {
		if loc := outlineNone.FindStringIndex(styleBlock(t, page)); loc != nil {
			t.Errorf("%s: outline:none suppresses the keyboard focus ring (WCAG 2.4.7)", name)
		}
	}
	themes := string(themesCSS)
	if !strings.Contains(themes, ":focus-visible {") {
		t.Error("themes.css has no shared :focus-visible rule")
	}
	if n := strings.Count(themes, "--focus-ring:"); n < 4 {
		t.Errorf("--focus-ring defined in %d theme blocks, want all 4", n)
	}
}

// ── 4.1 labels ─────────────────────────────────────────────────────────────

func TestStaticFormControlsAreLabelled(t *testing.T) {
	tagRe := regexp.MustCompile(`(?s)<(input|select|textarea)\b[^>]*>`)
	for name, page := range pages {
		body := markupOnly(page)
		for _, loc := range tagRe.FindAllStringIndex(body, -1) {
			tag := body[loc[0]:loc[1]]
			if strings.Contains(tag, "aria-label=") || strings.Contains(tag, "aria-labelledby=") {
				continue
			}
			if id := regexp.MustCompile(`id="([^"]+)"`).FindStringSubmatch(tag); id != nil &&
				strings.Contains(body, `<label for="`+id[1]+`"`) {
				continue
			}
			// Wrapped in a <label>: the nearest preceding <label must be unclosed.
			back := body[max(0, loc[0]-400):loc[0]]
			if strings.LastIndex(back, "<label") > strings.LastIndex(back, "</label>") {
				continue
			}
			t.Errorf("%s: control has no accessible name (placeholder is not a label): %s", name, tag)
		}
	}
}

func TestGeneratedSettingsRowsLabelTheirInputs(t *testing.T) {
	js := inlineScripts(intelHTML)
	if n := strings.Count(js, `aria-labelledby="' + labelId(s.key) + '"`); n < 4 {
		t.Errorf("settings row builders wire aria-labelledby on %d inputs, want >= 4 (secret, int, float, text)", n)
	}
	if n := strings.Count(js, `<span class="sl-name" id="' + labelId(s.key) + '">`); n != 2 {
		t.Errorf("row name spans carrying the label id: %d, want 2 (secretRowHTML, knobRowHTML)", n)
	}
	if !strings.Contains(js, `<label class="set-toggle"><input type="checkbox"`) {
		t.Error("bool knob checkbox must stay wrapped in its <label>")
	}
}

// ── 4.2 combobox ───────────────────────────────────────────────────────────

func TestSearchIsACombobox(t *testing.T) {
	tag := regexp.MustCompile(`(?s)<input class="search" id="search-input"[^>]*>`).FindString(intelHTML)
	if tag == "" {
		t.Fatal("search input not found")
	}
	for _, want := range []string{`role="combobox"`, `aria-controls="palette"`, `aria-expanded="false"`, `aria-autocomplete="list"`, `aria-haspopup="listbox"`, `aria-label="`} {
		if !strings.Contains(tag, want) {
			t.Errorf("search input missing %s", want)
		}
	}
	js := inlineScripts(intelHTML)
	for _, want := range []string{"aria-activedescendant", `id="pal-opt-' + i`, "aria-selected", "function syncPaletteAria"} {
		if !strings.Contains(js, want) {
			t.Errorf("palette JS missing %s", want)
		}
	}
}

// ── 4.3 dialogs ────────────────────────────────────────────────────────────

func TestModalsAreNativeDialogs(t *testing.T) {
	if strings.Contains(intelHTML, `<div class="sess-modal"`) {
		t.Fatal("a modal is still a div overlay: no focus trap, no inert background")
	}
	for _, id := range []string{"payload-modal", "sess-modal"} {
		if !regexp.MustCompile(`<dialog class="sess-modal" id="` + id + `" aria-labelledby="[a-z-]+">`).MatchString(intelHTML) {
			t.Errorf("%s is not a labelled <dialog>", id)
		}
	}
	js := inlineScripts(intelHTML)
	if n := strings.Count(js, "modal.showModal()"); n != 2 {
		t.Errorf("showModal() call sites: %d, want 2", n)
	}
	// The only remaining .open toggle is the actor-detail drawer, not a modal.
	if n := strings.Count(js, ".classList.add('open')"); n != 1 || !strings.Contains(js, "el.classList.add('open')") {
		t.Errorf("modal open state must come from <dialog>.open, not a class (found %d class toggles)", n)
	}
	css := styleBlock(t, intelHTML)
	for _, want := range []string{".sess-modal[open]", ".sess-modal::backdrop"} {
		if !strings.Contains(css, want) {
			t.Errorf("dialog CSS missing %s", want)
		}
	}
}

// ── 4.4 polling ────────────────────────────────────────────────────────────

func TestPollingIsVisibilityGated(t *testing.T) {
	intel := inlineScripts(intelHTML)
	if n := strings.Count(intel, "setInterval("); n != 1 {
		t.Errorf("intel.html has %d bare setInterval calls, want 1 (inside pollEvery)", n)
	}
	for _, want := range []string{"function pollEvery", "visibilitychange", "_intelRefreshInFlight", "now - p.last < p.ms / 2"} {
		if !strings.Contains(intel, want) {
			t.Errorf("intel.html missing %s", want)
		}
	}
	// index.html has one poller. Every setInterval on the page must carry the
	// hidden-tab guard in the same statement — a count, not a literal, so a
	// second unguarded timer cannot slip in.
	index := inlineScripts(indexHTML)
	all := regexp.MustCompile(`setInterval\(`).FindAllStringIndex(index, -1)
	guarded := regexp.MustCompile(`setInterval\(function \(\) \{ if \(!document\.hidden\)`).FindAllStringIndex(index, -1)
	if len(all) == 0 || len(all) != len(guarded) {
		t.Errorf("index.html: %d setInterval calls, %d guarded by document.hidden", len(all), len(guarded))
	}
	for _, want := range []string{"_refreshInFlight", "_lastRefreshAt", "visibilitychange", "} finally {"} {
		if !strings.Contains(index, want) {
			t.Errorf("index.html missing %s", want)
		}
	}
}

// ── 4.5 vis-network ────────────────────────────────────────────────────────

func TestVisNetworkIsLazyLoaded(t *testing.T) {
	if strings.Contains(intelHTML, `<script src="/vendor/vis-network.min.js"`) {
		t.Fatal("vis-network is a render-blocking <head> script again (689 KB for a third-tab panel)")
	}
	js := inlineScripts(intelHTML)
	if !strings.Contains(js, "function ensureVis") || !strings.Contains(js, "await ensureVis()") {
		t.Error("graph refresh does not load vis-network on demand")
	}
}

// ── 4.6 / 4.7 / 3.2 layout ─────────────────────────────────────────────────

func TestNoInlineLayoutStyles(t *testing.T) {
	// Any inline layout property beats every media query, which is how the
	// stats rows kept five columns on a phone and the right-rail panels kept
	// a 28vh cap — so the check covers the whole class, not one property.
	inline := regexp.MustCompile(`style="[^"]*(grid-template-columns|max-height|min-height|height:|flex:)`)
	for name, page := range pages {
		if m := inline.FindString(markupOnly(page)); m != "" {
			t.Errorf("%s: inline layout style defeats the responsive rules: %s", name, m)
		}
	}
	css := styleBlock(t, intelHTML)
	if !strings.Contains(css, ".stats.cols-5 {") || !strings.Contains(css, ".stats, .stats.cols-5 { grid-template-columns: 1fr 1fr; }") {
		t.Error("five-column stats must collapse to two columns on small screens")
	}
}

func TestSmallScreenLayouts(t *testing.T) {
	intel := strings.Join(mediaBlocks(styleBlock(t, intelHTML), "(max-width: 760px)"), "\n")
	if !strings.Contains(intel, ".shell { grid-template-columns: 1fr;") {
		t.Error("intel.html: the 52px sidebar column has no phone breakpoint")
	}
	index := strings.Join(mediaBlocks(styleBlock(t, indexHTML), "(max-width: 760px)"), "\n")
	if strings.Contains(index, ".rail.right { display: none; }") {
		t.Error("index.html: the live feed is hidden on phones")
	}
	for _, want := range []string{"html, body { overflow: auto;", ".rail.right { display: flex;"} {
		if !strings.Contains(index, want) {
			t.Errorf("index.html phone layout missing %q", want)
		}
	}
	themes := strings.Join(mediaBlocks(string(themesCSS), "(max-width: 760px)"), "\n")
	if !strings.Contains(themes, "max-width: none") {
		t.Error("themes.css: #cobe-wrap keeps its viewport-relative max-width (0px on a phone)")
	}
}

// ── 4.8 contrast ───────────────────────────────────────────────────────────

func relLum(hex string) float64 {
	ch := func(s string) float64 {
		n, _ := strconv.ParseUint(s, 16, 8)
		f := float64(n) / 255
		if f <= 0.03928 {
			return f / 12.92
		}
		return math.Pow((f+0.055)/1.055, 2.4)
	}
	return 0.2126*ch(hex[1:3]) + 0.7152*ch(hex[3:5]) + 0.0722*ch(hex[5:7])
}

func contrast(a, b string) float64 {
	la, lb := relLum(a), relLum(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// themeTokens parses every `html…{ --x: #hex; }` block in themes.css.
func themeTokens(t *testing.T) map[string]map[string]string {
	t.Helper()
	out := map[string]map[string]string{}
	blockRe := regexp.MustCompile(`(?s)(html[^{}]*)\{([^{}]*)\}`)
	varRe := regexp.MustCompile(`--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;`)
	for _, m := range blockRe.FindAllStringSubmatch(string(themesCSS), -1) {
		sel := strings.Join(strings.Fields(m[1]), " ")
		if !strings.Contains(sel, "data-theme=") || !strings.Contains(m[2], "--dim-2:") {
			continue
		}
		vars := map[string]string{}
		for _, v := range varRe.FindAllStringSubmatch(m[2], -1) {
			vars[v[1]] = strings.ToLower(v[2])
		}
		out[sel] = vars
	}
	return out
}

func TestDimTokensMeetContrast(t *testing.T) {
	blocks := themeTokens(t)
	if len(blocks) != 4 {
		t.Fatalf("found %d theme blocks defining --dim-2, want 4 (signal dark/light, meridian, sprite)", len(blocks))
	}
	for sel, v := range blocks {
		for _, k := range []string{"bg", "glass", "glass-2", "dim", "dim-2", "focus-ring"} {
			if v[k] == "" {
				t.Fatalf("%s: --%s missing", sel, k)
			}
		}
		// Text tokens: 4.5:1 (WCAG 1.4.3) against the body ground and every
		// panel surface they can sit on — the lightest surface is the binding
		// one on dark themes, the darkest on light themes, so check them all.
		for _, tok := range []string{"dim", "dim-2"} {
			for _, surf := range []string{"bg", "glass", "glass-2"} {
				if c := contrast(v[tok], v[surf]); c < 4.5 {
					t.Errorf("%s: --%s %s on --%s %s = %.2f:1, want >= 4.5", sel, tok, v[tok], surf, v[surf], c)
				}
			}
		}
		// Non-text: 3:1 (WCAG 1.4.11) for the focus ring against the ground.
		if c := contrast(v["focus-ring"], v["bg"]); c < 3 {
			t.Errorf("%s: --focus-ring %s on --bg %s = %.2f:1, want >= 3", sel, v["focus-ring"], v["bg"], c)
		}
	}
	// The pre-theme :root fallback in intel.html must clear the bar too.
	root := styleBlock(t, intelHTML)
	get := func(name string) string {
		m := regexp.MustCompile(`--` + name + `:\s*(#[0-9a-fA-F]{6})`).FindStringSubmatch(root)
		if m == nil {
			t.Fatalf("intel.html :root has no --%s", name)
		}
		return strings.ToLower(m[1])
	}
	if c := contrast(get("dim-2"), get("bg")); c < 4.5 {
		t.Errorf("intel.html :root --dim-2 on --bg = %.2f:1, want >= 4.5", c)
	}
}

func TestNoSubTenPixelText(t *testing.T) {
	tiny := regexp.MustCompile(`(?:font|font-size):\s*(?:\d+\s+)?(?:[0-9]|9\.5|8\.5)px\b`)
	for name, page := range pages {
		if m := tiny.FindString(styleBlock(t, page)); m != "" {
			t.Errorf("%s: text below the 10px floor: %q", name, m)
		}
	}
	if m := tiny.FindString(string(themesCSS)); m != "" {
		t.Errorf("themes.css: text below the 10px floor: %q", m)
	}
}

// ── 4.9 fonts ──────────────────────────────────────────────────────────────

func TestFontsAreSelfHosted(t *testing.T) {
	for name, page := range pages {
		for _, host := range []string{"googleapis", "gstatic"} {
			if strings.Contains(page, host) {
				t.Errorf("%s still references %s", name, host)
			}
		}
		if !strings.Contains(page, `href="/fonts/fonts.css`) {
			t.Errorf("%s does not load the vendored fonts.css", name)
		}
	}
	rec := httptest.NewRecorder()
	securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	csp := rec.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "googleapis") || strings.Contains(csp, "gstatic") || !strings.Contains(csp, "font-src 'self';") {
		t.Errorf("CSP still whitelists a third-party font host: %s", csp)
	}

	css, err := fontsFS.ReadFile("fonts/fonts.css")
	if err != nil {
		t.Fatalf("fonts.css not embedded: %v", err)
	}
	faces := regexp.MustCompile(`(?s)@font-face\s*\{[^}]*\}`).FindAllString(string(css), -1)
	if len(faces) == 0 {
		t.Fatal("fonts.css declares no @font-face")
	}
	families := map[string]bool{}
	for _, f := range faces {
		if !strings.Contains(f, "font-display: swap") {
			t.Errorf("face without font-display: swap: %s", f)
		}
		u := regexp.MustCompile(`url\(/fonts/([^)]+)\)`).FindStringSubmatch(f)
		if u == nil {
			t.Errorf("face without a same-origin url(): %s", f)
			continue
		}
		data, err := fontsFS.ReadFile("fonts/" + u[1])
		if err != nil {
			t.Errorf("fonts.css references %s which is not embedded", u[1])
			continue
		}
		// The route serves faces as immutable, which is only honest if the
		// name changes with the bytes: the filename must carry the sha256.
		h := regexp.MustCompile(`-([0-9a-f]{8})\.woff2$`).FindStringSubmatch(u[1])
		if h == nil {
			t.Errorf("%s is not content-addressed (no sha256 prefix in the name)", u[1])
		} else if sum := fmt.Sprintf("%x", sha256.Sum256(data)); !strings.HasPrefix(sum, h[1]) {
			t.Errorf("%s: name says %s, content hashes to %s…", u[1], h[1], sum[:8])
		}
		if fam := regexp.MustCompile(`font-family:\s*'([^']+)'`).FindStringSubmatch(f); fam != nil {
			families[fam[1]] = true
		}
	}
	// Every quoted family a theme stack names must be vendored, or that theme
	// silently renders in a system fallback that was never designed for.
	stackRe := regexp.MustCompile(`--(?:mono|sans|display):\s*([^;]+);`)
	for _, m := range stackRe.FindAllStringSubmatch(string(themesCSS), -1) {
		for _, q := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(m[1], -1) {
			if !families[q[1]] {
				t.Errorf("themes.css names %q but fonts.css does not vendor it", q[1])
			}
		}
	}
}

func TestFontRoute(t *testing.T) {
	s, _ := hasshTestServer(t)
	get := func(method, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.handleFont(rec, httptest.NewRequest(method, path, nil))
		return rec
	}
	if r := get(http.MethodGet, "/fonts/fonts.css"); r.Code != 200 || !strings.HasPrefix(r.Header().Get("Content-Type"), "text/css") {
		t.Errorf("fonts.css: code %d type %q", r.Code, r.Header().Get("Content-Type"))
	}
	css, _ := fontsFS.ReadFile("fonts/fonts.css")
	face := regexp.MustCompile(`url\(/fonts/([^)]+)\)`).FindStringSubmatch(string(css))
	if face == nil {
		t.Fatal("fonts.css names no face")
	}
	if r := get(http.MethodGet, "/fonts/"+face[1]); r.Code != 200 || r.Header().Get("Content-Type") != "font/woff2" ||
		!strings.Contains(r.Header().Get("Cache-Control"), "immutable") || !strings.HasPrefix(r.Body.String(), "wOF2") {
		t.Errorf("%s: code %d type %q cache %q", face[1], r.Code, r.Header().Get("Content-Type"), r.Header().Get("Cache-Control"))
	}
	for _, bad := range []string{"/fonts/", "/fonts/nope.woff2", "/fonts/../embed.go", "/fonts/README.md", "/fonts/.hidden.woff2"} {
		if r := get(http.MethodGet, bad); r.Code != http.StatusNotFound {
			t.Errorf("%s: code %d, want 404", bad, r.Code)
		}
	}
	if r := get(http.MethodPost, "/fonts/fonts.css"); r.Code != http.StatusMethodNotAllowed || r.Header().Get("Allow") == "" {
		t.Errorf("POST: code %d allow %q, want 405 with Allow", r.Code, r.Header().Get("Allow"))
	}
}

// ── P3 hygiene ─────────────────────────────────────────────────────────────

func TestSidebarLinksAreNamed(t *testing.T) {
	re := regexp.MustCompile(`<a class="sb-item[^"]*"[^>]*><svg[^>]*>`)
	for name, page := range pages {
		links := re.FindAllString(page, -1)
		if len(links) != 2 {
			t.Errorf("%s: %d sidebar links, want 2", name, len(links))
		}
		for _, l := range links {
			if !strings.Contains(l, "aria-label=") || !strings.Contains(l, `aria-hidden="true"`) {
				t.Errorf("%s: icon link is named by title only or exposes its svg: %s", name, l)
			}
		}
	}
}

func TestTabsControlTabpanels(t *testing.T) {
	for _, v := range []string{"overview", "blue", "red", "settings"} {
		if !regexp.MustCompile(`id="tab-` + v + `" data-view="` + v + `" role="tab"[^>]*aria-controls="view-` + v + `"`).MatchString(intelHTML) {
			t.Errorf("tab %s lacks id/aria-controls", v)
		}
		if !strings.Contains(intelHTML, `id="view-`+v+`" role="tabpanel" aria-labelledby="tab-`+v+`"`) {
			t.Errorf("view %s is not a labelled tabpanel", v)
		}
	}
}

func TestCanvasesHaveTextAlternatives(t *testing.T) {
	if !regexp.MustCompile(`<canvas id="heatmap"[^>]*role="img"[^>]*aria-describedby="heatmap-desc"`).MatchString(intelHTML) ||
		!strings.Contains(intelHTML, `id="heatmap-desc"`) || !strings.Contains(inlineScripts(intelHTML), "setHeatmapDesc(") {
		t.Error("heatmap canvas has no maintained text alternative")
	}
	if !strings.Contains(indexHTML, `aria-describedby="spark-max"`) {
		t.Error("sparkline canvas is not described by its peak readout")
	}
	if strings.Contains(indexHTML, `aria-label="Interactive 3D globe`) {
		t.Error("globe canvas claims keyboard interactivity it does not have")
	}
}

func TestNoSideStripeBorders(t *testing.T) {
	if m := regexp.MustCompile(`border-left:\s*[2-9]px`).FindString(styleBlock(t, intelHTML)); m != "" {
		t.Errorf("decorative side stripe: %q", m)
	}
}

// TestIntelGraphEmptyWindowEncodesArrays: found while verifying the audit fixes
// on a fresh database — graph.Build returns nil slices for an empty window,
// which JSON-encodes as null, and the panel's `data.edges.length` then threw
// "Cannot read properties of null" and showed "load failed" instead of an
// empty graph. Both sides are fixed; this pins the server side.
func TestIntelGraphEmptyWindowEncodesArrays(t *testing.T) {
	s, _ := hasshTestServer(t)
	rec := httptest.NewRecorder()
	s.handleIntelGraph(rec, httptest.NewRequest(http.MethodGet, "/api/intel/graph?window=7d", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"nodes":[]`, `"edges":[]`} {
		if !strings.Contains(body, want) {
			t.Errorf("empty-window graph response lacks %s: %s", want, body)
		}
	}
	js := inlineScripts(intelHTML)
	for _, bad := range []string{"data.edges.length", "data.nodes.length", "data.nodes.map("} {
		if strings.Contains(js, bad) {
			t.Errorf("graph JS dereferences %s without a null guard", bad)
		}
	}
}

// TestDownloadControlsAreButtons: the IOC/wordlist/replay downloads all go
// through downloadWithAuth (fetch + Blob), so their anchors never had a usable
// href — and an <a> without one has no link role and is not focusable, which
// left three pointer-only controls in place after the accessibility pass.
func TestDownloadControlsAreButtons(t *testing.T) {
	if strings.Contains(intelHTML, `<a class="ioc-dl"`) {
		t.Error("a download control is still an href-less anchor")
	}
	if n := strings.Count(intelHTML, `<button type="button" class="ioc-dl"`); n != 4 {
		t.Errorf("download buttons: %d, want 4 (csv, stix, wordlist, replay)", n)
	}
	if strings.Contains(inlineScripts(intelHTML), "removeAttribute('href')") {
		t.Error("JS still strips an href a button never had")
	}
}

// TestHeatmapAxisAndDescriptionShareAFormatter pins that what a screen reader
// hears for a column matches the label a sighted reader sees under it.
func TestHeatmapAxisAndDescriptionShareAFormatter(t *testing.T) {
	js := inlineScripts(intelHTML)
	if strings.Count(js, "fmtHeatHour(") < 4 {
		t.Error("heatmap axis and text alternative do not share fmtHeatHour")
	}
	if strings.Contains(js, "d.getUTCHours()+'h'") {
		t.Error("axis label still uses its own hour format")
	}
}
