# Globe Artifacts, Ambient Dashboard & Intel Palette Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Signal theme's globe render floating artifacts (the reported bug), turn the globe page into an ambient wall display by cutting the six panels duplicated in `/intel`, replace the `/intel` search row-hider with a real command palette, and remove the 28 hardcoded Dragon-red values still tinting `/intel`.

**Architecture:** Frontend-first. Artifacts reuse the existing overlay pipeline (`buildThemeOverlays` → `makeOverlayEl` → `ShardCobe.setOverlayPlaces`) by adding a `signal` branch — no new machinery and no CSS, because the `.globe-*` rules are already unscoped and token-driven. The panel cull is driven by element ID (writers are not uniformly named). One small Go change exposes two already-cached fields so the ported Threat gauge has inputs.

**Tech Stack:** Go (`net/http`), vanilla JS, CSS custom properties, Cobe (WebGL globe), `go test`, headless Chromium (bundled with Playwright) for visual verification.

## Global Constraints

- Ships as part of **v2.0.0** (not yet tagged). Two waves: **Wave 1 = Tasks 1–4** (`index.html` + Go + README), **Wave 2 = Tasks 5–7** (`intel.html` + README).
- Signal accent: dark `#d1fe17`, light `#b6d900`. Signal artifacts must follow the `data-mode` dark/light toggle.
- **No per-theme overlay CSS may be added.** `.globe-overlay`, `.globe-sticker`, `.globe-sat`, `.globe-sat--hub`, `.globe-live`, `.globe-analytics` are unscoped base rules at `themes.css:288-343` driven by `var(--accent)`/`var(--line)`; there are zero `[data-theme=…] .globe-*` rules. Only add an override if a render proves it necessary.
- Meridian and Sprite globe artifacts and theme tokens must remain **unchanged**.
- After Task 6: `grep -c "208,40,40" internal/web/intel.html` → **0**.
- All tracked files valid UTF-8 (CI runs `scripts/check-utf8.sh`). `go vet ./...` and `go test ./...` stay green. CI has no lint step beyond `go vet` — do not add one.
- Every palette action must call a function that already exists: `loadActorDetail(id)` (`intel.html:2089`), the enrich flow (`:3405-3424`), `openSession(sid)` (`:3066`), `openPayload(sha)` (`:3721`).
- HTML files are not valid JS — do **not** run `node --check` on them. Verify inline scripts by extracting them, or rely on the visual gate. `node --check` IS valid for `cobe-boot.js` / `cobe-globe.js`.

---

## File Structure

- `internal/web/server.go` — add `IntentCounts` + `KindCounts` to `dashboardResponse`; populate from `summaryStatsCached()`. (Task 1)
- `internal/web/index.html` — `signal` branch in `buildThemeOverlays`; delete dead `node` branch; remove 6 panels + their 6 writers + call sites; add Threat gauge markup, CSS, and `renderGauge`. (Tasks 2–3)
- `README.md` — correct the widget/globe bullets (Task 4), add the palette line (Task 7).
- `internal/web/intel.html` — command palette replacing `applyClientSearch`'s global hiding (Task 5); tokenise 28 Dragon-red literals (Task 6).

No new files. No Go logic beyond the two response fields.

---

### Task 1: Expose `intentCounts` + `kindCounts` on `/api/dashboard`

The ported Threat gauge needs these; they are already computed and cached in `summaryStats` but never serialised.

**Files:**
- Modify: `internal/web/server.go` (`dashboardResponse` struct; `handleDashboard` summary block)

**Interfaces:**
- Produces: `/api/dashboard` JSON gains `intentCounts` and `kindCounts`, each an array of `{label, count}` (Go type `[]store.LabelCount`). Task 3's `renderGauge` consumes them.

- [ ] **Step 1: Add the two fields to the response struct**

In `internal/web/server.go`, in `type dashboardResponse struct`, add after the `Hourly` field:

```go
	Hourly       []hourPoint       `json:"hourly"`
	IntentCounts []store.LabelCount `json:"intentCounts"`
	KindCounts   []store.LabelCount `json:"kindCounts"`
	Home         homePoint         `json:"home"`
```

- [ ] **Step 2: Populate them from the existing stats cache**

In `handleDashboard`, the stats cache is already read into local variables. Find this block:

```go
	var ec, ac, uniqueIPs, countries int
	var topIPs, topUsers, topCommands []store.CountRow
	if stats, err := s.summaryStatsCached(); err == nil {
		ec, ac, uniqueIPs, countries = stats.Events, stats.Actors, stats.UniqueIPs, stats.Countries
		topIPs, topUsers, topCommands = stats.TopIPs, stats.TopUsers, stats.TopCommands
	}
```

Extend it to also capture the two count slices:

```go
	var ec, ac, uniqueIPs, countries int
	var topIPs, topUsers, topCommands []store.CountRow
	var intentCounts, kindCounts []store.LabelCount
	if stats, err := s.summaryStatsCached(); err == nil {
		ec, ac, uniqueIPs, countries = stats.Events, stats.Actors, stats.UniqueIPs, stats.Countries
		topIPs, topUsers, topCommands = stats.TopIPs, stats.TopUsers, stats.TopCommands
		// Already computed and cached by summaryStatsCached — no extra query.
		// The globe dashboard's threat gauge needs both to score intent mix.
		intentCounts, kindCounts = stats.IntentCounts, stats.KindCounts
	}
```

Then assign them where `resp` is built (alongside `Hourly`):

```go
		IntentCounts: intentCounts,
		KindCounts:   kindCounts,
```

- [ ] **Step 3: Verify it compiles and the field ships**

Run: `go build ./... && go vet ./...`
Expected: no output from either.

Run: `go test ./internal/web/ 2>&1 | tail -3`
Expected: `ok  github.com/networkshard/shardlure/internal/web`

- [ ] **Step 4: Verify the JSON actually contains the keys**

Run:
```bash
go build -o /tmp/sl-t1 ./cmd/shardlure && bash scripts/ci-web-smoke.sh && rm -f /tmp/sl-t1
```
Expected: smoke prints `all checks passed`.

Then confirm the keys serialise (grep the struct tags, since an empty DB yields `null` values):
```bash
grep -c 'json:"intentCounts"' internal/web/server.go
grep -c 'json:"kindCounts"' internal/web/server.go
```
Expected: `1` and `1`.

- [ ] **Step 5: Commit**

```bash
git add internal/web/server.go
git commit -m "feat(api): expose intentCounts/kindCounts on /api/dashboard for the globe threat gauge"
```

---

### Task 2: Signal globe artifacts (the reported bug) + delete dead `node` branch

**Files:**
- Modify: `internal/web/index.html` (`buildThemeOverlays` gate at line 872; `makeOverlayEl` `node` branch)

**Interfaces:**
- Consumes: `themeAccentRGB()` (already returns Signal dark/light palettes), `currentMode()`, `makeOverlayEl()` kinds `sat` / `live` / `analytics`.
- Produces: Signal globes emit overlay descriptors, so `applyGlobeOverlays()` renders artifacts. No signature changes.

- [ ] **Step 1: Add `signal` to the overlay gate**

In `internal/web/index.html`, `buildThemeOverlays` currently starts (line ~872):

```js
function buildThemeOverlays(theme, home, actors) {
  if (theme !== 'sprite' && theme !== 'meridian') return [];
```

Change the gate to admit `signal`:

```js
function buildThemeOverlays(theme, home, actors) {
  if (theme !== 'sprite' && theme !== 'meridian' && theme !== 'signal') return [];
```

- [ ] **Step 2: Add the Signal branch**

The function body is an `if (theme === 'sprite') { … } else { …meridian… }`. Signal reuses Meridian's *shape* (hub sat + live badge at home; per-actor sat + analytics chip) but must be its own branch so Meridian is untouched.

Immediately after the `ranked` computation and **before** `if (theme === 'sprite') {`, insert:

```js
  if (theme === 'signal') {
    var pkHomeS = 'home';
    out.push({
      lat: home.lat, lng: home.lon, kind: 'live', alt: 0.05,
      rate: 'LIVE', sub: (home.city || 'home'), placeKey: pkHomeS,
    });
    out.push({
      lat: home.lat, lng: home.lon, kind: 'sat', alt: 0.075,
      label: 'HUB', placeKey: pkHomeS, hub: true, ringDelay: 0,
    });
    ranked.forEach(function (a, i) {
      var pk = 'actor' + i;
      var n = a.events || 0;
      var r = Number(a.rateHour);
      var rateLbl = Number.isFinite(r) && r > 0 ? r.toFixed(1) + '/h' : '';
      out.push({
        lat: a.lat, lng: a.lon, kind: 'sat', alt: 0.055 + (i % 3) * 0.01,
        label: a.cc || a.ip || 'node', placeKey: pk, ringDelay: i * 0.4,
      });
      out.push({
        lat: a.lat, lng: a.lon, kind: 'analytics', alt: 0.04,
        placeKey: pk,
        title: (a.cc || '??') + (a.city ? ' · ' + a.city : ''),
        value: n >= 1000 ? (n / 1000).toFixed(1) + 'k' : String(n),
        rateLabel: rateLbl,
        ip: a.ip || '',
      });
    });
    return out;
  }
```

Read the surrounding code first and place this so `ranked` and `out` are already declared — do not duplicate their declarations.

- [ ] **Step 3: Delete the dead `node` branch**

Nothing emits `kind: 'node'` (verify: `grep -c "kind: 'node'" internal/web/index.html` → `0`). In `makeOverlayEl()`, delete the entire `} else if (d.kind === 'node') { … }` block, keeping the `sticker` / `sat` / `live` / `analytics` branches intact.

- [ ] **Step 4: Verify no dead reference and the branch is reachable**

Run:
```bash
grep -c "kind: 'node'" internal/web/index.html          # expect 0 (no emitters)
grep -c "d.kind === 'node'" internal/web/index.html     # expect 0 (branch deleted)
grep -c "theme !== 'signal'" internal/web/index.html    # expect 1 (the new gate)
```
Expected: `0`, `0`, `1`.

- [ ] **Step 5: Verify artifacts actually render (this is the bug's proof)**

Build, seed, serve, and screenshot Signal-dark:

```bash
go build -o /tmp/sl-t2 ./cmd/shardlure
export SHARDLURE_DATA=/tmp/t2-data && rm -rf /tmp/t2-data && mkdir -p /tmp/t2-data
printf 'data_dir: /tmp/t2-data\nadmin_ips: []\n' > /tmp/t2.yaml
/tmp/sl-t2 -config /tmp/t2.yaml ingest journal testdata/sample.journal --replace
nohup /tmp/sl-t2 -config /tmp/t2.yaml web :18091 >/tmp/t2.log 2>&1 &
sleep 3
CHROME=/home/het/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome
PWCORE=$(ls -d /home/het/.npm/_npx/*/node_modules/playwright-core/index.js | head -1)
mkdir -p /tmp/t2-shots
cat > /tmp/t2.mjs <<JS
import pkg from '$PWCORE'; const { chromium } = pkg;
const b = await chromium.launch({ headless: true, executablePath: '$CHROME' });
const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
const errs = []; p.on('pageerror', e => errs.push(String(e)));
await p.goto('http://127.0.0.1:18091/', { waitUntil: 'load' });
await p.evaluate("localStorage.setItem('shardlure_theme','signal');localStorage.setItem('shardlure_mode','dark')");
await p.reload({ waitUntil: 'load' }); await p.waitForTimeout(2600);
console.log('overlay elements:', await p.evaluate(() => document.querySelectorAll('.globe-overlay').length));
console.log('pageerrors:', errs.length ? errs.join('; ') : 'none');
await p.screenshot({ path: '/tmp/t2-shots/signal-dark.png' });
await b.close();
JS
node /tmp/t2.mjs
```
Expected: `overlay elements:` a number **> 0** (this is the fix working — it was 0 before), and `pageerrors: none`.

Then **read** `/tmp/t2-shots/signal-dark.png` and confirm satellites, a LIVE badge, and analytics chips are visible on the globe in chartreuse.

Clean up: `kill %1; rm -rf /tmp/t2-data /tmp/t2.yaml /tmp/t2.mjs /tmp/sl-t2 /tmp/t2-shots /tmp/t2.log`

- [ ] **Step 6: Commit**

```bash
git add internal/web/index.html
git commit -m "fix(globe): render artifacts on Signal theme; drop dead node overlay branch"
```

---

### Task 3: Ambient dashboard — cut 6 duplicated panels, add Threat gauge

**Files:**
- Modify: `internal/web/index.html` (markup ~lines 344-398; writers at 662, 693, 708, 725, 758, 791; `refreshCapture` 834; call sites 1025-1032, 1050)

**Interfaces:**
- Consumes: `intentCounts`/`kindCounts` from Task 1; `/api/dashboard` `summary` (`eventCount`, `actorCount`, `uniqueIps`, `countries` — all four populated, verified).
- Produces: `renderGauge(summary, intentCounts, kindCounts)` in `index.html`, called from `refresh()`.

- [ ] **Step 1: Remove the six panels' markup**

In `internal/web/index.html`, delete the enclosing `<section class="panel">…</section>` block for each of these (locate by the element ID, **not** by guessing function names — one writer uses `querySelector`, so an ID grep alone misses it):

| Panel | Element |
| --- | --- |
| By country | `<table id="top-countries">` (~line 348) |
| Top usernames tried | `<div class="users" id="top-users">` (~356) |
| Top actors | `<div class="rows" id="actors">` (~361) |
| Recent shell sessions | `<div … id="shell-sessions">` (~378) + its `<span id="sess-count">` |
| Top commands | `<div … id="top-commands">` (~383) |
| Payload capture | `<div … id="capture-feed">` (~396) + the `cap-head`/`cap-stats` block with `#cap-live`, `#cap-active`, `#cap-bytes`, `#cap-fetched` |

- [ ] **Step 2: Delete the six writer functions and `refreshCapture`**

Delete these whole functions from `index.html`: `renderTopCountries` (line ~662), `renderTopUsers` (~693), `renderTopCommands` (~708), `renderShellSessions` (~725), `renderActors` (~758), `renderCapture` (~791), and `refreshCapture` (~834, an `async function`).

- [ ] **Step 3: Delete every call site**

Remove these calls (in `refresh()` and at module level):

```
line ~1025  renderTopCountries(d.topCountries);
line ~1027  renderTopUsers(d.topUsers);
line ~1028  renderTopCommands(d.topCommands);
line ~1029  renderShellSessions(d.sessions);
line ~1032  renderActors(d.topActors || actors);
line ~1050  refreshCapture();
```

Also delete the `setInterval(refreshCapture, 5000)` registration (search `refreshCapture` to catch every reference).

- [ ] **Step 4: Verify zero dangling references**

A surviving call to a deleted function is a runtime `ReferenceError` — the exact defect class the v2.0 final review caught. Check each:

```bash
for f in renderTopCountries renderTopUsers renderTopCommands renderShellSessions renderActors renderCapture refreshCapture; do
  printf "%-22s %s\n" "$f" "$(grep -c "$f" internal/web/index.html)"
done
```
Expected: **0** for every one.

```bash
for id in top-countries top-users '"actors"' shell-sessions top-commands capture-feed cap-live cap-active cap-bytes cap-fetched sess-count; do
  printf "%-16s %s\n" "$id" "$(grep -c "$id" internal/web/index.html)"
done
```
Expected: **0** for every one (note `#actors` is matched as `"actors"` to avoid hitting the unrelated word "actors" in prose/CSS; if a non-zero count is only CSS rules or prose, delete those too).

- [ ] **Step 5: Add the Threat gauge markup**

In the left rail, after the Summary tiles panel, insert:

```html
  <section class="panel">
    <h2>Threat Level</h2>
    <div class="gauge-outer" id="threat-gauge">
      <svg class="gauge-svg" viewBox="0 0 200 110">
        <defs>
          <linearGradient id="gg" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="var(--good)"/>
            <stop offset="40%" stop-color="var(--accent-2)"/>
            <stop offset="100%" stop-color="var(--accent)"/>
          </linearGradient>
        </defs>
        <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="rgba(255,255,255,0.04)" stroke-width="12" stroke-linecap="round"/>
        <path id="gauge-arc" d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="url(#gg)" stroke-width="12" stroke-linecap="round" stroke-dasharray="0 251"/>
        <text id="gauge-val" x="100" y="88" text-anchor="middle" fill="var(--text)" font-family="var(--mono)" font-size="36" font-weight="700">0</text>
        <text id="gauge-lbl-svg" x="100" y="104" text-anchor="middle" fill="var(--dim)" font-family="var(--mono)" font-size="10" font-weight="600" letter-spacing="0.12em">LOW</text>
      </svg>
      <div class="gauge-breakdown" id="gauge-breakdown"></div>
    </div>
  </section>
```

- [ ] **Step 6: Add the gauge CSS**

The gauge classes are defined in `intel.html`'s local `<style>`, not shared, so copy them into `index.html`'s `<style>` block:

```css
  .gauge-outer { display: flex; flex-direction: column; align-items: center; padding: 4px 0; }
  .gauge-svg { width: 100%; max-width: 220px; height: auto; }
  .gauge-breakdown { display: grid; grid-template-columns: 1fr 1fr; gap: 2px 12px; font: 10px var(--mono); color: var(--dim); margin-top: 8px; width: 100%; }
  .gauge-breakdown .gb-row { display: flex; justify-content: space-between; }
```

(`themes.css` already carries light-theme `.gauge-breakdown` overrides for signal-light/meridian/sprite, so no theme CSS is needed.)

- [ ] **Step 7: Port `renderGauge` and call it**

Copy the whole `renderGauge(summary, intentCounts, kindCounts)` function from `intel.html` (starts line ~4302, ends at its closing `}`) verbatim into `index.html`'s script. It reads `#gauge-arc`, `#gauge-val`, `#gauge-lbl-svg`, `#gauge-breakdown` — all present from Step 5.

Then call it inside `refresh()`, next to where the summary tiles are written:

```js
  renderGauge(d.summary, d.intentCounts, d.kindCounts);
```

- [ ] **Step 8: Verify the page still works and the gauge renders**

```bash
go build -o /tmp/sl-t3 ./cmd/shardlure
export SHARDLURE_DATA=/tmp/t3-data && rm -rf /tmp/t3-data && mkdir -p /tmp/t3-data
printf 'data_dir: /tmp/t3-data\nadmin_ips: []\n' > /tmp/t3.yaml
/tmp/sl-t3 -config /tmp/t3.yaml ingest journal testdata/sample.journal --replace
nohup /tmp/sl-t3 -config /tmp/t3.yaml web :18092 >/tmp/t3.log 2>&1 &
sleep 3
CHROME=/home/het/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome
PWCORE=$(ls -d /home/het/.npm/_npx/*/node_modules/playwright-core/index.js | head -1)
mkdir -p /tmp/t3-shots
cat > /tmp/t3.mjs <<JS
import pkg from '$PWCORE'; const { chromium } = pkg;
const b = await chromium.launch({ headless: true, executablePath: '$CHROME' });
for (const [name, set] of [
  ['signal-dark',  "localStorage.setItem('shardlure_theme','signal');localStorage.setItem('shardlure_mode','dark')"],
  ['signal-light', "localStorage.setItem('shardlure_theme','signal');localStorage.setItem('shardlure_mode','light')"],
  ['meridian',     "localStorage.setItem('shardlure_theme','meridian')"],
  ['sprite',       "localStorage.setItem('shardlure_theme','sprite')"]]) {
  const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
  const errs = []; p.on('pageerror', e => errs.push(String(e)));
  await p.goto('http://127.0.0.1:18092/', { waitUntil: 'load' });
  await p.evaluate(set); await p.reload({ waitUntil: 'load' }); await p.waitForTimeout(2600);
  console.log(name,
    '| overlays:', await p.evaluate(() => document.querySelectorAll('.globe-overlay').length),
    '| gauge:', await p.evaluate(() => (document.getElementById('gauge-val')||{}).textContent),
    '| errors:', errs.length ? errs.join('; ') : 'none');
  await p.screenshot({ path: '/tmp/t3-shots/' + name + '.png' });
  await p.close();
}
await b.close();
JS
node /tmp/t3.mjs
```
Expected for **every** state: `errors: none`; a numeric `gauge:` value; `overlays:` > 0 for signal/meridian/sprite.

**Read all four screenshots** and confirm: the six panels are gone, the gauge renders, the globe is larger, and Meridian/Sprite still look like themselves.

Clean up: `kill %1; rm -rf /tmp/t3-data /tmp/t3.yaml /tmp/t3.mjs /tmp/sl-t3 /tmp/t3-shots /tmp/t3.log`

- [ ] **Step 9: Full gate + commit**

```bash
bash scripts/check-utf8.sh && go vet ./... && go test ./... && bash scripts/ci-web-smoke.sh
git add internal/web/index.html
git commit -m "feat(dashboard): ambient globe view — cut 6 panels duplicated in /intel, add threat gauge"
```

---

### Task 4: README — globe/widget bullets (Wave 1 docs)

**Files:**
- Modify: `README.md` (the "Dashboard widgets" bullet ~line 52; the "3D Cobe globe" bullet ~line 51)

**Interfaces:** none.

- [ ] **Step 1: Rewrite the two bullets**

The current "Dashboard widgets" bullet lists everything as one undifferentiated set, which is wrong now that most of those live only in `/intel`. Replace the `3D Cobe globe` and `Dashboard widgets` bullets with:

```markdown
- **3D Cobe globe:** WebGL globe with live arcs from attacker IPs to your home point, plus floating artifacts anchored to attacker coordinates — satellites, a LIVE badge at your origin, and per-actor analytics chips. Pointer-drag rotation, scroll zoom, double-click reset. Proper listener lifecycle (no leaks on theme switch).
- **Two dashboards, split by job:** the **globe view** (`/`) is an ambient wall display — summary counts, threat-level gauge, events/hour sparkline, live feed, and the globe with its artifacts. The **intel console** (`/intel`) is where you dig: attack geography, brute-force radar, top credentials, MITRE ATT&CK coverage, sessions, payloads, tunnel/proxy targets, IOC export. All fed by real-time API polling.
```

- [ ] **Step 2: Verify no stale widget claims remain**

Run: `grep -nE "Dashboard widgets:" README.md`
Expected: only the roadmap line (~683), which is historical and stays.

Run: `bash scripts/check-utf8.sh`
Expected: `OK` line, no failures.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: README describes the two-dashboard split and globe artifacts"
```

---

### Task 5: Intel command palette (Wave 2)

**Files:**
- Modify: `internal/web/intel.html` (`#search-input` ~line 1126; `applyClientSearch` ~2774; search handler ~2764)

**Interfaces:**
- Consumes (all verified to exist): `loadActorDetail(id)` (`:2089`), `selectedActor` (`:2087`), `openSession(sid)` (`:3066`), `openPayload(sha)` (`:3721`), the `#enrich-ip` lookup (`:3405-3424`), and the existing view/tab switcher.
- Produces: `buildPalette(query)` → array of `{group, label, sub, action}`; `openPalette()` / `closePalette()` / `movePaletteSel(delta)` / `activatePaletteSel()`.

- [ ] **Step 1: Add the palette container markup**

Immediately after the `<input class="search" id="search-input" …>` element, add:

```html
<div class="palette" id="palette" hidden role="listbox" aria-label="Search results"></div>
```

- [ ] **Step 2: Add palette CSS**

In `intel.html`'s `<style>`, using tokens only (no literal colours):

```css
  .toolbar { position: relative; }
  .palette {
    position: absolute; top: calc(100% + 6px); left: 0; right: 0; z-index: 60;
    max-height: 60vh; overflow: auto;
    background: var(--panel-bg); border: 1px solid var(--line-strong);
    border-radius: var(--radius); box-shadow: 0 12px 32px rgba(0,0,0,0.35);
  }
  .palette .pg { font: 600 9px var(--mono); letter-spacing: .14em; text-transform: uppercase;
    color: var(--dim); padding: 8px 10px 4px; }
  .palette .pi { display: flex; justify-content: space-between; gap: 10px;
    padding: 6px 10px; font: 12px var(--mono); color: var(--text); cursor: pointer; }
  .palette .pi:hover, .palette .pi.sel { background: color-mix(in srgb, var(--accent) 12%, transparent); }
  .palette .pi .sub { color: var(--dim); }
  .palette .pempty { padding: 10px; font: 11px var(--mono); color: var(--dim); }
```

- [ ] **Step 3: Replace the search handler with palette logic**

Replace the existing `searchInput.addEventListener('input', …)` block and `applyClientSearch()` with the following. `applyClientSearch` is **kept** but scoped to the active view only.

```js
var _pal = { items: [], sel: -1 };

function paletteEl() { return document.getElementById('palette'); }

function closePalette() {
  var el = paletteEl();
  if (el) { el.hidden = true; el.innerHTML = ''; }
  _pal = { items: [], sel: -1 };
}

/* Build grouped results from data already fetched into the page's state plus
 * the /api/* payloads, so the palette finds items that are NOT rendered in the
 * current tab (the old row-hiding filter could only see the DOM). */
function buildPalette(q) {
  q = (q || '').trim().toLowerCase();
  if (!q) return [];
  var out = [];
  var seenIp = {};
  (_lastIntel && _lastIntel.actors ? _lastIntel.actors : []).forEach(function (a) {
    var ip = (a.primaryIp || a.ip || '');
    var hay = (ip + ' ' + (a.id || '') + ' ' + (a.playbook || '') + ' ' + (a.cc || '')).toLowerCase();
    if (hay.indexOf(q) < 0) return;
    if (out.filter(function (r) { return r.group === 'Actors'; }).length < 5) {
      out.push({
        group: 'Actors', label: ip || a.id,
        sub: (a.playbook || '') + ' · ' + (a.events || 0) + ' ev',
        action: function () { selectedActor = a.id; loadActorDetail(a.id); closePalette(); }
      });
    }
    if (ip && !seenIp[ip] && out.filter(function (r) { return r.group === 'IPs'; }).length < 5) {
      seenIp[ip] = 1;
      out.push({
        group: 'IPs', label: ip, sub: 'enrich →',
        action: function () {
          var f = document.getElementById('enrich-ip');
          if (f) { f.value = ip; f.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true })); }
          closePalette();
        }
      });
    }
  });
  (_lastIntel && _lastIntel.recentCommands ? _lastIntel.recentCommands : []).forEach(function (c) {
    if ((c.command || '').toLowerCase().indexOf(q) < 0) return;
    if (out.filter(function (r) { return r.group === 'Commands'; }).length >= 5) return;
    out.push({
      group: 'Commands', label: c.command, sub: c.ip || '',
      action: function () { searchInput.value = c.command; applyClientSearch(); closePalette(); }
    });
  });
  (_lastSessions || []).forEach(function (s) {
    var hay = ((s.id || '') + ' ' + (s.ip || '') + ' ' + (s.user || '')).toLowerCase();
    if (hay.indexOf(q) < 0) return;
    if (out.filter(function (r) { return r.group === 'Sessions'; }).length >= 5) return;
    out.push({
      group: 'Sessions', label: s.id, sub: (s.ip || '') + ' · ' + (s.commands || 0) + ' cmds',
      action: function () { openSession(s.id); closePalette(); }
    });
  });
  (_lastPayloads || []).forEach(function (p) {
    var hay = ((p.sha256 || '') + ' ' + (p.filename || '')).toLowerCase();
    if (hay.indexOf(q) < 0) return;
    if (out.filter(function (r) { return r.group === 'Payloads'; }).length >= 5) return;
    out.push({
      group: 'Payloads', label: p.filename || (p.sha256 || '').slice(0, 16),
      sub: (p.family || p.fileKind || ''),
      action: function () { openPayload(p.sha256); closePalette(); }
    });
  });
  return out;
}

function renderPalette(items) {
  var el = paletteEl();
  if (!el) return;
  _pal.items = items; _pal.sel = items.length ? 0 : -1;
  if (!items.length) {
    el.innerHTML = '<div class="pempty">no matches — press Esc to close</div>';
    el.hidden = false;
    return;
  }
  var html = '', group = '';
  items.forEach(function (it, i) {
    if (it.group !== group) { group = it.group; html += '<div class="pg">' + esc(group) + '</div>'; }
    html += '<div class="pi' + (i === _pal.sel ? ' sel' : '') + '" data-i="' + i + '" role="option">' +
      '<span>' + esc(it.label) + '</span><span class="sub">' + esc(it.sub || '') + '</span></div>';
  });
  el.innerHTML = html;
  el.hidden = false;
  el.querySelectorAll('.pi').forEach(function (row) {
    row.addEventListener('click', function () {
      var it = _pal.items[Number(row.getAttribute('data-i'))];
      if (it && it.action) it.action();
    });
  });
}

function movePaletteSel(delta) {
  if (!_pal.items.length) return;
  _pal.sel = (_pal.sel + delta + _pal.items.length) % _pal.items.length;
  var el = paletteEl();
  el.querySelectorAll('.pi').forEach(function (row, i) {
    row.classList.toggle('sel', i === _pal.sel);
    if (i === _pal.sel && row.scrollIntoView) row.scrollIntoView({ block: 'nearest' });
  });
}

function activatePaletteSel() {
  var it = _pal.items[_pal.sel];
  if (it && it.action) it.action();
}

var searchTimer = 0;
searchInput.addEventListener('input', function () {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(function () {
    Filters.search = searchInput.value.trim().toLowerCase();
    if (!Filters.search) { closePalette(); applyClientSearch(); return; }
    renderPalette(buildPalette(Filters.search));
    applyClientSearch();
  }, 120);
});

searchInput.addEventListener('keydown', function (e) {
  if (e.key === 'ArrowDown') { e.preventDefault(); movePaletteSel(1); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); movePaletteSel(-1); }
  else if (e.key === 'Enter') { e.preventDefault(); activatePaletteSel(); }
  else if (e.key === 'Escape') { closePalette(); }
});

document.addEventListener('click', function (e) {
  if (!e.target.closest('#palette') && e.target !== searchInput) closePalette();
});
```

- [ ] **Step 4: Scope the row filter to the active view and cache the payloads**

Change `applyClientSearch()` so its `querySelectorAll` is rooted at the **active** view instead of the document (the old behaviour silently hid rows on hidden tabs). Find the active view container (the `.view` element without `hidden`, per `setActiveView`) and query within it:

```js
function applyClientSearch() {
  const q = Filters.search;
  const root = document.querySelector('.view:not([hidden])') || document;
  const matches = function(row) {
    if (!q) return true;
    return (row.textContent || '').toLowerCase().indexOf(q) >= 0;
  };
  root.querySelectorAll(
    '#actors-table tbody tr, #cmds-table tbody tr, #capture-table tbody tr,' +
    '#sessions-list .sess-row,' +
    '#ioc-table tbody tr,' +
    '#ttp-table tbody tr, .ttp-row,' +
    '#payloads-table tbody tr,' +
    '#bazaar-table tbody tr,' +
    '#deobf-rows .deobf-row,' +
    '.tl-feed .tl-row'
  ).forEach(function(el) {
    el.style.display = matches(el) ? '' : 'none';
  });
}
```

The palette reads `_lastIntel`, `_lastSessions`, `_lastPayloads`. If any of those module variables do not already exist, add them and assign in the corresponding fetch handler — e.g. in the `/api/intel` refresh add `_lastIntel = d;`, in the sessions loader `_lastSessions = resp.sessions || [];`, in the payloads loader `_lastPayloads = resp.payloads || [];`. Declare them once near the other module state (`var _lastIntel = null, _lastSessions = [], _lastPayloads = [];`). Grep first — do not create a duplicate declaration.

- [ ] **Step 5: Verify the palette works**

```bash
go build -o /tmp/sl-t5 ./cmd/shardlure
export SHARDLURE_DATA=/tmp/t5-data && rm -rf /tmp/t5-data && mkdir -p /tmp/t5-data
printf 'data_dir: /tmp/t5-data\nadmin_ips: []\n' > /tmp/t5.yaml
/tmp/sl-t5 -config /tmp/t5.yaml ingest journal testdata/sample.journal --replace
nohup /tmp/sl-t5 -config /tmp/t5.yaml web :18093 >/tmp/t5.log 2>&1 &
sleep 3
CHROME=/home/het/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome
PWCORE=$(ls -d /home/het/.npm/_npx/*/node_modules/playwright-core/index.js | head -1)
cat > /tmp/t5.mjs <<JS
import pkg from '$PWCORE'; const { chromium } = pkg;
const b = await chromium.launch({ headless: true, executablePath: '$CHROME' });
const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
const errs = []; p.on('pageerror', e => errs.push(String(e)));
await p.goto('http://127.0.0.1:18093/intel', { waitUntil: 'load' });
await p.waitForTimeout(3000);
await p.click('#search-input');
await p.type('#search-input', '188');
await p.waitForTimeout(500);
console.log('palette visible:', await p.evaluate(() => { const e = document.getElementById('palette'); return !!e && !e.hidden; }));
console.log('palette rows:', await p.evaluate(() => document.querySelectorAll('#palette .pi').length));
await p.keyboard.press('ArrowDown');
console.log('sel after ArrowDown:', await p.evaluate(() => document.querySelectorAll('#palette .pi.sel').length));
await p.keyboard.press('Escape');
console.log('closed after Esc:', await p.evaluate(() => document.getElementById('palette').hidden));
console.log('pageerrors:', errs.length ? errs.join('; ') : 'none');
await p.screenshot({ path: '/tmp/t5-palette.png' });
await b.close();
JS
node /tmp/t5.mjs
```
Expected: `palette visible: true`, `palette rows:` > 0, `sel after ArrowDown: 1`, `closed after Esc: true`, `pageerrors: none`. **Read** `/tmp/t5-palette.png` to confirm grouped results render legibly.

Clean up: `kill %1; rm -rf /tmp/t5-data /tmp/t5.yaml /tmp/t5.mjs /tmp/sl-t5 /tmp/t5-palette.png /tmp/t5.log`

- [ ] **Step 6: Full gate + commit**

```bash
bash scripts/check-utf8.sh && go vet ./... && go test ./... && bash scripts/ci-web-smoke.sh
git add internal/web/intel.html
git commit -m "feat(intel): command palette replaces row-hiding search; filter scoped to active tab"
```

---

### Task 6: Tokenise the 28 hardcoded Dragon-red values in `intel.html`

**Files:**
- Modify: `internal/web/intel.html` (inline `<style>`: `:75`, `:113`, `:197`, `:232-233`, `:251`, `:273-275`, and every other `rgba(208,40,40,…)`)

**Interfaces:** none (CSS only, no behaviour change).

- [ ] **Step 1: Confirm the starting count**

Run: `grep -c "208,40,40" internal/web/intel.html`
Expected: `28`.

- [ ] **Step 2: Replace every literal with a token**

These are Dragon's red hardcoded where the theme's accent belongs, so `/intel` still shows red on Signal/Meridian/Sprite. Replace each occurrence by alpha:

- `rgba(208,40,40,0.08)` → `color-mix(in srgb, var(--accent) 8%, transparent)`
- `rgba(208,40,40,0.15)` → `color-mix(in srgb, var(--accent) 15%, transparent)`
- `rgba(208,40,40,0.20)` → `color-mix(in srgb, var(--accent) 20%, transparent)`
- `rgba(208,40,40,0.4)` / `0.45` / `0.5` / `0.55` → `color-mix(in srgb, var(--accent) 40%, transparent)` / `45%` / `50%` / `55%`
- `rgba(208,40,40,0)` (a keyframe end-state) → `transparent`

Work through them one at a time and keep the surrounding property intact — several are inside `box-shadow` lists and `@keyframes livePulse`, where only the colour token changes.

- [ ] **Step 3: Verify zero literals remain and CSS is intact**

```bash
grep -c "208,40,40" internal/web/intel.html      # expect 0
grep -c "d02828" internal/web/intel.html         # expect 1 (the inert :root base default — leave it)
```
Expected: `0`, then `1`.

Brace balance (a broken `@keyframes` would silently kill the animation):
```bash
node -e "const c=require('fs').readFileSync('internal/web/intel.html','utf8');const s=c.slice(c.indexOf('<style>'),c.indexOf('</style>'));const o=(s.match(/{/g)||[]).length,x=(s.match(/}/g)||[]).length;console.log('braces',o,x);process.exit(o===x?0:1)"
```
Expected: matching counts, exit 0.

- [ ] **Step 4: Verify no red survives in any theme**

```bash
go build -o /tmp/sl-t6 ./cmd/shardlure
export SHARDLURE_DATA=/tmp/t6-data && rm -rf /tmp/t6-data && mkdir -p /tmp/t6-data
printf 'data_dir: /tmp/t6-data\nadmin_ips: []\n' > /tmp/t6.yaml
/tmp/sl-t6 -config /tmp/t6.yaml ingest journal testdata/sample.journal --replace
nohup /tmp/sl-t6 -config /tmp/t6.yaml web :18094 >/tmp/t6.log 2>&1 &
sleep 3
CHROME=/home/het/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome
PWCORE=$(ls -d /home/het/.npm/_npx/*/node_modules/playwright-core/index.js | head -1)
mkdir -p /tmp/t6-shots
cat > /tmp/t6.mjs <<JS
import pkg from '$PWCORE'; const { chromium } = pkg;
const b = await chromium.launch({ headless: true, executablePath: '$CHROME' });
for (const [name, set] of [
  ['signal-dark',  "localStorage.setItem('shardlure_theme','signal');localStorage.setItem('shardlure_mode','dark')"],
  ['signal-light', "localStorage.setItem('shardlure_theme','signal');localStorage.setItem('shardlure_mode','light')"],
  ['meridian',     "localStorage.setItem('shardlure_theme','meridian')"],
  ['sprite',       "localStorage.setItem('shardlure_theme','sprite')"]]) {
  const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
  const errs = []; p.on('pageerror', e => errs.push(String(e)));
  await p.goto('http://127.0.0.1:18094/intel', { waitUntil: 'load' });
  await p.evaluate(set); await p.reload({ waitUntil: 'load' }); await p.waitForTimeout(2600);
  const nav = await p.evaluate(() => { const a = document.querySelector('.nav a.active'); return a ? getComputedStyle(a).backgroundColor : 'none'; });
  console.log(name, '| nav active bg:', nav, '| errors:', errs.length ? errs.join('; ') : 'none');
  await p.screenshot({ path: '/tmp/t6-shots/' + name + '.png' });
  await p.close();
}
await b.close();
JS
node /tmp/t6.mjs
```
Expected: `errors: none` everywhere, and the `nav active bg` is a **theme-appropriate** colour (a lime-ish rgba for Signal, teal for Meridian, coral for Sprite) — **not** `rgb(208, 40, 40)`-derived. **Read** all four screenshots and confirm no red chrome remains on the nav, selected rows, badges, or live dot.

Clean up: `kill %1; rm -rf /tmp/t6-data /tmp/t6.yaml /tmp/t6.mjs /tmp/sl-t6 /tmp/t6-shots /tmp/t6.log`

- [ ] **Step 5: Full gate + commit**

```bash
bash scripts/check-utf8.sh && go vet ./... && go test ./... && bash scripts/ci-web-smoke.sh
git add internal/web/intel.html
git commit -m "fix(themes): tokenise 28 hardcoded Dragon-red values in intel.html"
```

---

### Task 7: README — palette line (Wave 2 docs)

**Files:**
- Modify: `README.md` (Features list; roadmap)

**Interfaces:** none.

- [ ] **Step 1: Add the palette bullet**

After the "Two dashboards, split by job" bullet added in Task 4, insert:

```markdown
- **Command palette:** the search box in the intel console is a real lookup, not a row filter — type any IP, actor, session id, command, or payload hash and get grouped, actionable results (jump to an actor, enrich an IP, open a session transcript or payload) with arrow-key navigation. It searches the API, so it finds records that aren't on the current tab.
```

- [ ] **Step 2: Add the roadmap entries**

In the completed-items roadmap list, append:

```markdown
- [x] Globe artifacts on every theme (satellites, live badge, per-actor analytics chips)
- [x] Ambient globe dashboard (analyst widgets consolidated in `/intel`)
- [x] Intel command palette (actors / IPs / sessions / commands / payloads)
```

- [ ] **Step 3: Verify**

Run: `bash scripts/check-utf8.sh && grep -c "Command palette" README.md`
Expected: UTF-8 OK, and `1`.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document the intel command palette"
```

---

## Self-review notes

- **Spec coverage:** (A) → Task 2; (B) → Task 3 (+ Task 1 for the gauge's data); (C) → Task 5; (D) → Task 6; (E) → Tasks 4 and 7. Every spec section maps to a task.
- **Wave split:** Tasks 1–4 are Wave 1 (`index.html`, Go, README); Tasks 5–7 are Wave 2 (`intel.html`, README). Task 1 precedes Task 3 because the gauge needs its fields.
- **No-CSS constraint honoured:** Task 2 adds zero overlay CSS (the rules are unscoped/token-driven). Task 3 copies gauge classes because those *are* `intel.html`-local, which is a different thing and verified.
- **Naming consistency:** `renderGauge(summary, intentCounts, kindCounts)` is used identically in Tasks 1 and 3; palette functions (`buildPalette`, `renderPalette`, `movePaletteSel`, `activatePaletteSel`, `closePalette`) are declared and referenced with the same names throughout Task 5.
- **Removal is ID-driven** (Task 3 Step 1) because `renderTopCountries` uses `querySelector('#top-countries tbody')` and would be missed by an ID-only `getElementById` grep — the trap the spec called out.
