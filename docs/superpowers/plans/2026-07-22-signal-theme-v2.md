# Signal Theme (v2.0.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the live dashboard's v2.0.0 theme set — a new **Signal** theme with a dark/light toggle (default), Meridian and Sprite retained, **Dragon deleted**, and **Cobe as the only globe engine** (globe.gl removed) — then delete the `demos/themes/` study folder.

**Architecture:** Themes are pure CSS token blocks selected by `<html data-theme="…">`. Signal adds a second axis, `data-mode="dark|light"`, that only its block reads. The backend stores two keystore keys (`ui.theme`, new `ui.mode`); the frontend applies both before first paint and swaps the single Cobe globe on theme change. Removing Dragon removes the only `globe.gl` consumer and its external texture URLs.

**Tech Stack:** Go (`net/http`, `modernc.org/sqlite`), vanilla JS, CSS custom properties, Cobe (WebGL globe, imported from `esm.sh`), `go test`, headless Chromium (bundled with Playwright) for visual verification.

## Global Constraints

- Theme ids are exactly `signal | meridian | sprite`; default `signal`. Validator must reject anything else (including the old `dragon`).
- Mode values are exactly `dark | light`; default `dark`. Only meaningful when theme is `signal`.
- Keystore keys: `ui.theme` (existing), `ui.mode` (new, value `"ui.mode"`).
- All tracked files must be valid UTF-8 (no BOM/NUL) — CI runs `scripts/check-utf8.sh`.
- CI runs `go vet ./...` and `go test ./...`; both must stay green. There is no JS/CSS unit-test harness — frontend correctness is verified via `scripts/ci-web-smoke.sh` and headless-Chromium screenshots.
- No new third-party runtime dependency. Removing globe.gl must not add a replacement.
- Signal dark tokens (from `demos/themes/phosphor.html`): bg `#0f1113`, surface `#131517`, surface-raised `#1c1e20`, border `#2a2d31`, ink `#f7f7f8`, ink-2 `#898a8b`, ink-3 `#565a5e`, accent `#d1fe17`, on-accent `#14151a`, danger `#e72930`, ok `#40d986`, warn `#f3c977`. Type: display `"Space Grotesk"`, sans `"Inter"`.
- Signal light tokens (from `demos/themes/anode.html`): bg `#efefe9`, surface `#f7f7f2`, surface-raised `#ffffff`, border `#d6d6cc`, ink `#14151a`, ink-2 `#5c5e63`, ink-3 `#8b8d92`, accent `#b6d900`, danger `#c41e25`, ok `#1f8a4c`, warn `#9a6b00`.
- Signal Cobe params — dark: `dark:1, diffuse:1.05, mapBrightness:2.8, mapBaseBrightness:0.015, baseColor:[0.07,0.08,0.09], markerColor:[0.82,0.99,0.09], glowColor:[0.12,0.14,0.10]`; light: `dark:0, diffuse:1.15, mapBrightness:1.35, mapBaseBrightness:0.08, baseColor:[0.92,0.92,0.88], markerColor:[0.55,0.68,0.0], glowColor:[0.85,0.86,0.80]`.

---

## File Structure

- `internal/settings/keystore.go` — add `KeyUIMode` constant; update `ui.theme` doc comment. (~2 lines)
- `internal/web/api_settings.go` — theme validator accepts `signal|meridian|sprite`; add `ui.mode` validation + registry entry.
- `internal/web/theme_settings_test.go` — update theme cases; add mode-validation test.
- `internal/web/themes.css` — delete `dragon` block + rules; add `signal` dark block + `signal`+`light` overrides; port shared-chrome rules to also match `signal`.
- `internal/web/cobe-globe.js` — add `signal` case to `cobeThemeConfig(theme, mode)` (dark + light param sets).
- `internal/web/index.html` — head-inline default `signal`/`dark`; `applyTheme`/new `applyMode`; delete `ensureDragonGlobe`/`usesCobeTheme`/globe.gl import + textures; collapse `syncGlobeEngine` to Cobe-only.
- `internal/web/intel.html` — head-inline default `signal`/`dark`; picker cards (drop Dragon, add dark/light toggle); `applyTheme`/`applyMode`; BroadcastChannel carries mode.
- `README.md`, `CLAUDE.md` — theme docs.
- `demos/themes/` — deleted last.

---

### Task 1: Settings backend — `ui.mode` key, accept `signal`, reject `dragon`

**Files:**
- Modify: `internal/settings/keystore.go` (Key constants block ~line 55-63)
- Modify: `internal/web/api_settings.go` (registry ~line 85; validator ~line 258-265)
- Test: `internal/web/theme_settings_test.go`

**Interfaces:**
- Produces: `settings.KeyUIMode = "ui.mode"`; validator accepts theme ∈ {signal,meridian,sprite} and mode ∈ {dark,light}; registry contains a `kindText` entry for `KeyUIMode`.

- [ ] **Step 1: Update the failing tests first**

In `internal/web/theme_settings_test.go`, replace the theme list in `TestValidateUITheme` and add a mode test. Change the `good` loop and add a new function:

```go
func TestValidateUITheme(t *testing.T) {
	meta, ok := metaFor(settings.KeyUITheme)
	if !ok {
		t.Fatal("ui.theme missing from settingsRegistry")
	}
	for _, good := range []string{"signal", "meridian", "sprite"} {
		if msg := validateSetting(meta, good); msg != "" {
			t.Fatalf("%q rejected: %s", good, msg)
		}
	}
	if msg := validateSetting(meta, "dragon"); msg == "" {
		t.Fatal("expected dragon to be rejected (removed in v2.0)")
	}
	if msg := validateSetting(meta, "neon"); msg == "" {
		t.Fatal("expected neon to be rejected")
	}
}

func TestValidateUIMode(t *testing.T) {
	meta, ok := metaFor(settings.KeyUIMode)
	if !ok {
		t.Fatal("ui.mode missing from settingsRegistry")
	}
	for _, good := range []string{"dark", "light"} {
		if msg := validateSetting(meta, good); msg != "" {
			t.Fatalf("%q rejected: %s", good, msg)
		}
	}
	if msg := validateSetting(meta, "sepia"); msg == "" {
		t.Fatal("expected sepia to be rejected")
	}
}
```

Also update the existing `TestSettingsSaveUITheme` if it saves `"meridian"` — that still passes, leave it; but if any assertion references `"dragon"`, change it to `"signal"`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/web/ -run 'TestValidateUITheme|TestValidateUIMode' -v`
Expected: FAIL — `ui.mode missing from settingsRegistry` and/or `dragon` accepted.

- [ ] **Step 3: Add the keystore constant**

In `internal/settings/keystore.go`, in the Key constants block (after `KeyUITheme = "ui.theme"` ~line 63), add:

```go
	KeyUITheme = "ui.theme"
	// KeyUIMode is the light/dark mode for themes that support it (Signal).
	// Allowed: dark | light. Empty / unset means dark (default).
	KeyUIMode = "ui.mode"
```

Also update the comment above `KeyUITheme` (currently mentions dragon|meridian|sprite / default dragon) to: `// Allowed: signal | meridian | sprite. Empty / unset means signal (default).`

- [ ] **Step 4: Add registry entry + validator branch**

In `internal/web/api_settings.go`, after the `KeyUITheme` registry entry (~line 85) add:

```go
	{Key: settings.KeyUITheme, Kind: kindText, Label: "UI theme"},
	{Key: settings.KeyUIMode, Kind: kindText, Label: "Light/dark mode"},
```

In `validateSetting`, update the `KeyUITheme` case and add a `KeyUIMode` case (in the `kindText` block ~line 258):

```go
		if m.Key == settings.KeyUITheme {
			switch val {
			case "signal", "meridian", "sprite":
			default:
				return "theme must be signal, meridian, or sprite"
			}
		}
		if m.Key == settings.KeyUIMode {
			switch val {
			case "dark", "light":
			default:
				return "mode must be dark or light"
			}
		}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/web/ -run 'TestValidateUITheme|TestValidateUIMode|TestSettingsSaveUITheme' -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add internal/settings/keystore.go internal/web/api_settings.go internal/web/theme_settings_test.go
git commit -m "feat(settings): add ui.mode key; theme validator signal/meridian/sprite (drop dragon)"
```

---

### Task 2: Signal theme CSS (add signal dark + light; delete dragon)

**Files:**
- Modify: `internal/web/themes.css` (dragon block lines 4-39; shared-chrome rules throughout)

**Interfaces:**
- Consumes: nothing.
- Produces: `html[data-theme="signal"]` (dark tokens) and `html[data-theme="signal"][data-mode="light"]` (light overrides); every `[data-theme="meridian"], [data-theme="sprite"]` shared-chrome selector list also includes `[data-theme="signal"]`.

- [ ] **Step 1: Replace the dragon token block with the signal dark block**

In `internal/web/themes.css`, replace lines 1-39 (the header comment + `html, html[data-theme="dragon"] { … }` block) with:

```css
/* ShardLure UI themes — applied via <html data-theme="…">.
   Signal is the default; it supports data-mode="dark|light". */

html,
html[data-theme="signal"] {
  --bg: #0f1113;
  --glass: #131517;
  --glass-2: #1c1e20;
  --sheet: #131517;
  --paper: #0f1113;
  --line: #2a2d31;
  --line-strong: #3a3d41;
  --line-soft: #1e2024;
  --text: #f7f7f8;
  --ink: #f7f7f8;
  --dim: #898a8b;
  --muted: #565a5e;
  --accent: #d1fe17;
  --accent-2: #40d986;
  --good: #40d986;
  --warn: #f3c977;
  --danger: #e72930;
  --ok: #40d986;
  --blue-team: #5a8fd4;
  --red-team: #e72930;
  --mono: "JetBrains Mono", ui-monospace, monospace;
  --sans: "Inter", system-ui, -apple-system, sans-serif;
  --display: "Space Grotesk", "Inter", system-ui, sans-serif;
  --radius: 12px;
  --chunk: 0px;
  --shadow: none;
  --panel-bg: var(--glass);
  --body-bg: var(--bg);
  --vignette: radial-gradient(ellipse at center, transparent 40%, rgba(0, 0, 0, 0.5) 95%);
  --globe-atmosphere: #d1fe17;
  --globe-point: #d1fe17;
  --bg-pane: var(--glass);
}

html[data-theme="signal"][data-mode="light"] {
  --bg: #efefe9;
  --glass: #f7f7f2;
  --glass-2: #ffffff;
  --sheet: #f7f7f2;
  --paper: #efefe9;
  --line: #d6d6cc;
  --line-strong: #c4c4b8;
  --line-soft: #e0e0d6;
  --text: #14151a;
  --ink: #14151a;
  --dim: #5c5e63;
  --muted: #8b8d92;
  --accent: #b6d900;
  --accent-2: #1f8a4c;
  --good: #1f8a4c;
  --warn: #9a6b00;
  --danger: #c41e25;
  --ok: #1f8a4c;
  --red-team: #c41e25;
  --globe-atmosphere: #b6d900;
  --globe-point: #b6d900;
  --vignette: radial-gradient(ellipse at 50% 42%, rgba(255, 255, 255, 0.5) 0%, transparent 70%);
}
```

- [ ] **Step 2: Add `signal` to the shared-chrome selector lists**

The file has many rules of the form `html[data-theme="meridian"] X, html[data-theme="sprite"] X { … }` (light-theme chrome). Signal-light needs the same treatment; Signal-dark uses the token defaults. For each such shared rule that should apply to Signal-light, extend the selector list with `html[data-theme="signal"][data-mode="light"] X`. Apply this to the light-surface rules (panels, tables, inputs, chips, sidebar, topbar, mitre cells, modals) — i.e. the blocks between lines ~112 and ~797.

Concretely, run this guided transform: for each selector group that pairs meridian+sprite, append the signal-light selector. Example — the panel rule at lines ~635-639:

```css
html[data-theme="meridian"] .panel,
html[data-theme="sprite"] .panel,
html[data-theme="signal"][data-mode="light"] .panel,
html[data-theme="meridian"] .pane,
html[data-theme="sprite"] .pane,
html[data-theme="signal"][data-mode="light"] .pane {
  border: 1px solid var(--line);
}
```

Delete the dragon-specific rule `html[data-theme="dragon"] #cobe-stage { display: none !important; }` (line ~560) — Signal uses Cobe, so the stage must stay visible.

- [ ] **Step 3: Verify no dragon references remain and CSS is well-formed**

Run: `grep -c dragon internal/web/themes.css`
Expected: `0`

Run: `node -e "const c=require('fs').readFileSync('internal/web/themes.css','utf8'); const o=(c.match(/{/g)||[]).length, cl=(c.match(/}/g)||[]).length; console.log('braces', o, cl); process.exit(o===cl?0:1)"`
Expected: matching brace counts, exit 0.

- [ ] **Step 4: Commit**

```bash
git add internal/web/themes.css
git commit -m "feat(themes): add Signal dark+light CSS; remove dragon block"
```

---

### Task 3: Cobe globe config — add `signal` (dark + light), keep meridian/sprite

**Files:**
- Modify: `internal/web/cobe-globe.js` (`cobeThemeConfig` ~lines 457-502)

**Interfaces:**
- Consumes: nothing.
- Produces: `cobeThemeConfig(theme, mode)` returns a Signal config keyed on `mode` when `theme === "signal"`; existing meridian/sprite behavior unchanged when `mode` is omitted.

- [ ] **Step 1: Add the signal branch and a mode parameter**

In `internal/web/cobe-globe.js`, change the signature and add a `signal` branch at the top of `cobeThemeConfig` (before the `sprite` check ~line 459):

```js
export function cobeThemeConfig(theme, mode) {
  if (theme === "signal") {
    if (mode === "light") {
      return {
        dark: 0,
        diffuse: 1.15,
        mapSamples: 8000,
        mapBrightness: 1.35,
        mapBaseBrightness: 0.08,
        baseColor: [0.92, 0.92, 0.88],
        markerColor: [0.55, 0.68, 0.0],
        glowColor: [0.85, 0.86, 0.80],
        markerElevation: 0.022,
        arcColor: [0.55, 0.68, 0.0],
        arcWidth: 0.5,
        arcHeight: 0.3,
        colors: {
          home: [0.55, 0.68, 0.0],
          hot: [0.77, 0.12, 0.15],
          cool: [0.12, 0.54, 0.30],
          arc: [0.55, 0.68, 0.0],
        },
      };
    }
    return {
      dark: 1,
      diffuse: 1.05,
      mapSamples: 8000,
      mapBrightness: 2.8,
      mapBaseBrightness: 0.015,
      baseColor: [0.07, 0.08, 0.09],
      markerColor: [0.82, 0.99, 0.09],
      glowColor: [0.12, 0.14, 0.10],
      markerElevation: 0.03,
      arcColor: [0.82, 0.99, 0.09],
      arcWidth: 0.5,
      arcHeight: 0.32,
      colors: {
        home: [0.82, 0.99, 0.09],
        hot: [0.90, 0.16, 0.19],
        cool: [0.25, 0.85, 0.52],
        arc: [0.82, 0.99, 0.09],
      },
    };
  }
  if (theme === "sprite") {
```

Leave the sprite and meridian returns unchanged below.

- [ ] **Step 2: Verify JS parses**

Run: `node --check internal/web/cobe-globe.js`
Expected: no output, exit 0.

- [ ] **Step 3: Commit**

```bash
git add internal/web/cobe-globe.js
git commit -m "feat(themes): Cobe config for Signal dark+light globe"
```

---

### Task 4: Globe engine — remove globe.gl + Dragon, Cobe-only (index.html)

**Files:**
- Modify: `internal/web/index.html` (globe.gl import + textures ~line 568-580; `usesCobeTheme` ~611; `setDragonGlobeVisible`; `syncGlobeEngine` ~639-672; head-inline ~1-12; `currentThemeId` ~422; `applyTheme` ~425)

**Interfaces:**
- Consumes: `cobeThemeConfig(theme, mode)` from Task 3; `applyMode` (defined here).
- Produces: `currentMode()` returns `dark|light`; `syncGlobeEngine(theme)` always uses Cobe; no globe.gl symbols remain.

- [ ] **Step 1: Head-inline default → signal + mode**

Replace the head-inline theme script (lines ~5-12) in `index.html`:

```html
  <script>
    try {
      var t = localStorage.getItem('shardlure_theme') || 'signal';
      var m = localStorage.getItem('shardlure_mode') || 'dark';
      document.documentElement.setAttribute('data-theme', t);
      if (t === 'signal') document.documentElement.setAttribute('data-mode', m);
    } catch (e) {
      document.documentElement.setAttribute('data-theme', 'signal');
      document.documentElement.setAttribute('data-mode', 'dark');
    }
  </script>
```

Also change the `<html lang="en" data-theme="dragon">` opening tag (line 2) to `<html lang="en" data-theme="signal" data-mode="dark">`.

- [ ] **Step 2: Delete globe.gl engine + Dragon helpers**

- Delete `ensureDragonGlobe()` (the whole function ~line 568, including the `import('https://esm.sh/globe.gl@2.32.0')` and the three `https://networkshard.com/...` texture URLs).
- Delete `setDragonGlobeVisible()`.
- Delete `usesCobeTheme()` (~line 611).
- Delete any module-scope `globe`/`_dragonGlobePromise` variables used only by the above.

- [ ] **Step 3: Collapse `syncGlobeEngine` to Cobe-only**

Replace `syncGlobeEngine` (lines ~639-672) with:

```js
function currentMode() {
  if (currentThemeId() !== 'signal') return 'dark';
  return document.documentElement.getAttribute('data-mode') || 'dark';
}

function syncGlobeEngine(theme) {
  theme = theme || currentThemeId();
  return ensureCobeBoot().then(function (boot) {
    return boot.ensure(theme, currentMode());
  }).then(function () {
    if (typeof applyGlobeOverlays === 'function') applyGlobeOverlays();
    if (typeof _lastHome !== 'undefined' && _lastHome && window.ShardCobe) {
      window.ShardCobe.updateData(_lastHome, typeof _lastActors !== 'undefined' ? _lastActors : []);
    }
  }).catch(function () {});
}
```

(Note: `boot.ensure` now takes `(theme, mode)`; Task 5 threads mode through cobe-boot.js. If `boot.ensure` currently takes only `theme`, update its call site in `cobe-boot.js` to accept and forward `mode` to `cobeThemeConfig`.)

- [ ] **Step 4: Add `applyMode` + default `signal` in `currentThemeId`/`applyTheme`**

Change `currentThemeId` (line ~423) fallback from `'dragon'` to `'signal'`. In `applyTheme`, after setting `data-theme`, ensure mode is applied for signal. Add:

```js
function applyMode(mode) {
  mode = (mode === 'light') ? 'light' : 'dark';
  try { localStorage.setItem('shardlure_mode', mode); } catch (e) {}
  if (currentThemeId() === 'signal') {
    document.documentElement.setAttribute('data-mode', mode);
  } else {
    document.documentElement.removeAttribute('data-mode');
  }
  try { syncGlobeEngine(currentThemeId()); } catch (e) {}
}
```

In `applyTheme(id)`, after `document.documentElement.setAttribute('data-theme', id)`, add:

```js
  if (id === 'signal') {
    document.documentElement.setAttribute('data-mode', localStorage.getItem('shardlure_mode') || 'dark');
  } else {
    document.documentElement.removeAttribute('data-mode');
  }
```

Update the three `|| 'dragon'` fallbacks in `syncThemeFromServer` / `storage` handlers (lines ~454-460) to `|| 'signal'`.

- [ ] **Step 5: Verify no globe.gl / dragon references remain**

Run: `grep -nE "globe\.gl|networkshard\.com|ensureDragonGlobe|usesCobeTheme|dragon" internal/web/index.html`
Expected: no output (empty).

- [ ] **Step 6: Commit**

```bash
git add internal/web/index.html internal/web/cobe-boot.js
git commit -m "feat(globe): Cobe-only engine; remove globe.gl + Dragon from index.html"
```

---

### Task 5: Settings UI — picker (drop Dragon) + Signal dark/light toggle (intel.html)

**Files:**
- Modify: `internal/web/intel.html` (head-inline ~1-12; picker cards ~1626-1655; `applyTheme`/`applyMode` ~1781-1830; `selectTheme` ~2385; BroadcastChannel ~1823)
- Modify: `internal/web/cobe-boot.js` (`ensure(theme, mode)` — thread mode to `cobeThemeConfig`)

**Interfaces:**
- Consumes: `KeyUIMode` (Task 1); `cobeThemeConfig(theme, mode)` (Task 3); `applyMode` pattern (Task 4).
- Produces: a working dark/light toggle that persists `ui.mode` and re-skins Signal live.

- [ ] **Step 1: Head-inline + `<html>` tag (mirror index.html Task 4 Step 1)**

Apply the identical head-inline replacement and `<html data-theme="signal" data-mode="dark">` change to `intel.html`.

- [ ] **Step 2: Update the theme picker cards**

In `intel.html` remove the Dragon card (~lines 1627-1635) and update the remaining swatches/labels. Signal card first:

```html
<button type="button" class="theme-card" data-theme-id="signal" role="radio" aria-checked="true">
  <div class="swatch" aria-hidden="true">
    <span style="background:#0f1113"></span><span style="background:#1c1e20"></span>
    <span style="background:#f7f7f8"></span><span style="background:#d1fe17"></span>
  </div>
  <div class="tname">Signal</div>
</button>
```

(Class is `swatch` — matches the existing Meridian/Sprite cards, not `tswatch`.)

Keep the Meridian and Sprite cards (lines ~1636-1651) as-is.

- [ ] **Step 3: Add the dark/light toggle markup**

Immediately after the `theme-picker` div (~line 1655), add a mode toggle that JS shows only for Signal:

```html
<div class="mode-toggle" id="mode-toggle" style="margin-top:12px;display:none">
  <span class="set-label">Mode</span>
  <button type="button" class="chip" data-mode="dark">Dark</button>
  <button type="button" class="chip" data-mode="light">Light</button>
</div>
```

- [ ] **Step 4: Add `applyMode` + wire the toggle**

Add the same `applyMode` function as index.html (Task 4 Step 4) to intel.html's theme block (~line 1781). In `selectTheme(id)` (~line 2385), after applying the theme, show/hide the toggle:

```js
  var mt = document.getElementById('mode-toggle');
  if (mt) mt.style.display = (id === 'signal') ? '' : 'none';
```

Add a click handler (near the existing theme-card handler ~line 2404):

```js
document.getElementById('mode-toggle').addEventListener('click', function (e) {
  var b = e.target.closest('[data-mode]');
  if (!b) return;
  var mode = b.getAttribute('data-mode');
  applyMode(mode);
  postSetting({ key: 'ui.mode', value: mode });
  document.querySelectorAll('#mode-toggle .chip').forEach(function (c) {
    c.classList.toggle('on', c.getAttribute('data-mode') === mode);
  });
});
```

On load, initialize the toggle's active chip and visibility from `localStorage.getItem('shardlure_mode') || 'dark'` and the current theme.

- [ ] **Step 5: Thread mode through BroadcastChannel + cobe-boot**

In the BroadcastChannel handler (~line 1823) also broadcast/receive `mode` and call `applyMode(ev.data.mode)` when present. Update the three `|| 'dragon'` fallbacks to `|| 'signal'`.

In `internal/web/cobe-boot.js`: change `async function ensure(theme)` (line ~82) to `async function ensure(theme, mode)`, store the mode in the existing module-scope state (add a `let _mode = "dark";` beside `_theme`, and set `_mode = mode || "dark";` inside `ensure`). Then update **both** `cobeThemeConfig(theme)` call sites — line ~105 (`cobeThemeConfig(theme, _mode)`) and line ~160 (`cobeThemeConfig(_theme, _mode)`, inside the other closure that reads `_theme`). Both call sites must pass mode or the light globe won't repaint on live theme changes.

- [ ] **Step 6: Verify no dragon references remain in intel.html**

Run: `grep -nc dragon internal/web/intel.html`
Expected: `0`

Run: `node --check internal/web/cobe-boot.js`
Expected: exit 0.

- [ ] **Step 7: Commit**

```bash
git add internal/web/intel.html internal/web/cobe-boot.js
git commit -m "feat(settings): theme picker drops Dragon; Signal dark/light toggle"
```

---

### Task 6: Visual verification (all four states) via web-smoke + headless Chromium

**Files:** none (verification only).

**Interfaces:**
- Consumes: the built binary serving the embedded dashboard.

- [ ] **Step 1: Build + smoke + full test suite**

Run:
```bash
go build -o /tmp/shardlure-v2 ./cmd/shardlure && go vet ./... && go test ./... && bash scripts/ci-web-smoke.sh
```
Expected: build OK, vet clean, all tests PASS, smoke `all checks passed`.

- [ ] **Step 2: Render each theme state to screenshots**

Start a seeded dashboard on a test port, then screenshot Signal-dark, Signal-light, Meridian, Sprite. Use the bundled Chromium (channel `chrome` is not installed):

```bash
CHROME=/home/het/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome
PWCORE=$(ls -d /home/het/.npm/_npx/*/node_modules/playwright-core/index.js | head -1)
/tmp/shardlure-v2 -config /tmp/v2.yaml web :18090 &  # or `live` with a sample cowrie.json
sleep 2
mkdir -p /tmp/v2-shots
cat > /tmp/v2-shot.mjs <<JS
import pkg from '$PWCORE'; const { chromium } = pkg;
const b = await chromium.launch({ headless: true, executablePath: '$CHROME' });
const states = [
  ['signal-dark',  "localStorage.setItem('shardlure_theme','signal');localStorage.setItem('shardlure_mode','dark')"],
  ['signal-light', "localStorage.setItem('shardlure_theme','signal');localStorage.setItem('shardlure_mode','light')"],
  ['meridian',     "localStorage.setItem('shardlure_theme','meridian')"],
  ['sprite',       "localStorage.setItem('shardlure_theme','sprite')"],
];
for (const [name, set] of states) {
  const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
  await p.goto('http://127.0.0.1:18090/', { waitUntil: 'load' });
  await p.evaluate(set); await p.reload({ waitUntil: 'load' });
  await p.waitForTimeout(2200);
  await p.screenshot({ path: '/tmp/v2-shots/' + name + '.png' });
  await p.close();
}
await b.close();
JS
node /tmp/v2-shot.mjs
ls -la /tmp/v2-shots/
```
Expected: four PNGs written.

- [ ] **Step 3: Inspect the screenshots**

Read each of `/tmp/v2-shots/{signal-dark,signal-light,meridian,sprite}.png`. Confirm: Signal dark = near-black field + chartreuse accent + Cobe globe painting; Signal light = paper field + lime accent + pale globe; Meridian/Sprite unchanged; no missing/black globe; no dragon-red anywhere.

- [ ] **Step 4: Stop the server, clean up**

```bash
kill %1 2>/dev/null; rm -f /tmp/v2-shot.mjs /tmp/shardlure-v2; rm -rf /tmp/v2-shots
```

(No commit — verification only. If a screenshot reveals a defect, fix in the owning task's file and re-run this task.)

---

### Task 7: Docs + delete `demos/themes/`

**Files:**
- Modify: `README.md` (Features theme bullet; roadmap; any "Noctiluca"/"Dragon" prose)
- Modify: `CLAUDE.md` (Web-layer themes bullet; remove the "demos/themes/ is NOT the live UI" note)
- Delete: `demos/themes/` (whole directory)

**Interfaces:** none.

- [ ] **Step 1: README theme docs**

In `README.md`, replace the multi-theme feature bullet (the one naming Dragon/Meridian/Sprite/Noctiluca) with:

```markdown
- **Themes:** ships **Signal** (default — a near-black signal field with a light/dark toggle), plus **Meridian** and **Sprite**. Switchable live from the settings panel; the selected theme and Signal's mode persist in SQLite. One WebGL globe engine (Cobe) across all themes.
```

Search for other `Dragon`/`Noctiluca` mentions (`grep -n "Dragon\|Noctiluca\|globe.gl" README.md`) and update/remove each (roadmap checkboxes, architecture notes).

- [ ] **Step 2: CLAUDE.md theme docs**

In `CLAUDE.md`, replace the "Themes: only 3 are implemented (dragon/meridian/sprite)…" bullet and the "demos/themes/ is NOT the live UI" bullet with:

```markdown
- **Themes: 3 implemented** — `signal` (default; supports `data-mode="dark|light"`), `meridian`, `sprite`. `themes.css` defines exactly those and `validateSetting` hard-rejects anything else. Persisted as keystore `ui.theme` (+ `ui.mode` for Signal), server > localStorage, synced across tabs via `BroadcastChannel`. **One globe engine (Cobe)** for all themes — globe.gl and the Dragon theme were removed in v2.0.0.
```

- [ ] **Step 3: Delete the demo folder**

Run: `git rm -r demos/themes/`
Expected: the 8 theme HTML files + `_shared.js`/`_intel.js`/`_intel_data.js`/index.html staged for deletion.

- [ ] **Step 4: Verify nothing references demos/themes**

Run: `grep -rn "demos/themes" README.md CLAUDE.md internal/ scripts/ 2>/dev/null`
Expected: no output.

- [ ] **Step 5: Final full verification**

Run: `bash scripts/check-utf8.sh && go vet ./... && go test ./... && go build -o /tmp/shardlure-v2 ./cmd/shardlure && bash scripts/ci-web-smoke.sh && rm -f /tmp/shardlure-v2`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: v2.0.0 theme docs (Signal default, Cobe-only); remove demos/themes"
```

---

## Post-plan: release (human-triggered)

Not a task in this plan — after merge, the maintainer follows [the release procedure](../../RELEASING.md). The version is ldflags-injected (`cmd/shardlure/main.go:33`); no source edit. Series continues v2.0.0 → v2.0.1 → …

## Self-review notes

- **Spec coverage:** data model (T1), CSS dark+light (T2), Cobe signal config (T3), globe.gl/Dragon removal (T4), settings UI + toggle (T5), verification of all 4 states (T6), README/CLAUDE.md + demo removal (T7), release prep (post-plan). All spec sections mapped.
- **Ordering rationale:** backend validator first (T1, TDD) so the API accepts `signal`/`mode` before the UI sends them; CSS + Cobe (T2/T3) before the HTML/JS that references them (T4/T5); verify (T6) before the irreversible demo deletion (T7).
- **Mode-through-cobe:** `cobeThemeConfig` gains a `mode` param (T3); `cobe-boot.js ensure()` and both HTML call sites thread it (T4/T5) — consistent name `cobeThemeConfig(theme, mode)` everywhere.
