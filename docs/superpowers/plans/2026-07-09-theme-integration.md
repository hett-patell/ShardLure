# Theme Integration (Dragon / Meridian / Sprite) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship three selectable UI themes (Dragon default, Meridian, Sprite) across the live globe (`/`) and intel console (`/intel`), with a Theme Picker in Settings that persists via the existing `app_settings` keystore.

**Architecture:** Keep the current page structure and APIs. Introduce a single `ui.theme` setting (`dragon` | `meridian` | `sprite`) stored in SQLite through the existing settings whitelist. Apply themes by setting `data-theme` on `<html>` and swapping CSS custom properties (+ theme-specific chrome). Do **not** replace `globe.gl` in v1 — theme the surrounding UI and globe colors first; Cobe/stickers/satellites are a follow-up phase so the picker ships without rewriting the 3D stack.

**Tech Stack:** Go (`internal/settings`, `internal/web`), embedded HTML/CSS/JS (`index.html`, `intel.html`), existing `/api/settings*` routes, SQLite `app_settings`.

## Global Constraints

- Default theme remains **Dragon** (`dragon`) — zero visual change for existing deploys until an operator picks another theme.
- Theme IDs are exactly: `dragon`, `meridian`, `sprite` (lowercase, stable API values).
- Persist via `settings.KeyUITheme = "ui.theme"` in `app_settings` (same path as AbuseIPDB knobs) — **not** env-only, **not** a new table.
- Theme must apply on **both** `/` and `/intel` after save (same DB value; each page reads it on load).
- Secrets/settings save whitelist must reject unknown keys; add `ui.theme` explicitly to `settingsRegistry`.
- No `styled-jsx`. No new frontend framework. Prefer CSS variables over duplicated markup.
- Demos under `demos/themes/` stay as reference; production code lives in `internal/web/`.
- Do not force-migrate the globe engine to Cobe in this plan’s Phase A.
- Accessibility: keep text contrast readable (Sprite body copy uses sans, not pixel, for data).
- Commits: small, reviewable; one logical commit per completed task group below.

---

## File map

| File | Responsibility |
|------|----------------|
| `internal/settings/keystore.go` | Add `KeyUITheme`; document allowed values |
| `internal/web/api_settings.go` | Register `ui.theme` in `settingsRegistry` + validate enum on save |
| `internal/web/theme_test.go` (new) | API/unit tests for theme save/reject/default |
| `internal/web/static/themes.css` (new) or embedded CSS blocks | Shared token layers for all three themes |
| `internal/web/index.html` | `data-theme` boot, theme-aware chrome, load/apply theme |
| `internal/web/intel.html` | Appearance panel (Theme Picker), same boot/apply, Settings save wiring |
| `internal/web/embed.go` | Embed any new static CSS if split out |
| `demos/themes/*` | Reference only (optional: note “ported” in gallery) |

---

## Phase overview

```
Phase A (this plan)     Phase B (follow-up, separate plan)
─────────────────────   ─────────────────────────────────
• ui.theme setting       • Optional Cobe globe behind flag
• Theme Picker UI       • Meridian satellites / analytics overlays
• CSS token themes      • Sprite gaming stickers on markers
• Dragon/Meridian/      • Shared overlay projection helpers
  Sprite on both pages
• Globe.gl color theming
```

---

## Task 1: Persist `ui.theme` in the keystore + settings API

**Files:**
- Modify: `internal/settings/keystore.go`
- Modify: `internal/web/api_settings.go`
- Create: `internal/web/theme_settings_test.go` (or extend existing settings tests)

- [ ] **Step 1: Add the key constant**

In `internal/settings/keystore.go`, after the home-origin keys:

```go
// UI appearance (non-secret).
KeyUITheme = "ui.theme" // dragon | meridian | sprite
```

- [ ] **Step 2: Whitelist + validate in settings API**

In `internal/web/api_settings.go`:

1. Append to `settingsRegistry` (own section, after geo):

```go
{Key: settings.KeyUITheme, Kind: kindText, Label: "UI theme"},
```

2. In `handleSettingsSave` validation path, when `key == settings.KeyUITheme`, accept only:

```go
var allowedThemes = map[string]bool{
  "dragon": true, "meridian": true, "sprite": true,
}
```

Reject anything else with `400` and a clear error (`invalid theme`). Empty value → clear DB row (revert to default dragon via client `GetOr`).

3. Ensure GET snapshot returns the current value (or `""` if unset — client treats unset as `dragon`).

- [ ] **Step 3: Write failing tests, then make them pass**

Cover:

- Save `meridian` → GET shows `value: "meridian"`, `source: "db"`
- Save `neon` → `400`
- Clear / empty → unset; effective default is dragon on the client

Run:

```bash
go test ./internal/web/ -run Theme -count=1
go test ./internal/settings/ -count=1
```

- [ ] **Step 4: Commit**

```bash
git add internal/settings/keystore.go internal/web/api_settings.go internal/web/theme_settings_test.go
git commit -m "$(cat <<'EOF'
Add ui.theme setting for dashboard theme persistence.

EOF
)"
```

---

## Task 2: Extract theme tokens and `data-theme` application

**Files:**
- Create: `internal/web/themes.css` (preferred) **or** a shared `<style id="theme-tokens">` block duplicated carefully into both HTML files if embed split is painful
- Modify: `internal/web/embed.go` if a new file is embedded and served
- Modify: `internal/web/index.html`, `internal/web/intel.html` (boot script + `html` attribute)

**Token design (lock these names):**

```css
:root, [data-theme="dragon"] {
  --bg: …; --glass: …; --text: …; --dim: …;
  --accent: …; --accent-2: …; --good: …; --warn: …;
  --line: …; --line-strong: …;
  --mono: …; --sans: …;
  /* optional theme flags */
  --radius: 4px;
  --shadow: none;
  --chunk: 0px;
}
[data-theme="meridian"] { /* slate / teal / paper — from demos/themes/meridian*.html */ }
[data-theme="sprite"]   { /* paper / coral / chunky borders — from demos/themes/sprite*.html */ }
```

Map existing Dragon variables 1:1 so current selectors keep working.

- [ ] **Step 1: Port Meridian + Sprite palettes from demos into token blocks**

Source of truth for colors/fonts:

- `demos/themes/meridian.html` / `meridian-intel.html`
- `demos/themes/sprite.html` / `sprite-intel.html`

Include `@import` / `<link>` for theme fonts (Barlow + IBM Plex Mono; Pixelify Sans + DM Sans) — load all three font pairs once, or load on demand when theme is selected (prefer load-all for simplicity in v1).

- [ ] **Step 2: Add early boot script (both pages, in `<head>` before paint if possible)**

```js
(function () {
  var t = localStorage.getItem('shardlure_theme') || 'dragon';
  if (t !== 'dragon' && t !== 'meridian' && t !== 'sprite') t = 'dragon';
  document.documentElement.setAttribute('data-theme', t);
})();
```

Purpose: avoid flash of Dragon when the operator already chose Sprite/Meridian (local cache). Server value remains source of truth after settings fetch.

- [ ] **Step 3: Add `applyTheme(id)` helper shared conceptually on both pages**

```js
function applyTheme(id) {
  if (id !== 'dragon' && id !== 'meridian' && id !== 'sprite') id = 'dragon';
  document.documentElement.setAttribute('data-theme', id);
  try { localStorage.setItem('shardlure_theme', id); } catch (e) {}
  // page-specific: retint globe materials / marker colors if present
  if (window.__shardlureOnTheme) window.__shardlureOnTheme(id);
}
```

- [ ] **Step 4: On intel + globe load, reconcile with server**

After auth-ready fetch of `/api/settings`:

```js
var row = settings.find(s => s.key === 'ui.theme');
var id = (row && row.value) || localStorage.getItem('shardlure_theme') || 'dragon';
applyTheme(id);
```

If server value differs from localStorage, **server wins**, then update localStorage.

- [ ] **Step 5: Manual check**

```bash
# from repo root with live binary or existing arm deploy after build
# Set theme via API, reload /, /intel — chrome colors must match
```

- [ ] **Step 6: Commit**

```bash
git add internal/web/themes.css internal/web/embed.go internal/web/index.html internal/web/intel.html
git commit -m "$(cat <<'EOF'
Add data-theme token layers for Dragon, Meridian, and Sprite.

EOF
)"
```

---

## Task 3: Theme Picker in Settings (Appearance panel)

**Files:**
- Modify: `internal/web/intel.html` (Settings tab markup + JS)

- [ ] **Step 1: Add Appearance panel above or below Live status**

Place a new panel in `#view-settings`:

```html
<section class="panel full" id="panel-set-appearance">
  <div class="panel-head">
    <h2>Appearance</h2>
    <span class="meta">UI theme · applies to globe and intel · saved live</span>
  </div>
  <div class="panel-body">
    <div class="theme-picker" id="theme-picker" role="radiogroup" aria-label="UI theme">
      <!-- three cards: Dragon, Meridian, Sprite -->
    </div>
  </div>
</section>
```

Each card:

- Swatch strip (5 color chips)
- Name + one-line description
- Selected ring using `aria-checked` / `.on`
- Click → optimistic `applyTheme(id)` → `POST /api/settings/save` with `{ key: "ui.theme", value: id }`
- On failure → toast/error and revert to previous theme

Copy (lock):

| ID | Title | Blurb |
|----|-------|-------|
| `dragon` | Dragon | Blood-red ops desk (default) |
| `meridian` | Meridian | Cool slate cartography |
| `sprite` | Sprite | Chunky pixel console |

- [ ] **Step 2: Wire picker state from settings snapshot**

When settings rows load, mark the active card from `ui.theme` (default dragon).

- [ ] **Step 3: Ensure globe page picks up changes**

Saving on `/intel` updates DB + localStorage. Next navigation to `/` uses boot script + settings fetch. Optional nicety (same task if cheap): `BroadcastChannel('shardlure-theme')` or `storage` event so an open globe tab updates live when Settings saves.

- [ ] **Step 4: Manual test checklist**

1. Open `/intel` → Settings → Appearance  
2. Select Meridian → UI updates immediately; reload still Meridian  
3. Open `/` in new tab → Meridian  
4. Select Sprite → both pages Sprite after reload / storage event  
5. Select Dragon → back to default  
6. Invalid API value rejected (curl test)

```bash
curl -sS -X POST "$BASE/api/settings/save" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key":"ui.theme","value":"sprite"}'
```

- [ ] **Step 5: Commit**

```bash
git add internal/web/intel.html
git commit -m "$(cat <<'EOF'
Add Appearance theme picker to intel Settings.

EOF
)"
```

---

## Task 4: Theme-aware chrome on globe + intel (beyond tokens)

**Files:**
- Modify: `internal/web/index.html`
- Modify: `internal/web/intel.html`

Tokens alone won’t make Sprite feel like the demo (chunky borders, hard shadows) or Meridian (paper stage, teal instruments). Add **small** `data-theme`-scoped overrides:

- [ ] **Step 1: Meridian overrides**

Under `[data-theme="meridian"]`:

- Lighter paper/sheet backgrounds for panels  
- Teal accent for chips/tabs/active nav  
- Mono labels for panel titles (already mostly mono)  
- Softer borders (`--line` solid slate)

- [ ] **Step 2: Sprite overrides**

Under `[data-theme="sprite"]`:

- `--chunk: 3px` borders on `.panel`, chips, buttons  
- Hard offset shadows (`box-shadow: 3px 3px 0 var(--ink)`)  
- Pixel font **only** for brand / panel `h2` / big numbers — keep tables/body on DM Sans  
- Optional sky-wash page background on intel (restrained; don’t break density)

- [ ] **Step 3: Globe.gl color hook**

In `index.html` globe setup, read CSS variables (or a small `THEME_GLOBE` map) inside `__shardlureOnTheme`:

- Atmosphere / arc / point colors from `--accent` / `--accent-2` / `--good`  
- Avoid full globe recreate if possible; update existing material colors

- [ ] **Step 4: Visual QA against demos**

Compare side-by-side:

- `demos/themes/meridian.html` vs `/` with Meridian  
- `demos/themes/sprite-intel.html` vs `/intel` with Sprite  

Parity target for Phase A: **palette + typography + panel chrome**, not sticker overlays or Cobe.

- [ ] **Step 5: Commit**

```bash
git add internal/web/index.html internal/web/intel.html internal/web/themes.css
git commit -m "$(cat <<'EOF'
Theme-aware chrome for Meridian and Sprite on globe and intel.

EOF
)"
```

---

## Task 5: Docs + operator notes

**Files:**
- Modify: `README.md` (short Appearance / theme section) — only if README already documents Settings
- Optional: one line in `demos/themes/index.html` noting demos are the visual reference for production themes

- [ ] **Step 1: Document themes**

State: default Dragon; change under Intel → Settings → Appearance; values persist in SQLite `ui.theme`.

- [ ] **Step 2: Final verification**

```bash
go test ./internal/settings/ ./internal/web/ -count=1
```

Manual: three themes × two pages × reload persistence.

- [ ] **Step 3: Commit**

```bash
git add README.md demos/themes/index.html
git commit -m "$(cat <<'EOF'
Document UI theme picker and persistence.

EOF
)"
```

---

## Out of scope (Phase B — do not implement in this plan)

- Replacing `globe.gl` with Cobe  
- Gaming stickers / satellite DOM overlays / polaroids  
- Per-user themes (multi-operator); v1 is **instance-wide** via DB  
- Theme marketplace / custom CSS upload  
- Removing Dragon  

When Phase A is done, open a separate plan: “Cobe globe + theme overlays” using `demos/themes/_shared.js` projection helpers and `demos/themes/stickers/`.

---

## Risk notes

| Risk | Mitigation |
|------|------------|
| FOUC / wrong theme flash | `localStorage` boot in `<head>` + server reconcile |
| Sprite pixel font hurts tables | Restrict Pixelify to brand/headings/stats only |
| Settings whitelist miss | Enum validation + tests |
| Globe colors don’t update | Explicit `__shardlureOnTheme` hook |
| Large HTML diffs | Prefer `themes.css` embed over duplicating three full stylesheets |

---

## Success criteria

1. Settings → Appearance shows three themes; selection saves to `ui.theme`.  
2. `/` and `/intel` both reflect the saved theme after reload.  
3. Unset / fresh DB → Dragon (current look preserved).  
4. Invalid theme values rejected by API.  
5. No regression in Settings key save/test/token flows.  
6. `go test ./internal/settings/ ./internal/web/` passes.
