# v2.0.0 — Signal theme + Dragon/globe.gl removal

**Date:** 2026-07-22
**Status:** approved (design), pending spec review
**Scope:** live dashboard theme system (`internal/web/`), docs, demo-folder removal, v2.0.0 release prep

## Goal

Consolidate the live dashboard's themes for the v2.0.0 release:

- Introduce **Signal** — one theme with a **dark + light** toggle — ported from the `demos/themes/phosphor.html` (dark) and `anode.html` (light) design studies. Make it the **default**.
- **Delete the Dragon theme** entirely.
- Make **Cobe the only globe engine**: remove `globe.gl` and its three external `networkshard.com` texture URLs (Dragon was their sole consumer).
- Keep **Meridian** and **Sprite** (dark-only, unchanged behavior).
- Extract the design from `demos/themes/`, then **delete that folder** (it is disposable reference scaffolding, not the live UI).
- Fix stale theme docs (README claims a non-existent "Noctiluca"; CLAUDE.md).

Version series continues **v2.0.0 → v2.0.1 → …**.

## Background / current state (verified)

- The **live dashboard** (`internal/web/`) implements exactly three themes: `dragon`, `meridian`, `sprite`. `themes.css` (~797 lines) is built around `html[data-theme="…"]` blocks; the settings validator (`api_settings.go`) hard-rejects anything else; the keystore key is `ui.theme` (default currently `dragon`).
- The demo names **`phosphor` / `anode` do NOT exist in `internal/web/`** — they are static mockups in `demos/themes/` only. "Make Phosphor default" therefore means **porting that look into the live theme system**, not editing a demo file.
- **Globe engines today:** Dragon uses `globe.gl` (imported from `esm.sh`, with earth textures from `networkshard.com`); Meridian/Sprite use **Cobe** (`cobe-boot.js` → `cobe-globe.js`). Dragon is globe.gl's only consumer, so deleting Dragon cleanly removes globe.gl and the external texture dependency.
- **Version** is injected at build time via `-ldflags -X main.version=…` (`cmd/shardlure/main.go:33` defaults to `"dev"`). There is no hardcoded version constant to edit — a release is a git tag + GitHub release.

## Design

### Data model

- `ui.theme` ∈ `{signal, meridian, sprite}`, default **`signal`**. (Existing keystore key; validator updated, `dragon` removed.)
- **New** `ui.mode` ∈ `{dark, light}`, default **`dark`**. Only meaningful when `ui.theme=signal`; Meridian/Sprite ignore it.
- DOM: `<html data-theme="signal" data-mode="light">`. Meridian/Sprite depend only on `data-theme`.

### CSS (`internal/web/themes.css`)

- Delete the `[data-theme="dragon"]` token block and every `[data-theme="dragon"]` rule (including `#cobe-stage { display:none }` for dragon).
- Add `[data-theme="signal"]` — dark tokens ported from `phosphor.html` (near-black field, single chartreuse accent, uppercase grotesque type).
- Add `[data-theme="signal"][data-mode="light"]` — light overrides ported from `anode.html` (paper field, dark ink, same lime accent).
- Meridian/Sprite blocks unchanged.

### Globe engine (`index.html`, `cobe-boot.js`, `cobe-globe.js`)

- Remove `ensureDragonGlobe()`, the `globe.gl` dynamic import, the three `networkshard.com` texture URLs, and the globe.gl HTML-overlay / rAF-pause branches.
- `syncGlobeEngine()` collapses to "always Cobe"; the dual-engine switch (`usesCobeTheme()`) is removed. Signal (both modes) + Meridian + Sprite all drive the single Cobe globe.
- `cobeThemeConfig` (`cobe-globe.js`) gains a `signal` entry that keys globe colors on `data-mode` (dark globe for dark mode; pale-dotted globe for light mode, matching the two demos).

### Settings UI (`intel.html`, `api_settings.go`, `keystore.go`)

- Theme picker: 3 cards — Signal, Meridian, Sprite (Dragon card removed; swatches updated). Signal pre-selected.
- A dark/light toggle appears **only** when Signal is active (hidden/disabled for Meridian/Sprite). Writes `ui.mode`.
- JS: `applyTheme(id)` sets `data-theme`; new `applyMode(mode)` sets `data-mode`. The pre-paint head-inline script (currently defaults `dragon`) reads `ui.theme` (default `signal`) and `ui.mode` (default `dark`) and applies both before first paint (no flash). Cross-tab `BroadcastChannel` sync carries both theme and mode.
- `api_settings.go`: validator accepts `signal|meridian|sprite`; add `ui.mode` → `dark|light` to the settings registry.
- `keystore.go`: update the `ui.theme` comment (default `signal`); document the new `ui.mode` key.

### Docs

- **README:** replace the stale multi-theme prose (and the phantom "Noctiluca") with **Signal (default, dark/light) + Meridian + Sprite**, and note the globe.gl→Cobe consolidation.
- **CLAUDE.md:** update the Web-layer themes bullet (3 themes, `signal` default, `ui.theme`+`ui.mode`, Cobe-only globe); remove the "demos/themes/ is NOT the live UI" note (folder being deleted).

### Demo folder removal

Port the Phosphor/Anode design into the live Signal theme and **verify it renders first**; then `git rm -r demos/themes/`. (`.gitignore` needs no change — it has no `demos/themes/` entries.)

### Versioning / release

Prep only in this work: land the changes on a branch and draft release notes. The actual `v2.0.0` git tag + GitHub release is a **human-triggered step** the user approves (version is ldflags-injected, so no source edit). Series continues v2.0.0 → v2.0.1 → …

## Testing & verification

- Update `internal/web/theme_settings_test.go`: `dragon`→`signal`; assert the validator now rejects `dragon`; add a `ui.mode` test (accepts `dark`/`light`, rejects junk).
- `go test ./...`, `go vet ./...` green; `scripts/ci-web-smoke.sh` passes; `scripts/check-utf8.sh` clean.
- Render the live dashboard in the bundled Chromium for all four states — Signal dark, Signal light, Meridian, Sprite — confirming each theme and the Cobe globe paint **before** deleting `demos/themes/`.

## Out of scope

- OS `prefers-color-scheme` auto-switching (possible v2.0.1 follow-up).
- Any change to Meridian/Sprite visuals.
- Backend/data changes beyond the two settings keys.
- The actual git tag / GitHub release publish (human-triggered).

## Risks / notes

- **Flash-of-wrong-theme:** the pre-paint inline script must set both `data-theme` and `data-mode` before first paint; test the light-mode reload path specifically.
- **Removing globe.gl** also removes the external `networkshard.com` texture fetches — a side benefit (fewer third-party requests) but confirm no other code path references those URLs.
- **Demo removal is irreversible in the tree** (recoverable via git history); do it only after the live Signal theme is verified rendering.
