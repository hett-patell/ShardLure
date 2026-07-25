# v2.0.0 — Globe artifacts, ambient dashboard, intel command palette

**Date:** 2026-07-22
**Status:** approved (design), pending spec review
**Ships as:** part of **v2.0.0** (not yet tagged), implemented in two waves (A+B, then C). Folding these into v2.0.0 avoids shipping the new Signal theme with a globe that renders no artifacts.

## Goal

Three related dashboard improvements:

- **(A) Fix missing globe artifacts on Signal.** The Signal theme's globe renders no stickers/satellites/overlays. Wire Signal into the existing overlay system with satellites + analytics chips + a live badge.
- **(B) Make the globe dashboard an ambient wall display.** Remove the six panels duplicated in `/intel`, keep at-a-glance status, add a Threat Level gauge, and let the globe grow.
- **(C) Turn the `/intel` search bar into a command palette.** Replace DOM row-hiding with a grouped, actionable, keyboard-driven lookup that can find data not currently on screen.

**Wave 1 = A + B** (both in `index.html`) — verified and deployed first, so the globe fix is not blocked behind the palette.
**Wave 2 = C** (in `intel.html`) — verified and deployed after.

## Background / current state (verified against source)

**(A) Root cause.** `buildThemeOverlays()` in `internal/web/index.html` (gate at line 872) begins:
```js
if (theme !== 'sprite' && theme !== 'meridian') return [];
```
Signal therefore receives an empty overlay array and renders nothing. This is **not** a regression from the v2.0 theme work — Signal was never added to this gate (Dragon used globe.gl's own HTML overlays, which were removed with it).

All supporting infrastructure already exists and works:
- 7 SVGs embedded (`internal/web/stickers/`) and served at `/stickers/` behind an allowlist (`embed.go`, `stickers.go`).
- `ShardCobe.setOverlayPlaces(places, nodes)` in `cobe-boot.js:173`, driven by `applyGlobeOverlays()` (`index.html:981`).
- `makeOverlayEl()` (`index.html:925`) already renders **five artifact kinds**: `sticker`, `sat`, `live`, `analytics`, `node` — theme-agnostic. These map onto Cobe's own demo vocabulary (Stickers / Satellites / Live Badge / Analytics).

So (A) is wiring plus styling, not new machinery. Meridian's variant (satellites + live badge + per-actor analytics chips) is the richer of the two existing treatments and is the model for Signal.

**(B) Duplication.** Six of the globe page's ten panels duplicate `/intel`: By country ↔ Attack Geography; Top usernames tried ↔ Top Credentials; Top actors ↔ Threat actors; Recent shell sessions ↔ Cowrie sessions; Top commands ↔ Recent commands executed; Payload capture ↔ Payload capture (live).

**(C) Current search.** `applyClientSearch()` (`intel.html:2774`) does `row.textContent.toLowerCase().indexOf(q)` over already-rendered rows and sets `display:none`. Limits: cannot find anything not already loaded (e.g. an IP outside the 80 fetched actors); silently hides rows on inactive tabs; no result list, count, or actions.

**Reusable handlers confirmed present** in `intel.html`: `openSession(sid)` (:3066), `openPayload(sha)` (:3721), the enrich-IP flow (:3405-3424), `renderGauge(summary, intentCounts, kindCounts)` (:4302). `/api/intel` returns `recentCommands` and per-actor `topUsers`.

## Design

### (A) Signal globe artifacts

Add a `signal` branch to `buildThemeOverlays(theme, home, actors)` alongside the existing sprite/meridian branches (their paths untouched). Reuse Meridian's structure:

- **At home:** a `live` badge (`LIVE · <city>`) and a `sat` with `hub: true`.
- **Per attacker:** top 6 actors by event count, filtered to finite `lat`/`lon`; each emits a `sat` (staggered `alt` and `ringDelay`) and an `analytics` chip carrying `CC · City`, event count (abbreviated, e.g. `44.4k`), rate (`1114/h`), and IP.
- Colors come from `themeAccentRGB()`, which already returns Signal dark (`#d1fe17`) and Signal light (`#b6d900`) — so artifacts follow the dark/light toggle with no extra work.
- **CSS:** extend the existing `.globe-sat` / `.globe-sat--hub` / `.globe-live` / `.globe-analytics` / `.globe-node` rules in `themes.css` to also match `html[data-theme="signal"]` and `html[data-theme="signal"][data-mode="light"]` (they are currently in meridian/sprite-scoped selector lists).

### (B) Ambient wall display

**Remove** these six panels from `index.html`, together with their render functions and every `refresh()` call site: By country, Top usernames tried, Top actors, Recent shell sessions, Top commands, Payload capture.

**Keep:** title card, Summary tiles (events / actors / unique IPs / countries), events-per-hour sparkline, Live feed (taller).

**Add:** a Threat Level gauge, ported from `intel.html` (markup + `renderGauge`), on the left rail.

**Layout:** left rail = title, Summary tiles, Threat gauge; right rail = Live feed; center = globe, grown into the reclaimed width; bottom = sparkline.

Meridian and Sprite share this markup, so they get the same lean layout — intended (one dashboard, three skins). Their globe artifacts are unchanged.

### (C) Intel command palette (wave 2)

Replace `applyClientSearch()`'s global row-hiding with a dropdown anchored under the existing `#search-input`. Groups, sources, and Enter actions:

| Group | Source | Enter action |
| --- | --- | --- |
| Actors | `/api/intel` actors, `/api/actor?id=` | jump to actor detail |
| IPs | matched actor IPs | open enrichment (existing `#enrich-ip` flow) |
| Sessions | `/api/intel/sessions` | `openSession(sid)` (transcript modal) |
| Commands | `/api/intel` `recentCommands` | jump to the command's context |
| Payloads | `/api/intel/payloads` | `openPayload(sha)` |

**Behavior:** keep the existing 120 ms debounce; query the `/api/*` endpoints so results include items not on screen; `↑`/`↓` navigate, `Enter` activates, `Esc` closes, click-outside closes, empty query closes; cap ~5 results per group and show a total count.

**Row-filter is retained** as an explicit "filter this table" fallback, but scoped to the **active tab only** rather than silently hiding rows on hidden tabs.

Reuses the monkey-patched `fetch` (auth-token injection) and the existing modal/enrich/deep-link handlers: no new backend, no new auth surface.

### API change (small, required by B)

`renderGauge(summary, intentCounts, kindCounts)` needs `intentCounts` and `kindCounts`. These are computed and cached in `summaryStats` (`server.go:138`, `:148`) but are **not** exposed in `dashboardResponse`. Add two fields to `dashboardResponse` and populate them from `summaryStatsCached()` in `handleDashboard`:

```go
IntentCounts []store.LabelCount `json:"intentCounts"`
KindCounts   []store.LabelCount `json:"kindCounts"`
```

Values are already computed and cached, so this adds **no new query** and no measurable cost. This is the only Go change in the spec — everything else is frontend.

## Testing & verification

- `scripts/check-utf8.sh`, `go vet ./...`, `go test ./...`, `go build`, `scripts/ci-web-smoke.sh` — all green (Go is touched by the two-field API addition, and embedded assets ship in the binary).
- **Visual gate (the real proof).** Headless Chromium (bundled `chromium-1228`; the `chrome` channel is not installed) against a seeded DB, at 1440×900, capturing **Signal-dark, Signal-light, Meridian, Sprite**:
  - artifacts (satellites, live badge, analytics chips) actually appear on the Signal globe — the specific reported bug;
  - the six removed panels are gone and the Threat gauge renders with a plausible value;
  - Meridian and Sprite still render their own artifacts and are otherwise unchanged;
  - **zero page errors** in every state.
- **Dead-code gate.** For each removed panel, grep that both its render function and every `refresh()` call site are gone. A surviving call to a deleted function is a runtime `ReferenceError` — the exact class of defect the v2.0 final review caught, so it is checked explicitly rather than assumed.
- Wave 2 adds: palette opens on input, `↑`/`↓`/`Enter`/`Esc` behave, a query for an IP **not** in the loaded set still returns it, and each group's Enter action reaches the right handler.

## Out of scope

- Full-bleed globe (lean rails chosen instead).
- New sticker SVGs; changes to `/intel`'s own panels.
- A server-side `/api/search` endpoint (the palette uses existing endpoints).
- Any backend work beyond the two `dashboardResponse` fields.
- Cutting now-unused fields from `/api/dashboard` — other consumers still read them; trimming is scope creep with no gain.

## Risks / notes

- **Artifact clutter.** Six actors × (satellite + chip) plus home badges can crowd a 1440px viewport. Mitigated by the existing `dedupeActorsByLocation` (~1° buckets) and the 6-actor cap; the visual gate is where this gets judged.
- **Shared markup.** Removing panels affects all three themes, not just Signal. Intended, and covered by rendering all four states.
- **Palette scope creep.** (C) is the largest piece and is deliberately deferred to wave 2 so (A) — the reported bug — ships first.
