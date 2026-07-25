# v2.0.0 — Globe artifacts, ambient dashboard, intel command palette

**Date:** 2026-07-22
**Status:** approved (design), pending spec review
**Ships as:** part of **v2.0.0** (not yet tagged), implemented in two waves (A+B, then C+D). Folding these into v2.0.0 avoids shipping the new Signal theme with a globe that renders no artifacts and an analyst console still tinted Dragon red.

## Goal

Four related dashboard fixes — (A) and (D) are bugs, (B) and (C) are improvements — plus (E) the doc updates they force:

- **(A) Fix missing globe artifacts on Signal.** The Signal theme's globe renders no stickers/satellites/overlays. Wire Signal into the existing overlay system with satellites + analytics chips + a live badge.
- **(B) Make the globe dashboard an ambient wall display.** Remove the six panels duplicated in `/intel`, keep at-a-glance status, add a Threat Level gauge, and let the globe grow.
- **(C) Turn the `/intel` search bar into a command palette.** Replace DOM row-hiding with a grouped, actionable, keyboard-driven lookup that can find data not currently on screen.
- **(D) Fix hardcoded Dragon-red left in `intel.html`.** Found while critiquing this spec: 28 literal `rgba(208,40,40,…)` occurrences that ignore the theme, so the analyst console still shows Dragon red on Signal/Meridian/Sprite.

**Wave 1 = A + B** (both in `index.html`) + the (E) README bullets they invalidate — verified and deployed first, so the globe fix is not blocked behind the palette.
**Wave 2 = C + D** (both in `intel.html`) + the (E) palette README line — verified and deployed after.

## Background / current state (verified against source)

**(A) Root cause.** `buildThemeOverlays()` in `internal/web/index.html` (gate at line 872) begins:
```js
if (theme !== 'sprite' && theme !== 'meridian') return [];
```
Signal therefore receives an empty overlay array and renders nothing. This is **not** a regression from the v2.0 theme work — Signal was never added to this gate (Dragon used globe.gl's own HTML overlays, which were removed with it).

All supporting infrastructure already exists and works:
- 7 SVGs embedded (`internal/web/stickers/`) and served at `/stickers/` behind an allowlist (`embed.go`, `stickers.go`).
- `ShardCobe.setOverlayPlaces(places, nodes)` in `cobe-boot.js:173`, driven by `applyGlobeOverlays()` (`index.html:981`).
- `makeOverlayEl()` (`index.html:925`) renders five artifact kinds — `sticker`, `sat`, `live`, `analytics`, `node` — all theme-agnostic. **Four are live; `node` is dead code** (no caller emits `kind: 'node'`, verified by grep). The four live kinds map onto Cobe's own demo vocabulary (Stickers / Satellites / Live Badge / Analytics).
- **The overlay CSS is already theme-neutral.** `.globe-overlay`, `.globe-sticker`, `.globe-sat`, `.globe-sat--hub`, `.globe-live`, `.globe-analytics` are unscoped base rules at `themes.css:288-343` and colour themselves from `var(--accent)` / `var(--line)` tokens. There are **zero** `[data-theme=…] .globe-*` rules. So Signal inherits correct artifact styling automatically — no per-theme CSS is required.

So (A) is a one-branch wiring change, not styling or new machinery. Meridian's variant (satellites + live badge + per-actor analytics chips) is the richer of the two existing treatments and is the model for Signal.

**(B) Duplication.** Six of the globe page's ten panels duplicate `/intel`: By country ↔ Attack Geography; Top usernames tried ↔ Top Credentials; Top actors ↔ Threat actors; Recent shell sessions ↔ Cowrie sessions; Top commands ↔ Recent commands executed; Payload capture ↔ Payload capture (live).

**(C) Current search.** `applyClientSearch()` (`intel.html:2774`) does `row.textContent.toLowerCase().indexOf(q)` over already-rendered rows and sets `display:none`. Limits: cannot find anything not already loaded (e.g. an IP outside the 80 fetched actors); silently hides rows on inactive tabs; no result list, count, or actions.

**Reusable handlers confirmed present** in `intel.html`: `openSession(sid)` (:3066), `openPayload(sha)` (:3721), the enrich-IP flow (:3405-3424), `renderGauge(summary, intentCounts, kindCounts)` (:4302). `/api/intel` returns `recentCommands` and per-actor `topUsers`.

## Design

### (A) Signal globe artifacts

Add a `signal` branch to `buildThemeOverlays(theme, home, actors)` alongside the existing sprite/meridian branches (their paths untouched). Reuse Meridian's structure:

- **At home:** a `live` badge (`LIVE · <city>`) and a `sat` with `hub: true`.
- **Per attacker:** top 6 actors by event count, filtered to finite `lat`/`lon`; each emits a `sat` (staggered `alt` and `ringDelay`) and an `analytics` chip carrying `CC · City`, event count (abbreviated, e.g. `44.4k`), rate (`1114/h`), and IP.
- Colors come from `themeAccentRGB()`, which already returns Signal dark (`#d1fe17`) and Signal light (`#b6d900`) — so artifacts follow the dark/light toggle with no extra work.
- **No CSS work required.** The overlay rules are unscoped and token-driven (see Background), so Signal picks up its own accent automatically. The visual gate confirms this rather than assuming it; only if a render shows wrong colour/contrast does a Signal-specific override get added.
- **Also fix while here:** delete the dead `node` branch in `makeOverlayEl()` (nothing emits `kind: 'node'`). Leaving it invites a future reader to wire it by mistake.

### (B) Ambient wall display

**Remove** these six panels from `index.html`: By country (`#top-countries`), Top usernames tried (`#top-users`), Top actors (`#actors`), Recent shell sessions (`#shell-sessions`), Top commands (`#top-commands`), Payload capture (`#capture-feed` + `#cap-*` tiles).

Removal mechanics, verified rather than assumed: `refresh()` (`index.html:1007-1047`, 40 lines) writes **only** the summary tiles and `gen-at`/`home-loc` — it does not inline-render the panels. Each panel is filled by its own helper, but they are **not uniformly named**: `renderTopUsers`, `renderTopCommands`, `renderCapture`/`refreshCapture` exist as discrete functions, while the countries / actors / sessions panels are filled by differently-named helpers. So the removal is surgical but must be driven by the **element IDs above**, not by guessing function names: for each ID, delete its markup, its writer, and every call site (including `refreshCapture`'s own `setInterval`).

**Keep:** title card, Summary tiles (events / actors / unique IPs / countries), events-per-hour sparkline, Live feed (taller).

**Add:** a Threat Level gauge, ported from `intel.html` (markup + `renderGauge`), on the left rail.

**Layout:** left rail = title, Summary tiles, Threat gauge; right rail = Live feed; center = globe, grown into the reclaimed width; bottom = sparkline.

Meridian and Sprite share this markup, so they get the same lean layout — intended (one dashboard, three skins). Their globe artifacts are unchanged.

### (C) Intel command palette (wave 2)

Replace `applyClientSearch()`'s global row-hiding with a dropdown anchored under the existing `#search-input`. Groups, sources, and Enter actions:

| Group | Source | Enter action |
| --- | --- | --- |
| Actors | `/api/intel` actors | `loadActorDetail(id)` + set `selectedActor` + switch to the Overview tab and mark the matching `.actor-row.selected` (mirrors what an actor-row click does today, `intel.html:2202-2207`) |
| IPs | matched actor IPs | populate `#enrich-ip` and trigger the existing lookup (`intel.html:3405-3424`) |
| Sessions | `/api/intel/sessions` | `openSession(sid)` (transcript modal) |
| Commands | `/api/intel` `recentCommands` | switch to the tab holding the command list and filter it to that command |
| Payloads | `/api/intel/payloads` | `openPayload(sha)` |

Every action above resolves to a function that **exists today** — verified: `loadActorDetail` (`:2089`), the enrich flow (`:3405`), `openSession` (`:3066`), `openPayload` (`:3721`). No new opener needs inventing. Actions that require a tab change must call the existing view switcher first, since the target panel may be on a hidden tab.

**Behavior:** keep the existing 120 ms debounce; query the `/api/*` endpoints so results include items not on screen; `↑`/`↓` navigate, `Enter` activates, `Esc` closes, click-outside closes, empty query closes; cap ~5 results per group and show a total count.

**Row-filter is retained** as an explicit "filter this table" fallback, but scoped to the **active tab only** rather than silently hiding rows on hidden tabs.

Reuses the monkey-patched `fetch` (auth-token injection) and the existing modal/enrich/deep-link handlers: no new backend, no new auth surface.

### (D) Hardcoded Dragon-red leftovers in `intel.html` (found during spec self-critique)

`intel.html` still carries **28 literal `rgba(208,40,40,…)` occurrences** in its inline `<style>` — Dragon's red, hardcoded instead of tokenised. Confirmed sites include: `.nav a.active` (:75), `tr.actor-row.selected td` (:113), `.cap-badge.failed/.blocked` (:197), a tab/chip active state (:232-233), the live-dot glow (:251), and `@keyframes livePulse` (:273-275).

Because these are literals rather than `var(--accent)`, they **do not follow the theme** — the analyst console still flashes Dragon red on Signal, Meridian, and Sprite. The v2.0 cleanup only grepped for the *string* `dragon`, so literal RGB slipped through every review.

**Fix:** replace each with the equivalent token (`var(--accent)`, or `color-mix(in srgb, var(--accent) 8%, transparent)` where an alpha wash is needed, matching how the surrounding rules already do it). This is CSS-only, no behaviour change. It belongs in **wave 2** (same file as the palette) to keep wave 1 focused on `index.html`.

Scope note: `--accent: #d02828` inside the `:root` blocks of both HTML files is a *base default* overridden by `themes.css`'s higher-specificity `html[data-theme=…]` rules, so it is inert and deliberately left alone (verified during the v2.0 review).

### (E) README updates (required — the cull changes documented behaviour)

Two bullets become wrong once (A)/(B) land, so they are updated in the same wave as the change they describe:

- **Line 52, "Dashboard widgets"** currently reads as one undifferentiated list (`threat-level gauge, attack geography, brute-force radar, top credentials, live attack timeline, tunnel/proxy targets, session metadata`). After the cull, most of those live only in `/intel`. Reword to state the split explicitly: the **globe dashboard** is an ambient view (summary counts, threat gauge, events/hour sparkline, live feed, globe artifacts), and the **intel console** (`/intel`) holds the analyst widgets (attack geography, brute-force radar, top credentials, MITRE coverage, sessions, payloads, tunnel/proxy targets).
- **Line 51, "3D Cobe globe"** — add that the globe carries floating artifacts (satellites, live badge, per-actor analytics chips) anchored to attacker coordinates.
- Wave 2 adds a line for the `/intel` **command palette** (searching actors / IPs / sessions / commands / payloads with keyboard navigation), replacing any implication that the search box merely filters rows.
- Roadmap line 683 (`Dashboard widgets: threat gauge, geography, credentials…`) stays accurate as history and is left alone.

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
- **Wave 2 (D) gate:** `grep -c "208,40,40" internal/web/intel.html` → **0**, and a rendered `/intel` in Signal-dark, Signal-light, Meridian and Sprite shows the accent colour of the active theme (no red) on: the active nav item, a selected actor row, a failed capture badge, and the live dot/pulse. This grep is the check the v2.0 review lacked — it caught the string `dragon` but not the literal RGB.

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
