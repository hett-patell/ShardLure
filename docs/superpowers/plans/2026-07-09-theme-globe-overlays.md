# Phase B: Theme Globe Overlays (Stickers / Satellites) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On the live globe (`/`), show theme-specific HTML overlays — Sprite gaming stickers, Meridian satellites + live/analytics chips — without replacing `globe.gl` or changing APIs.

**Architecture:** Keep `globe.gl` points/arcs as today. Add a second layer via `htmlElementsData` / `htmlElement`, gated by `data-theme` / `window.__shardlureTheme`. Overlay payloads are derived from existing `/api/dashboard` actors + home (top N by events). Stickers are embedded SVG assets served at `/stickers/*.svg`. Dragon theme keeps overlays empty so the default look is unchanged.

**Tech Stack:** Existing `internal/web/index.html` + `globe.gl` HTML elements layer; embed sticker SVGs from `demos/themes/stickers/`; `themes.css` for overlay chrome.

## Global Constraints

- **Do not** swap the globe engine to Cobe in this phase.
- **Do not** change dashboard/intel API contracts or ingest.
- Dragon (`ui.theme` unset or `dragon`) → **zero** HTML overlays (points/arcs only).
- Sprite → stickers on home + top hot actors (SVG, no emoji).
- Meridian → satellite icons + side analytics/live chips on top locations.
- Overlays must not break drag/zoom; use `pointer-events` carefully (clickable ok, don’t steal globe drag when not needed).
- Cap overlay count (e.g. home + ≤6 actors) for performance.
- Theme switch must clear/rebuild overlays via existing `__shardlureOnTheme`.

---

## File map

| File | Responsibility |
|------|----------------|
| `internal/web/stickers/*.svg` | Copied gaming/sat assets (from demos) |
| `internal/web/embed.go` | Embed stickers + optional serve helper |
| `internal/web/server.go` | `GET /stickers/{name}.svg` (safe allowlist) |
| `internal/web/themes.css` | `.globe-sticker`, `.globe-sat`, `.globe-live`, `.globe-analytics` |
| `internal/web/index.html` | Build overlay data; `htmlElementsData`; theme-aware arcs |

---

## Task 1: Embed and serve sticker SVGs

- [ ] Copy `demos/themes/stickers/{skull,bolt,bug,shield,controller,sat,pulse}.svg` → `internal/web/stickers/`
- [ ] Embed directory or individual files in `embed.go`
- [ ] Register allowlisted `/stickers/` handler (no path traversal)
- [ ] `go test` / `go build` still pass

## Task 2: Overlay CSS

- [ ] Add styles in `themes.css` for sticker / sat / live / analytics chips (readable, no emoji)
- [ ] Sprite: chunky border + tilt; Meridian: instrument chrome

## Task 3: Wire `htmlElementsData` on the globe

- [ ] Helper `buildThemeOverlays(theme, home, actors)` → array of `{ lat, lng, kind, ... }`
- [ ] `htmlElement(d)` factory creates DOM from kind
- [ ] `htmlElementVisibilityModifier` fades when behind globe
- [ ] Call from `refresh()` after points/arcs; call from `__shardlureOnTheme` to rebuild
- [ ] Theme-tint `arcColor` from CSS vars (Meridian teal / Sprite coral / Dragon red)

## Task 4: Verify

- [ ] Dragon: no stickers
- [ ] Sprite: stickers visible on hot spots
- [ ] Meridian: sats + chips
- [ ] Theme switch updates overlays without reload
- [ ] `go test ./internal/web/ ./internal/settings/`

## Out of scope

- Full Cobe migration
- Intel-page globe
- Polaroid photos
- Per-user themes
