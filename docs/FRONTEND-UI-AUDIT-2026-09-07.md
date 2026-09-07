# ShardLure — Frontend UI Audit + Cache-Performance Work + Deployment Status

Date: 2026-09-07
Auditor: Codex (read-only source analysis; no browser automation available this session)
Scope: internal/web/index.html, intel.html, themes.css, cobe-*.js, vendor/vis-network.min.js and the surrounding handler code, at branch fix/cache-performance-bounds (HEAD afb06ff).
Deployment target audited separately (read-only): arm (ubuntu@arm, shardlure-live).

> **Status, later the same day:** every finding below was reproduced in a real
> browser, fixed, pinned by tests, and deployed to arm — see §10. Sections 1–9
> are the audit as written and describe the state *before* remediation.

---

## 1. Executive summary

The frontend of ShardLure scores **12/20** across the five categories audited:

| Category | Score |
|---|---|
| Accessibility | 2/4 |
| Performance | 2/4 |
| Responsive design | 2/4 |
| Theming | 3/4 |
| Anti-patterns / robustness | 3/4 |

The strongest part of the frontend is its security posture: attacker-derived strings are escaped nearly everywhere (esc/escHtml/safeUrl with a strict scheme filter), the CSP is strict (script-src 'self'), and no XSS avenue was found. The weakest parts are keyboard/AT semantics (click-only collapsible panels, placeholder-only labels, missing dialog/combobox ARIA) and mobile behavior (the landing page is effectively unscrollable on small screens and the live feed is hidden entirely below 760px).

No frontend fix has been applied or deployed yet. The backend **cache-performance-bounds** work described in section 5 is complete, tested, and deployed on arm; the frontend findings in this report are source-level observations awaiting remediation.

## 2. Methodology and limitations

- **Static, line-anchored source analysis** of both HTML pages, the theme CSS, the Cobe globe code, and the vendored vis-network bundle.
- **Live runtime verification was not possible**: no browser automation was available in this session, so no real-device screenshots or screen-reader runs were captured. Every finding is therefore tagged **source-conclusive** (the literal markup/CSS proves the behavior) or **needs visual confirmation** (requires a real browser/device to confirm severity).
- The Go test suite for internal/web passes read-only (includes the new cache-tier tests, section 5).
- Production was touched only through **read-only** checks: systemctl show, curl on the localhost dashboard endpoint, sha256sum of the installed binary. Nothing was modified on arm.
- Color contrast was computed against the literal --bg and --dim-2 values in intel.html; WCAG ratios were not estimated visually.

## 3. Findings — P1 (fix first)

### 3.1 Collapsible panels are click-only (accessibility blocker)

- **Where:** intel.html:1405, :1567, :1590 — a panel-head div with an onclick class toggle.
- **Why it matters:** the trigger is a plain div wrapping an h2. It is not in the tab order, cannot be operated by keyboard, and exposes no state (aria-expanded/aria-controls). Screen-reader users cannot discover or operate these panels.
- **Fix:** move the toggle onto a native button inside the heading, set aria-expanded and aria-controls pointing at the panel body, and keep the JS class toggle. **Source-conclusive.**

### 3.2 Mobile landing page is effectively unscrollable and hides the live feed

- **Where:** index.html:55 (html, body overflow hidden) and index.html:233-236 (the max-width 760px block).
- **What happens on a phone:** .rail.left becomes position fixed, width 100%, height auto, so its own overflow-y auto never engages (auto height under a hidden body overflow = clipped content), and .rail.right is display none, which removes the Top Source IPs and **the entire live feed** on small screens.
- **Fix:** let the mobile layout scroll normally (remove the hard overflow hidden, or scope it to the desktop two-column layout), and give mobile a single-column flow with the live feed present (or an explicit, labeled alternative to it).
- **Status:** source-conclusive from the CSS cascade; one real-device screenshot would confirm the clipping visually. **Needs visual confirmation.**

### 3.3 Focus styles are suppressed on inputs; no focus-visible fallback

- **Where:** intel.html:331 (toolbar input.search outline none), intel.html:644 (enrich-input focus removes the outline).
- **Also:** no focus-visible rules exist for tabs, chips, sidebar links, buttons, theme cards, or modal close controls.
- **Why it matters:** keyboard users get no visible indication of where focus is — WCAG 2.4.7 (Focus Visible).
- **Fix:** remove the outline:none declarations and add a consistent focus-visible ring to every interactive control. **Source-conclusive.**

## 4. Findings — P2 (important)

### 4.1 Placeholder-only labels

- **Where:** search input (intel.html:1204), enrich input (:1548), deobf input (:1699), replay select (:1679), and dynamically generated settings rows.
- **Why it matters:** placeholders disappear on input and are not programmatically tied to the control; adjacent .set-label divs have no for/id association. Violates WCAG 1.3.1 (Info and Relationships), 3.3.2 (Labels or Instructions), 4.1.2 (Name, Role, Value).
- **Fix:** real label elements (or aria-label/aria-labelledby), keeping the placeholder as a hint only. **Source-conclusive.**

### 4.2 Search palette is not a true combobox

- **Where:** intel.html:1204 and :3069.
- **What's right:** arrow keys, Enter, and Escape are implemented correctly in the JS.
- **What's missing:** the input has no role=combobox, no aria-controls, no aria-expanded, no aria-activedescendant; the option rows have role=option but no aria-selected.
- **Fix:** add the missing ARIA wiring, then update the existing keyboard handlers to maintain aria-activedescendant. **Source-conclusive.**

### 4.3 Modals lack dialog semantics and focus management

- **Where:** payload modal (intel.html:1912) and session modal (:1924).
- **What's right:** Escape and backdrop-click close work.
- **What's missing:** no role=dialog, aria-modal, aria-labelledby; focus is not moved into the dialog on open, not trapped, and not restored on close.
- **Fix:** use a native dialog with showModal(), or add the ARIA roles plus a small focus-trap/restore helper. **Source-conclusive.**

### 4.4 Polling overlap and background-tab waste

- **Where:** index.html:1075 (fetch without try/catch) and :1160 (setInterval(refresh, 5000) with no in-flight guard and no visibility handling).
- **Measured context:** production /api/dashboard took ~5.2s cold on a prior read-only probe, which means a 5s poller **can** overlap its own request — the overlap is reproducible, not theoretical.
- **Intel page:** 13 intervals, each correctly guarded per active view (good), but none pause while the tab is hidden.
- **Positive contrast:** the deobf poller (intel.html:5066-5079) already bails when the user has scrolled or has an active selection — copy that pattern.
- **Fix:** (a) guard the home refresh against re-entry, (b) wrap the fetch in try/catch, (c) pause all polling on visibilitychange/document.hidden, and resume (with an immediate refresh) on return. **Source-conclusive.**

### 4.5 vis-network loads eagerly

- **Where:** intel.html:1175 — 689KB synchronous, render-blocking script.
- **Why it matters:** graph construction is already deferred until the panel is visible (:4872), so the bundle is blocking first paint for a feature the user may never open.
- **Fix:** use defer, or better, dynamic import() when the graph panel first becomes visible. **Source-conclusive.**

### 4.6 Inline grid styles defeat mobile breakpoints

- **Where:** intel.html:1221 (inline grid-template-columns repeat(5,1fr) on the stats row), and the same pattern for URLhaus/ThreatFox at :1471, :1510.
- **Why it matters:** an inline style always beats the media override at intel.html:93, so the intended responsive collapse never happens.
- **Fix:** move those grid templates into classes, then let the media query change them. **Source-conclusive.**

### 4.7 Intel page has no small-screen strategy

- **Where:** intel.html:226 — fixed 52px 1fr two-column grid with no sidebar collapse/hide breakpoint.
- **Result:** on a 375px phone, the content column gets ~323px, with the sidebar still eating space.
- **Fix:** a breakpoint that collapses the sidebar into a drawer/top bar, matching the landing page's layout effort. **Source-conclusive.**

### 4.8 --dim-2 contrast failure

- **Where:** intel.html:38 defines --dim-2 as #604840; it is used for roughly 24 small-text treatments at 8.5–10px and is never redefined by themes.css.
- **Measured:** 2.40:1 against --bg — far below WCAG 1.4.3's 4.5:1 for normal text. (For reference, the Signal dark theme's default dim #898a8b scores 5.47:1 against the same background.)
- **Fix:** raise the value (or redefine it per theme), and separately bump the tiny 8.5–10px text sizes. **Source-conclusive** (computed from the literal hex values).

### 4.9 External Google Fonts

- **Where:** index.html:25-26 and intel.html:25-26 — two render-blocking link requests loading 8 families across 4 themes.
- **Conflict:** the host is operated as an air-gapped/zero-egress posture, yet the CSP explicitly whitelists fonts.googleapis.com/fonts.gstatic.com, and every page load depends on those hosts for typography.
- **Fix:** self-host and subset the needed families (woff2 + font-display swap), then drop the font CSP allowances. **Source-conclusive.**

### 4.10 Light themes leak dark-theme assumptions

- **Where (examples):** intel.html:321 hard-codes rgba(0,0,0,0.25) chip backgrounds, :566 hard-codes #02060d modal body, plus white-only rgba(255,255,255,...) hover/track colors and dark .sm-card override remnants.
- **Why it matters:** literal dark-only values in components that all four themes share.
- **Fix:** move every hard-coded color into per-theme variables, then check each theme. **Needs visual confirmation** per theme; the literal values are source-conclusive.

## 5. Findings — P3 (hygiene)

- Sidebar icon links use title instead of aria-label, and the SVG icons lack aria-hidden (intel.html:1180).
- Tabs have excellent keyboard code (roving tabindex, arrows, Home/End, Enter/Space, manual activation — correct per APG) but lack aria-controls and tabpanel semantics.
- Small touch targets: .bz-btn ~24px (intel.html:1091), .chip ~24-25px (:320), .sb-item 34px (WCAG 2.5.8 suggests 24px minimum; the sidebar item is the only one clearly comfortable).
- .set-note uses a decorative left border stripe (intel.html:1108-1110) that conveys nothing to AT; pervasive tiny 9–10.5px uppercase tracked headings throughout.
- The globe canvas labels itself "Interactive" (index.html:348) but has no keyboard interaction; the heatmap and sparkline canvases have no text alternatives for their data.

## 6. Positive findings

- **No XSS avenue found.** ~187 esc/escHtml/safeUrl calls against 91 innerHTML writes; safeUrl enforces a strict scheme filter (intel.html:3355); the home page escapes attacker-controlled strings as well (index.html:703-717).
- Tabs keyboard handling is correct per the ARIA Authoring Practices pattern.
- Polling is guarded per active view; the earlier chip-click fan-out was already fixed.
- prefers-reduced-motion is honored globally; the Cobe globe skips and pauses sensibly.
- CSP is strict (script-src 'self'), no CDN scripts, and tables are semantic.
- Server-side window truncation is disclosed to the client through X-ShardLure-Window-Truncated and the UI meta text (intel.html:3208 and elsewhere) — an honest API contract.

## 7. Recommended remediation order

1. Collapsible panels → native button triggers + ARIA state (P1).
2. Focus styles + labeled inputs (P1/P2).
3. Mobile landing scrollport + live-feed alternative (P1).
4. Combobox semantics + dialog semantics (P2).
5. Polling hygiene: visibility pause, overlap guards, try/catch on the home refresh (P2).
6. Defer vis-network; self-host/subset fonts (P2).
7. Responsive intel layout: remove inline grid templates, add a small-screen strategy (P2).
8. Contrast pass on --dim-2 and the light-theme hard-coded colors (P2/P3).

## 8. Recently completed backend work (cache-performance-bounds)

This work is **complete on the branch but not yet merged into main**, and it **is deployed on arm** (see section 9). Its intent is to stop the 5s dashboard poll from dragging slow all-history scans along with it.

The summary statistics cache was split by change cadence:

| Cache | TTL | Contents |
|---|---|---|
| liveSummaryStatsCached | 10s | Event/actor counts, intent/playbook counts, 72h hourly distribution, Cowrie liveness |
| distributionSummaryStatsCached | 1m | Kind and source distributions |
| lifetimeSummaryStatsCached | 5m | Unique IPs, countries, top IPs/users/commands, session count |
| hasshCoverageCached | 5m (unchanged) | HASSH fingerprint coverage over all events |
| topCountriesCached | 5m (was 10s) | Hits-by-country aggregation |

The windowed-events cache (eventsForWindowCached, 15s single-flight per exact window) now:

- carries an LRU used sequence number so it can evict by recency rather than arbitrarily;
- evicts expired entries before live ones;
- enforces a hard maxEventsCacheEntries = 4 bound on retained memory even when an authenticated client requests many distinct exact windows inside one TTL;
- keeps serving **last-good** data on transient store errors.

Window truncation disclosure was also tightened: the handler already returned the true window total alongside the capped slice, and the new tests (internal/web/window_disclosure_test.go, internal/web/cache_tiers_test.go) pin the header/disclosure contract and all three eviction behaviors.

Test status: the internal/web suite passes read-only, including the new TestSummaryStatsLifetimeValuesOutliveStatsTTL, TestSummaryStatsDistributionsRefreshIndependently, TestEventsWindowCacheEvictsLeastRecentlyUsedAtCapacity, and TestEventsWindowCacheEvictsExpiredBeforeLiveEntries.

## 9. Current deployed status (arm)

Verified read-only at 2026-09-07 against ubuntu@arm:

- **Branch:** fix/cache-performance-bounds, HEAD afb06ff (afb06ffd273c52f8badaf47799c106574d9d483d).
- **Deployed binary:** /usr/local/bin/shardlure — SHA-256 eddf6def2d7ab9b45019e8152585efaf0ebc5c46aa7d1abc1f1a8ef24dbe1826 (deployed Sep 3 17:41 IST). This corresponds to the cache-performance-bounds build.
- **shardlure-live:** active, MainPID 1002945, **0 restarts**, started Thu 2026-09-03 17:41:21 IST.
- **cowrie:** active, **0 restarts**.
- **HTTP:** / returns 200; /api/dashboard returns live data (generatedAt 2026-09-07T06:08:11Z; ~1.32M events, 7,194 actors, 8,502 unique IPs, 434,037 sessions, Cowrie uptime ~516,740s at probe time).
- **Rollback binary:** the previous rollback binary was deleted at the user's request. Only the live binary and two pre-existing .bak-* files remain in /usr/local/bin; the live unit is the sole authority now.
- **Frontend status:** the UI findings in sections 3–5 are **not yet fixed or deployed** — the deployed build predates any frontend remediation.
- **Worktree note:** the audit made no writes to repo files or to arm; the pre-existing dirty files (internal/web/server.go, internal/web/window_disclosure_test.go, internal/web/cache_tiers_test.go) are the branch's own in-progress cache work and were preserved untouched.

---

## 10. Remediation — 2026-09-07 (same day, all findings)

Section 2 said no browser was available to the auditor. One was available to
the fix pass, so **every finding above was first reproduced against the
pre-fix build before anything was changed**: a clean checkout of HEAD
(`afb06ff`) was built in a separate worktree, run on `:18090` with the sample
journal, and driven with Playwright (Chromium). Each item was measured from
the live DOM / computed styles / network log, then the patched build was run
on `:18091` and the same probes re-run. Nothing was fixed on the strength of
the source read alone, and nothing failed to reproduce — two items were
worse than written.

### Before → after, as measured

| # | Finding | Baseline (HEAD, real browser) | Patched |
|---|---|---|---|
| 3.1 | Collapsible panels | 3 × `<div onclick>`, `tabIndex -1`, no `aria-expanded` | 3 × `<h2><button aria-expanded aria-controls>`; focusable, ring visible, toggle flips state, collapsed body `visibility:hidden` |
| 3.2 | Mobile landing (375×812) | `html,body overflow:hidden`; left rail `position:fixed` 876px tall in an 812px viewport, its own scroll never engaging; right rail `display:none` (no Top IPs, **no live feed**); `#cobe-wrap max-width: 0px` — **the globe did not render at all** | page scrolls (1929px); rails static; feed panel 324px with rows; Top IPs rendered; globe 293px, painted; sparkline shown |
| 3.2b | Tablet landing (900×700) — *not in the audit* | `.rail.left` 344px (its own rule out-specifies the ≤1100px breakpoint) → globe `max-width:156px` | rails 280px, globe 293px |
| 3.3 | Focus styles | 4 × `outline:none`, 0 `:focus-visible` rules; search input focused via keyboard: `outlineStyle: none` | 0 × `outline:none`; one shared `:focus-visible` ring in `themes.css`, per-theme `--focus-ring` (≥3:1 on each ground); search input: `2px solid` ring |
| 4.1 | Labels | 4 static controls with placeholder only; **19 of 23** generated Settings inputs unlabelled | 0 unlabelled (static: `aria-label`; Settings rows: `aria-labelledby` → the row's own name span) |
| 4.2 | Search combobox | no role / `aria-controls` / `aria-expanded` / `aria-activedescendant` | `role=combobox`; `aria-expanded` tracks the listbox; `aria-activedescendant` = `pal-opt-N` and follows ArrowDown; options carry `aria-selected` |
| 4.3 | Modals | `<div>` overlays, no role; after `openSession()` focus stayed on `<body>` | native `<dialog aria-labelledby>` + `showModal()`: focus lands on the close button, Tab stays inside, Esc closes, focus returns to the opener (all observed) |
| 4.4 | Polling | intel: 13 bare `setInterval`, 0 `visibilitychange`; index: no in-flight guard, no try/catch | every poller through `pollEvery` (skips hidden tabs, refreshes on return); `refresh()` on both pages guarded + try/finally |
| 4.5 | vis-network | `<script src>` in `<head>`, no defer; fetched on every page load (689 KB) | not requested at load; `ensureVis()` injects it on first graph refresh |
| 4.6 | Inline grids | 5 elements with inline `grid-template-columns`; at 375px the stats row still computed **5 columns × 46px** | 0 inline grids; `.stats.cols-5` → 2 columns × 169px at 375px |
| 4.7 | Intel small screens | `.shell` `52px 323px` at 375px; tabs clipped; labels truncated ("EVENT", "ACTO") | `.shell` `375px`; sidebar is a 47px top strip; tables `min-width:620px` scrolling inside their panel; tabs scroll |
| 4.8 | Contrast | `--dim-2` computed `#604840` on `#0f1113` = **2.40:1**; 24 declarations at 8–9.5px | per-theme `--dim-2` (Signal `#86888b` 5.3:1, light `#66686d` 4.8:1, Meridian `#57626f` 4.8:1, Sprite `#7a6759` 5.0:1; Meridian `--dim` was itself 4.46:1 and is now `#525d6b` 5.2:1), every value ≥4.5:1 against bg *and* both panel surfaces, computed by `TestDimTokensMeetContrast`; 0 declarations below 10px |
| 4.9 | Fonts | 3 `<link>`s; live requests to `fonts.googleapis.com` + 8 × `fonts.gstatic.com`; CSP whitelisted both | 0 external requests; 11 latin woff2 faces (289 KB) embedded under `/fonts/`; CSP is `'self'` for every directive. Chakra Petch / Space Grotesk were requested but resolved by no theme and are dropped |
| 4.10 | Light-theme literals | under Meridian `.sm-body` computed `rgb(2,6,13)`; white-alpha tints on light grounds | `--bg`/`--glass` tokens; every legacy `rgba(200,152,40,…)`-family tint rewritten as `color-mix(var(--token) …)` with the token chosen from the rule's own text colour |
| P3 | Sidebar / tabs / canvases / stripes / targets | `title` only, svg exposed; tabs without `aria-controls`, 0 tabpanels; heatmap canvas unlabelled; `border-left` stripes; chips 27.75px | `aria-label` + `aria-hidden` svg; `tab-*` ↔ `view-*` wired; heatmap `role=img` + a maintained hidden summary (`setHeatmapDesc`); sparkline described by its peak readout; stripes replaced by full tinted borders; chips 28px |

### What changed

- `internal/web/intel.html`, `internal/web/index.html` — all of the above.
- `internal/web/themes.css` — per-theme `--dim-2` / `--focus-ring`, the shared `:focus-visible` rule, Meridian `--dim`, the globe stage's tablet/phone rules (kept beside the desktop ones because this file loads last), overlay label floor.
- `internal/web/fonts/` (+ `scripts/fetch-fonts.sh`, `internal/web/embed.go`, `handleFont` in `server.go`) — self-hosted typography; CSP tightened.
- `internal/web/frontend_a11y_test.go` — 19 tests pinning every contract in the table, including a WCAG contrast computation over `themes.css` and a check that every quoted family in a theme stack is actually vendored (that check immediately caught the dead Space Grotesk reference and Sprite's quoted system "SF Mono").
- `CLAUDE.md` — Web layer section updated (cache tiers, fonts, contracts).
- **Found while verifying, not in the audit:** on an empty window `/api/intel/graph` encoded `"edges": null` and the Red tab's pivot graph read `data.edges.length`, so a fresh install showed "load failed: Cannot read properties of null" instead of an empty graph. Confirmed at HEAD and against the live API before fixing; the handler now encodes `[]` (`TestIntelGraphEmptyWindowEncodesArrays`) and the JS guards both slices. Verified live: the panel reads `0 nodes · 0 edges · 24h window`.

Gates: `go vet ./...`, `scripts/check-utf8.sh`, `go test ./...`, `scripts/ci-web-smoke.sh` all pass.

### Deliberately not changed

- The pivot-graph node colours (`NODE_STYLE`) and their legend swatches stay literal: they must agree with each other and are read by vis-network, not CSS.
- Tabs remain `<span role="tab">` with the existing (correct) roving-tabindex keyboard code; they gained ids/`aria-controls`, not a rewrite.
- `body` overflow stays hidden between 761px and 1100px — that range keeps the fixed two-rail layout, only the rail widths and the globe formula were corrected.
- The Sprite "LIVE · home" chip can protrude past a 375px viewport when the operator's home city sits at the globe's right limb; cosmetic, left as is.

### Deployed to arm — 2026-09-07 12:53 IST

Sources tar-pushed to `~/ShardLure` (the arm checkout; its `.remember/` was
backed up first since the overlay overwrites same-named files), `go.mod`/`go.sum`
sha256-matched against local, the 11 woff2 files hash-identical, `internal/web`
vetted and tested **on arm64** (go1.27.0 via `GOTOOLCHAIN=auto`), built with
`-X main.version=fix-cache-performance-bounds -X main.commit=afb06ff+cachefix+frontend`,
smoke-tested with `ci-web-smoke.sh` on a temp port and probed for `/fonts/` + the
`'self'`-only CSP on a temp instance **before** install. Previous binary kept at
`/usr/local/bin/shardlure.bak-precachefrontend-20260907-1253`. No schema change,
so no DB backup was taken. New binary SHA-256
`e2eb695904e3349211634fd2f6ce384fefe514fe3866cee0071a886610a6a69d`.

Post-deploy (live unit, 1,323,099 events / 7,198 actors):

| Check | Result |
|---|---|
| `shardlure-live` | active, 0 restarts, no `-p err` journal lines; listener bound ~8 s after restart (history seed) |
| `cowrie` | active, 0 restarts |
| `/`, `/intel`, `/fonts/fonts.css`, `/fonts/inter-var.woff2` (`font/woff2`), `/vendor/vis-network.min.js`, `/themes.css` | all 200 |
| CSP | every directive `'self'`; served `intel.html` has 0 Google-font references and no vis-network `<script>` in `<head>` |
| Ingest | event count advanced 1,323,083 → 1,323,099 across the restart |
| `/api/dashboard` | cold (all tiers empty, right after restart) 6.17 s; warm 4.6 ms; after a 12 s idle (only the 10 s tier expired) **1.99 s** — identical to the pre-deploy 1.88 s, as expected: this deploy changes the frontend, not the 10 s tier |

**Observation for the next perf pass, not changed here:** the 10-second tier
alone still costs ~1.9–2.0 s on the production DB (measured before and after,
both binaries carry the cache-tier split). The lifetime/distribution tiers are
doing their job — the difference between "all tiers cold" (6.2 s) and "10 s tier
only" (2.0 s) is exactly their share — but something on the 10 s path
(`liveSummaryStatsCached` + `dashExtraCachedValues` + whatever `handleDashboard`
still runs per request) is worth timing query-by-query the way the 08-31 audit
did for `HASSHCoverage`.

### Post-review fixes — 2026-09-07 13:30 IST

A final code review of the whole diff (17 verified findings, 1 refuted) turned
up regressions and gaps the fixes above had introduced or left; all reproduced
against the code before being changed:

- **Cold geo pinned for 5 min.** Raising the countries/lifetime tiers to 5 min
  cached an *empty* first read (the geo table is filled asynchronously by the
  handler that reads it), freezing the intel Attack Geography at "resolving…"
  and the countries tile at 0 for up to 5 min on a fresh DB. Degenerate values
  now expire on the 10 s TTL (`lifetimeStamp`; test).
- **Stale-on-error discarded.** The tier combiner turned any tier refresh error
  into a 500 although a last-good value existed; it now serves it (test).
- **Download controls were href-less anchors** — not focusable, no link role —
  left in place by the accessibility pass. Now real `<button>`s (test).
- **Phone star-field rule out-specified** by Signal's `background-attachment:
  fixed` selector; the phone rule names that selector too.
- **Tablet globe overlapped the left rail**: the stage centred in the viewport,
  not in the band between the rails, and the tablet budget omitted the sidebar.
  Stage now starts at the sidebar edge above 760 px; budget corrected.
- **Inline heights on the right-rail panels** (the class of bug the stats fix
  was about) and a magic 380 px feed height on phones: moved to classes, the
  feed is content-sized on phones; the inline-style test now covers
  height/flex, not just grid.
- **Resume bursts**: pollers skip the visibility-resume run if less than half
  their period has elapsed; index.html's poller has the same guard.
- **`immutable` fonts without content-addressed names**: `fetch-fonts.sh` now
  names faces `<family>-<weight>-<sha8>.woff2` (test checks name vs bytes).
- Minor: graph edges initialised in `graph.Build` (the handler's nil branch was
  dead), the pre-paint theme script validates the stored theme (a stale value
  from a removed theme rendered the pre-theme palette in an un-vendored font),
  `:root --sans` is now a vendored family, the heatmap axis and its text
  alternative share one hour formatter.

Deferred, noted for a later pass: fold the three tiers + countries into one
generic memo type with a single serve-stale policy; a shared `poll.js` for both
pages; fan the tier refreshes out concurrently so a coinciding expiry costs
max() rather than sum().
