# ShardLure v2 Signal Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish Signal dark/light as one accessible visual system, make appearance switching reliable, replace the globe page's IP-first hierarchy with actor-first operational widgets, and remove avoidable frontend work.

**Architecture:** Extract shared appearance behavior into one embedded JS asset while retaining each page's tiny pre-paint localStorage snippet. Extend the existing dashboard response rather than adding endpoints/schema. Preserve Intel's four-tab structure and route every periodic refresh through visibility-aware scheduling.

**Tech Stack:** Go HTTP/embed/tests, vanilla HTML/CSS/JS, Cobe, headless Chromium/CDP.

## Test ownership

- Static Go source tests: required tokens/selectors/ARIA, mode-aware source, reduced-motion rules, lazy-loading contract, actor-first markup.
- Go behavior tests: settings round trip, actor IP counts, dashboard fields, report suggestion identity.
- Headless Chromium: actual broadcast/rollback, Cobe rebuild/redraw, focus, mobile geometry, hidden polling, and live-data visual states.

Static source tests never substitute for runtime verification.

---

### Task 1: Shared Appearance State and Persistence

**Files:**
- Create: `internal/web/theme-runtime.js`
- Modify: `internal/web/embed.go`
- Modify: `internal/web/server.go`
- Modify: `internal/web/index.html`
- Modify: `internal/web/intel.html`
- Modify: `internal/web/theme_settings_test.go`
- Create: `internal/web/frontend_contract_test.go`

- [ ] Add failing tests `TestThemeRuntimeJSServed`, `TestSettingsAppearanceRoundTrip`, `TestPagesLoadSharedThemeRuntime`, `TestThemeRuntimeReadsServerThemeAndMode`, `TestThemeRuntimeBroadcastsAppearanceTuple`, and `TestModeSaveRollbackContract`.
- [ ] Run `go test ./internal/web -run 'ThemeRuntime|Appearance|ModeSave' -count=1`; expect missing shared runtime/behavior failures.
- [ ] Centralize `normalizeTheme`, `normalizeMode`, `currentAppearance`, `applyAppearance`, `applyTheme`, `applyMode`, `broadcastAppearance`, and `syncThemeFromServer`. Keep only the pre-paint snippet inline.
- [ ] Both `ui.theme` and `ui.mode` are loaded; non-empty server values win independently. Broadcast `{theme,mode,source}` and ignore only the same source. Invoke `window.__shardlureOnTheme(theme,mode)` when either axis changes.
- [ ] Intel `selectMode` awaits save and atomically restores DOM/localStorage/toggle/status on failure; `selectTheme` rolls back theme plus remembered Signal mode.
- [ ] Run tests and commit: `fix(theme): centralize appearance state and rollback failed saves`.

---

### Task 2: Appearance-Tuple Cobe Invalidation and Redraw

**Files:**
- Modify: `internal/web/cobe-boot.js`
- Modify: `internal/web/index.html`
- Modify: `internal/web/intel.html`

- [ ] Add failing `TestCobeEnsureInvalidatesAppearanceTuple`, `TestIntelAppearanceHookRedrawsVisuals`, and `TestSignalLightIsLightGraphTheme`.
- [ ] Normalize mode before Cobe's early return; reuse only when both theme and mode match. Otherwise destroy/recreate while retaining home and actor data. Expose read-only `mode()`.
- [ ] A mode-only Intel change redraws the last heatmap and debounces graph rendering from `GRAPH.lastData`; Signal light counts as a light graph theme.
- [ ] Run `go test ./internal/web -run 'CobeEnsure|AppearanceHook|SignalLight' -count=1` plus `node --check` on Cobe files.
- [ ] Commit: `fix(theme): rebuild visualizations on Signal mode changes`.

---

### Task 3: Cohesive AA Signal Tokens

**Files:**
- Modify: `internal/web/themes.css`
- Modify: `internal/web/index.html`
- Modify: `internal/web/intel.html`

- [ ] Add failing `TestSignalThemeDefinesCompleteSemanticTokens`, `TestSignalThemeContrastAA`, `TestSignalThemeHasNoLegacyDragonPalette`, and `TestSignalUsesRadiusTokens`. The contrast test parses hex tokens and requires text ratios `>=4.5`, strong control boundaries `>=3`, and `accent-ink` over `accent-fill >=4.5` against actual panel surfaces.
- [ ] Establish:

```css
/* Signal dark */
--accent:#d1fe17; --accent-fill:#d1fe17; --accent-ink:#14151a;
--dim-2:#82868a; --purple:#b89bd6; --danger:#f04b50;
/* Signal light */
--accent:#526800; --accent-fill:#b6d900; --accent-ink:#14151a; --good:#1f7a45;
--warn:#8a5d00; --purple:#6f4f8c; --dim-2:#686b70;
/* Both */
--radius:12px; --radius-sm:8px; --radius-xs:5px;
```

Use readable `--accent` for text/borders and bright `--accent-fill` for graphics. Replace legacy red/brown/gold fallbacks, hardcoded small radii, and graph/heatmap legacy colors. Use the intended display hierarchy consistently; remove any font request that remains unused.
- [ ] Run the targeted tests and commit: `feat(signal): complete accessible dark and light visual tokens`.

---

### Task 4: Reduced-Motion Contract

**Files:**
- Modify: `internal/web/cobe-globe.js`
- Modify: `internal/web/cobe-boot.js`
- Modify: `internal/web/themes.css`

- [ ] Add failing `TestReducedMotionContract`.
- [ ] Thread `matchMedia('(prefers-reduced-motion: reduce)')` into globe interaction. Disable initial rotation and prevent timers/drag/focus from re-enabling it while reduced; react to preference changes.
- [ ] In the media block stop title/sidebar/live/capture/timeline/satellite pulses, feed/capture entry animation, and collapsible transitions with `!important`.
- [ ] Run the web test plus Cobe syntax checks; commit: `fix(a11y): honor reduced motion across globe and chrome`.

---

### Task 5: Actor-First Dashboard Data

**Files:**
- Create: `internal/store/actor_ips.go`
- Create: `internal/store/actor_ips_test.go`
- Modify: `internal/web/server.go`
- Create: `internal/web/dashboard_response_test.go`
- Modify: `internal/intel/abuseipdb/suggest.go`
- Modify: `internal/intel/abuseipdb/suggest_test.go`
- Modify: `internal/web/api_intel.go`

- [ ] Add failing `TestActorIPCountsForActors`, `TestDashboardActorFirstResponse`, and `TestSuggestPreservesActorID`.
- [ ] Implement one batched `ActorIPCountsForActors(ids []string)` query over indexed `actor_ips`.
- [ ] Extend `actorCard` with `source`, `intent`, `uniqueUsers`, `probeScore`, and `ipCount`. Add dashboard `playbookCounts` from the existing summary cache. Add `ActorID` to AbuseIPDB suggestion input/output and populate the selected stable identity.
- [ ] Retain old JSON fields for compatibility and geo fallback; do not add endpoint or migration.
- [ ] Run `go test ./internal/store ./internal/intel/abuseipdb ./internal/web -count=1`; commit: `feat(dashboard): expose actor-first operational context`.

---

### Task 6: Replace IP-Centric Landing Widgets

**Files:**
- Modify: `internal/web/index.html`

- [ ] Add failing `TestLandingUsesActorFirstWidgets`.
- [ ] Replace:
  - `top-countries` with `roaming-identities`, merging recent 100 plus top 14 by actor ID, filtering `ipCount>1`, honestly labeled as the current actor set.
  - `top-ips` with `active-campaigns`, showing stable actor, playbook/intent, probe/confidence, rate and current IP.
  - `top-users` with `credential-playbooks` using cached `playbookCounts`.
  - `top-commands` with `operator-queue`, polling existing AbuseIPDB suggestions every 30 seconds and linking to `/intel#tab=blue`; no report mutation on landing.
- [ ] Keep Summary, Recent Sessions, Capture, Live Feed, Globe, and Events/hour. Add `setDashboardState('loading'|'ready'|'empty'|'stale')`; failures retain last-good data and announce staleness.
- [ ] Run targeted web tests and commit: `feat(dashboard): make the globe page actor-first`.

---

### Task 7: Keyboard and Dialog Essentials

**Files:**
- Modify: `internal/web/intel.html`

- [ ] Add failing `TestIntelTabArchitectureAndARIA`, `TestIntelInteractiveMarkup`, `TestIntelDialogMarkup`, and `TestCanvasAlternatives`.
- [ ] Convert four tabs and five window chips from spans to buttons. Add tablist/tab/tabpanel relationships and update `aria-selected`, `tabIndex`, `hidden` in the base `setActiveView`. Support ArrowLeft/Right, Home, End without changing view IDs/hashes.
- [ ] Replace inline collapsible handlers with `wireCollapsibles()` supporting click, Enter, Space, and `aria-expanded`. Make actor/session rows keyboard activatable and payload SHA controls semantic buttons.
- [ ] Give both modals dialog roles, labels, focus entry/trap, Escape close, and trigger-focus restoration through shared `openDialog`/`closeDialog`.
- [ ] Add accessible names and textual summaries for globe, sparkline, heatmap, and graph canvases.
- [ ] Run tests and commit: `fix(a11y): make Intel controls and dialogs keyboard complete`.

---

### Task 8: 390px Layouts

**Files:**
- Modify: `internal/web/index.html`
- Modify: `internal/web/intel.html`
- Modify: `internal/web/themes.css`

- [ ] Add failing `TestLandingMobileCSSContract` and `TestIntelMobileCSSContract`.
- [ ] At `<=760px`, make landing a scrolling column with both rails relative and visible, sidebar/vignette removed, sparkline in flow, and Cobe width around `min(88vw,340px)` with no `calc(100vw - 720px)` cap.
- [ ] On Intel hide the narrow sidebar, place topbar/main in column one, make tabs horizontally scrollable, reduce padding, and render `.overview-stats` as two `minmax(0,1fr)` columns. Remove the inline five-column override.
- [ ] Run targeted tests and commit: `fix(responsive): preserve globe and Intel workflows at 390px`.

---

### Task 9: Visibility Scheduling and Lazy Graph Bundle

**Files:**
- Modify: `internal/web/index.html`
- Modify: `internal/web/intel.html`

- [ ] Add failing `TestPollersUseVisibilityScheduler`, `TestIntelDoesNotEagerLoadVisNetwork`, and `TestIntelTabArchitectureContract`.
- [ ] Add `registerVisiblePoll` on landing and `registerViewPoll(viewID,fn,interval,guard)` on Intel. Clear timers while hidden; on visibility restore immediately refresh only active work. Route all current intervals through the scheduler, including the operator queue.
- [ ] Remove eager `<script src='/vendor/vis-network.min.js'>`. Memoize `ensureVisNetwork()` and await it only inside Red graph refresh. Keep current embedded asset route.
- [ ] Run tests and commit: `perf(web): pause hidden polling and lazy-load graph code`.

---

### Task 10: Runtime UI Release Gate

**Files:**
- Create: `scripts/web-ui-regression.mjs`

- [ ] Implement named CDP/Chromium checks: `serverModeWinsOnInitialSync`, `sameThemeModeBroadcastsAcrossTabs`, `failedModeSaveRollsBack`, `cobeRebuildsForSignalMode`, `modeRedrawsHeatmapAndGraph`, `reducedMotionStopsPersistentMotion`, `tabsRowsAndDialogsWorkByKeyboard`, `landingAndIntelFit390px`, `hiddenPagesStopRequests`, `visNetworkLoadsOnlyOnRed`, and `landingRendersLoadingEmptyPopulatedAndStale`.
- [ ] Mobile acceptance: globe width `>=280px`, right rail visible, no document horizontal overflow, readable Intel stats, scrollable tabs. Lazy-load acceptance: no vis resource on Overview and exactly one after first Red activation.
- [ ] Run:

```bash
go test ./internal/store ./internal/intel/abuseipdb ./internal/web -count=1
node --check internal/web/theme-runtime.js
node --check internal/web/cobe-boot.js
node --check internal/web/cobe-globe.js
bash scripts/check-utf8.sh
go vet ./...
go test ./... -count=1
go build -o /tmp/shardlure-v2 ./cmd/shardlure
BIN=/tmp/shardlure-v2 bash scripts/ci-web-smoke.sh
BIN=/tmp/shardlure-v2 node scripts/web-ui-regression.mjs
```

- [ ] Commit: `test(web): gate v2 appearance accessibility and performance`.
