# ShardLure Codebase Audit — Dead Code, Refactoring, Optimizations

**Date:** 2026-07-02
**Tree:** `858d16a` (post-sync with origin/main)
**Method:** mechanical analyzers (`deadcode`, `staticcheck`, `go vet`, `gofmt`) + four scoped review passes (store/ingest, web/capture, actor/intel, cmd/tui/scripts), every finding re-verified against the current tree. High-impact claims independently reproduced (tar behavior, Python precedence, SQLite query plans via `EXPLAIN QUERY PLAN`, bubbles keymap source, shell quoting).

Baseline: `go build ./...` OK, `go test ./...` 20/20 packages pass, `go vet` clean, `gofmt` clean, `staticcheck` clean.

---

## Part 1 — Bugs found along the way (fix first)

These came out of the refactoring/optimization review but are outright defects.

### B1. Primary deploy path ships zero files from `cmd/shardlure/` — CRITICAL
`scripts/push-sources.sh:21` — `--exclude='shardlure'` matches any path *component* named `shardlure`, so the tarball drops the entire `cmd/shardlure/` directory (and `scripts/shardlure`). **Empirically reproduced** with GNU tar. This is the `make deploy` path; the documented follow-up `go build ./cmd/shardlure` fails on any fresh remote. It only ever worked on remotes that already had the directory from an older push.
**Fix:** `--exclude='./shardlure'` (verified: ships `cmd/shardlure/`, still drops the root binary).

### B2. Bash installer destroys the pristine sshd_config backup on re-run — HIGH
`scripts/shardlure:165-167` — the guard greps sshd_config *content* for `shardlure-bak`, a string nothing ever writes there, so it's always true; a second run copies the already-modified config over the original backup. The Python installer does it correctly (`shardlure.py:233` checks `not bak.exists()`).
**Fix:** `[ ! -f /etc/ssh/sshd_config.shardlure-bak ]`.

### B3. TUI highlights the wrong actor (double cursor move) — HIGH
`tui/app.go:157-168` — j/k handler moves `m.cursor` + `SetCursor`, then falls through to `m.actors.Update(msg)`, and bubbles v0.20.0's default table keymap **also** binds j/k/up/down (verified in module source) → the highlight is permanently one row ahead of the detail panel. Compounded by `refreshPanels` (`tui/app.go:100-149`): the detail panel reads `list[m.cursor]` from a *fresh* `ListActors` (re-sorted by `last_seen DESC` every second) while the visible table rows are stale until manual `r` — so the detail can describe a different actor even without keypresses.
**Fix:** `return m, nil` from the up/down cases (or drop custom cursor tracking, read `m.actors.Cursor()` after delegating); use one `ListActors` result per tick to update both table rows and detail.

### B4. Live tail and batch ingest disagree on non-admin accepted logins — HIGH (correctness)
`internal/ingest/journal/tail.go:41-51` stamps an ActorID and calls `actor.SyncJournalEvent` for non-admin `KindAccepted` events; the batch path deliberately excludes accepted events from actor formation (`ingest.go:87-90`, `ingest.go:138-140`). Same log line ⇒ different actor state depending on ingest path, and a later batch rebuild silently reverses the live tail's contribution.
**Fix:** in tail.go, skip the ActorID stamp + `SyncJournalEvent` for `KindAccepted`, matching batch semantics.

### B5. `install.sh --honeypot-port` never takes effect — HIGH
`scripts/install.sh` provisions authbind for the port and records it in shardlure.yaml, but never touches `$COWRIE_HOME/etc/cowrie.cfg` (verified: zero references) — stock Cowrie stays on its dist default 2222. The Python installer has the needed `patch_cowrie_cfg` (`shardlure.py:481`).
**Fix:** port that patching step into install.sh, or make install.sh delegate to the Python installer.

### B6. `fix-go-sources.sh` rewrites every clean file on every run — MEDIUM
`scripts/fix-go-sources.sh:33` — Python conditional-expression precedence: `if s.encode() != orig.replace(...) if b"\x00" in orig else orig:` evaluates to truthy `orig` for clean files. **Reproduced.** Consequence: misleading `fixed <file>` output + mtime churn forcing full rebuilds after every deploy.
**Fix:** parenthesize the right-hand side.

### B7. `deploy-cowrie-live.sh` remote Python is corrupted by shell quoting — MEDIUM
`scripts/deploy-cowrie-live.sh:19-28` — the heredoc sits inside a double-quoted `ssh "..."` argument; the local shell strips inner quoting so the remote receives `if bx00 in b:` → `NameError`, and `set -eo pipefail` aborts the deploy. **Reproduced.** (Script is also referenced nowhere and uses raw `scp` against the README's own warning — candidate for deletion, see D-list.)

### B8. `vps-finish.sh` silently drops `SHARDLURE_*` env overrides — MEDIUM
`scripts/vps-finish.sh:80-86` — the config writer runs under `sudo` (env_reset) with only `SL_BUILD_BIN` forwarded; `SHARDLURE_HONEYPOT_PORT/ADMIN_PORT/DASH_PORT/ADMIN_IPS` are stripped and defaults always win.
**Fix:** forward them like `SL_BUILD_BIN`.

### B9. Bash installer appends duplicate `[shardlure]` sections — MEDIUM
`scripts/shardlure:256-260` — unconditional `cat >>` into cowrie.cfg on every run; configparser (strict) raises `DuplicateSectionError` and can stop Cowrie from starting.
**Fix:** guard with `grep -q '^\[shardlure\]'` — or resolve via R1 below (retire the bash installer).

### B10. Config drift: geo silently disabled on Python-installed boxes — MEDIUM
`shardlure.yaml` is generated by four independent writers (install.sh:137, vps-finish.sh:102, shardlure.py:576, scripts/shardlure:314). install.sh/vps-finish emit `geoip.enabled: true`; the Python + bash installers omit the section and `config.Default()` leaves it `false` → globe arcs/country stats (headline feature) silently off depending on install path.
**Fix (minimum):** add geoip to the Python/bash writers; **better:** single config emitter (see R6).

### B11. `freshness_days` documented but ignored — MEDIUM (abuse.ch policy-relevant)
`internal/config/config.go:86` — parsed, defaulted (10), shipped in `shardlure.yaml.example:57`, claimed by README ("share respects freshness_days") — zero readers. `cmd/shardlure/share.go:35` hardcodes `10*24*time.Hour`. Operator setting `freshness_days: 3` still uploads 10-day-old samples.
**Fix:** default `--since` from config when the flag isn't passed.

### B12. Usage text suggests flag values the parser rejects — LOW
`cmd/shardlure/main.go:456` and `share.go:57` suggest `--since 10d`/`30d`; `flag.Duration` cannot parse day suffixes (README's `240h` is correct). Fix strings or add a custom flag.Value.

---

## Part 2 — Dead code

### Confirmed by `deadcode` (11 unreachable functions)
| Symbol | Location | Note |
|---|---|---|
| `BuildFromJournal` | `internal/actor/builder.go:117` | only caller is dead `SyncJournalIP` |
| `BuildJournalActorsStreaming` | `internal/actor/builder.go:142` | 3rd-gen API, superseded |
| `journalCollector.FinalizeIP` | `internal/actor/builder.go:195` | see transitive notes below |
| `BuildFromCowrie` | `internal/actor/builder.go:294` | superseded |
| `BuildCowrieActorsStreaming` | `internal/actor/builder.go:317` | superseded |
| `resetLiveCollectorForTest` | `internal/actor/sync.go:99` | test-support in prod file → move to `_test.go`, don't delete |
| `SyncJournalIP` | `internal/actor/sync.go:381` | deprecated; root of a dead chain |
| `assertSafeURL` | `internal/capture/fetch.go:153` | |
| `Result.IsDuplicate` | `internal/intel/bazaar/client.go:93` | trim 2 test assertions (`IsAccepted` covers it) |
| `FilterByKind` | `internal/intel/ioc/collect.go:200` | |
| `Server.Run` | `internal/web/server.go:212` | |

### Transitive fallout (dead once the above are removed)
- **`internal/store/events_by_ip.go` — entire file** (`EventsByIP`'s only caller is `SyncJournalIP`).
- **`Store.UpsertActorIP` / `Store.UpsertActorUser`** (`sqlite.go:502/519`) — exported wrappers only called from `SyncJournalIP`. The unexported tx variants stay. `UpsertActor` stays (`cmd/_seed_demo` uses it).
- **`buildJournalActor`'s `copyUsers` param + copy block** (`builder.go:253, 283-289`) — `FinalizeIP` is the only true-caller; the live path's copy is discarded anyway (see O5).

### Additional dead code (agents, verified)
| Item | Location | Detail |
|---|---|---|
| `Store.EventExists` | `store/events_source.go:9` | zero callers; referenced only in comments. Its removal officially orphans `idx_events_identity` (see O2) |
| `Store.UpdateEventActor` (+file) | `store/update_event.go` | entire file dead |
| `Store.CountEventsSince` | `store/events_window.go:101` | zero callers |
| `Event.JA4` | `pkg/models/event.go:44` | DB column threaded through every scan/insert, **never assigned anywhere**. Delete or implement |
| `models.ActorIP` | `pkg/models/event.go:78-84` | zero references |
| `cowrieLine.Message` | `ingest/cowrie/ingest.go:42` | write-only; removing skips decoding a sizeable string per line (keep the warning comment) |
| `CowrieStats.Key` | `actor/builder.go:27` | write-only; `finalize()` recomputes it as `idSuffix` — replace with `CowrieActorID()` call (also fixes duplication R7) |
| `matcher.allowAll` | `intel/mitre/catalog.go:70, 234-236` | dead field + dead branch evaluated per-matcher per-event in the hottest classify loop |
| `Candidate.SrcIP/SessionID` | `intel/bazaar/share.go:23-24` | write-only; deliberately never shipped to abuse.ch — deleting removes future leak risk |
| `bazaar.Result.Raw` | `intel/bazaar/client.go:87` | write-only; pins up to 1 MiB response body per result |
| `accumulator.sampleSeen` | `intel/ioc/collect.go:83` | invariant-redundant with `sample != ""` |
| `Config.Save` | `config/config.go:202-216` | zero callers |
| `GeoIP.MMDB` | `config/config.go:52` | parsed, never read; still set in `shardlure.yaml.example:38` — confusing to operators |
| `relTime` | `web/intel.html:1848-1855` | JS never called |
| Source-filter chips | `web/intel.html:845-847, 1684` | write `Filters.source`; nothing reads it — dead UI |
| `lastArcKey`/`arcKey` | `web/index.html:505,769,778` | computed, stored, never compared → globe arcs reset (and animation restarts) every 5s. Implement the compare or delete |
| `model.err` | `tui/app.go:27,195` | checked in View, never assigned — while real errors are discarded (`_ = m.loadData()` etc.). Assign it to make the branch live |
| Nested `fs()` helper + `if ... pass` | `scripts/shardlure.py:454-455, 463-466` | defined never called; no-op error check |
| Unreachable branches | `builder.go:404-406` (HASSH backfill no-op), `builder.go:230,429` (`Count==0`), `bazaar_uploads.go:53-55` (`ErrNoRows` on COUNT), `journal/ingest.go:167-169` (empty tsSet), `cowrie/ingest.go:654-658` + `journal/parser.go:72-79` (timestamp layouts subsumed by RFC3339/RFC3339Nano) | note: the dead journal fallback hints at an unhandled `+0000` (no-colon) format some journalctl versions emit — worth a deliberate decision |
| Dead scripts | `scripts/gen_b64.py`, `scripts/deploy-cowrie-live.sh`, `scripts/push-to-vps.sh`, `scripts/push-installer.sh`, `scripts/plant-bait.sh` | zero references from README/Makefile/CI/other scripts (verified); deploy-cowrie-live is also broken (B7) |
| Unread JSON response fields | `api_intel.go:132-140` (sessionRow.Start/End/HASSH/Client/Actor), `server.go:455-467` (actorCard.ID/RateHour/Conf), `server.go:432-446` (shellSessionRow ts/geo fields), `api_intel.go:1160,653-669` | no consumer in either embedded page, TUI, or smoke script — candidates only, since JSON is nominally public API |
| Test-only store methods | `EventsBySource` (self-documented), `ListArtifactsSince` | different category — keep, or move noted |
| `cmd/_seed_demo/` | never built by CI (`_` prefix skips `./...`); `fakeSHA` is 62 hex chars (invalid sha256) | add a Makefile target so it at least compiles in CI; pad SHA |

---

## Part 3 — Optimizations (ranked)

### O1. Journal dedup full-scan pathology — HIGH (verified via EXPLAIN QUERY PLAN)
`ingest/journal/ingest.go:231` — `WHERE source=? AND ts IN (...)` makes SQLite pick `idx_events_identity` on the `source=` prefix and scan **every** journal row per 400-ts chunk. The cowrie side hit the identical bug and fixed it with a long warning comment (`cowrie/ingest.go:194-200`): filter on `ts` only, re-apply source in Go → point lookups on `idx_events_ts`. Runs on every daemon start (30-day journalctl seed): ~500k rows × 250 chunks ≈ 125M index-row visits.
**Fix:** mirror the cowrie approach (or better, share the helper — R4).

### O2. `idx_events_identity` is pure write amplification — HIGH
`store/sqlite.go:210` — 7-column covering index (incl. attacker-controlled `username`/`command`) on the hottest-write table; its only designed reader (`EventExists`) is dead, cowrie dedup deliberately avoids it, journal dedup only touches it via the O1 pathology.
**Fix:** after O1, migration v9 `DROP INDEX idx_events_identity`.

### O3. `/api/intel` + `/api/dashboard`: unbounded aggregates + N+1, every 5s per tab — HIGH
`web/intel.go:107-117,157,184` — `EventCount`/`ActorCount`/`UniqueIPCount` (COUNT DISTINCT over all events) + unbounded `GROUP BY` kind/source per poll; `intel.go:242` one `ActorUsersLimit` query per actor × 80. `server.go:573-575` repeats the counts on its own poll. The server already has the solution pattern (`topCountriesCached`, `eventsForWindowCached`).
**Fix:** short-TTL memoization of summary counts + aggregations; replace the per-actor loop with one `WHERE actor_id IN (...)` query.

### O4. `/api/intel/bazaar` N+1 × limit=1000 × two overlapping pollers — HIGH
`web/api_intel.go:990` — `GetArtifactBySHA` per upload row; frontend polls with `limit=1000` every 30s (`intel.html:2400`) *and again* with `limit=30` (`intel.html:2829`).
**Fix:** `JOIN artifacts ON sha256` in `ListBazaarUploads` (index exists); drop the duplicate poller.

### O5. Live journal path per-event waste — MEDIUM-HIGH
- `actor/sync.go:134-135,155` — `adminSetsEqual` sorts+joins both admin sets (`netmatch.Set.Key()`) on **every log line**, though the tail passes the identical pointer every call. Fix: pointer fast-path `if a == b`, and/or cache `Key()` in `New()` (Set is immutable).
- `sync.go:282` → `buildJournalActor(copyUsers=true)`: copies the whole per-IP users map (≤256 entries) per event — caller never reads it; plus a 1-entry map allocated and immediately unpacked. Fix: falls out of the D-list (`copyUsers` param removal) + return `IPStat` directly.
- Same pattern elsewhere: `capture/fetch.go:214` rebuilds `netmatch.New(adminIPs)` per dial/per DNS answer — build once in `NewSafeFetcher`.

### O6. MITRE classify lowercases the command 19× per event — MEDIUM-HIGH
`intel/mitre/catalog.go:232` — `strings.ToLower(e.Command)` at the top of `match`, called per technique (~19) per event by `Classify`/`ClassifyOne` (MITRE endpoint, session detail per line, `ttp.Harvest` per command).
**Fix:** hoist to once per event; pass the lowered string into `match`.

### O7. `ttp.Harvest` reclassifies repeated commands — MEDIUM
`intel/ttp/harvest.go:105-107,119` — full `ClassifyOne` (19 matchers) + `Normalise` (8 sequential regex passes) per event; honeypot command streams are massively repetitive by premise.
**Fix:** memoize both by raw command within the Harvest call.

### O8. Capture runner re-issues dedup queries forever — MEDIUM
`capture/runner.go:217-224, 315-337, 139-150` — every 5s tick: re-reads 500 newest commands + 2 regexes each + one `ArtifactURLRecorded` COUNT per URL; same for file-download events; `syncCowrieTTY` re-queries per already-indexed tty file including session backfill after it's stamped.
**Fix:** in-memory processed-set / event-ID watermark on the long-lived Runner (it already carries `ttyIndexed`), DB check only on cold start.

### O9. Actor-history re-sort every 5s tick — MEDIUM (verified plan: temp B-tree)
`store/events_source.go:85-87` — `IterateEventsByActorIDs ... ORDER BY ts` on single-column `idx_events_actor` → temp B-tree sort of each touched actor's full history per tick; also makes `LastCommandByActor`'s LIMIT 1 sort everything.
**Fix:** migration replacing the index with composite `(actor_id, ts)`. (The ORDER BY itself is required — collector is first-seen-wins order-sensitive.)

### O10. Frontend polling discipline — MEDIUM
- `intel.html:1635-1636` — the two heaviest pollers (`/api/intel` 5s, `/api/capture` 2s) aren't gated on the active tab; the gating pattern already exists in the same file (`intel.html:3131-3132`).
- `/api/capture` polled at 2s on both pages while data can only change on the 5s ingest tick; `CaptureSummary` is a full-table aggregate.
- Window-chip clicks fan out ~10 concurrent fetches; only `refreshMitre` checks its tab is visible (`intel.html:1770`).
- `server.go:595` + `intel.go:215` — synchronous `geo.prefetch(…, 5s)` inside request handlers can stall a 5s-polled endpoint its whole interval; both frontends already render "resolving…". Fix: fire-and-forget (inflight-dedup makes it safe).

### O11. Batch/IO details — MEDIUM-LOW
- `store/transaction.go:36-81,103-121` — no prepared statements in batch-insert loops; the modernc driver prepare→exec→finalizes per row (verified in driver source). Fix: `tx.Prepare` before loops.
- `journal/ingest.go:108-121` — non-replace ingest rebuilds every actor from full history even when the batch is 100% duplicates (every restart). Fix: early-return when `freshStored` is empty.
- `cowrie/ingest.go:411-431` — `readLineBounded` reads byte-at-a-time with per-line fresh buffers on the multi-hundred-MB backlog path. Fix: `ReadSlice('\n')` + reusable scratch.
- `journal/parser.go:56-67,95-113` — matched regex executed twice per line (`MatchString` then `FindStringSubmatch`); `SubexpIndex` per line. Fix: single `FindStringSubmatch` + hoisted indices.
- `capture/cowrie_index.go:62-76` — hand-rolled O(n·m) `containsBytes` over every log line; use `bytes.Contains`.

### O12. Micro (fix opportunistically) — LOW
`wordlist.go:119-120` string-concat per sort comparison; `payload/inspect.go:178` copies 64 KiB buf into string then reads byte-wise through two wrappers (`for _, b := range buf`); `deobf.go:169-186` per-pair `hex.DecodeString` allocs + convoluted bounds; `deobf.go:200` `[]rune(s)` just to count (`utf8.RuneCountInString`); `playbook.go:69` regex runs before the cheap check in `||`; `mitre/classify.go:110-111` `AllTactics()` called twice; `builder.go:277` recomputes a duration; `store/events_source.go:114-123` `joinComma` is O(n²) `strings.Join` reimplementation (used with 400 elems).

---

## Part 4 — Refactoring (ranked by value)

### R1. Retire the bash installer (`scripts/shardlure`, 459 lines) — HIGHEST VALUE
Complete duplicate of `shardlure.py` (1037 lines) that has drifted dangerously: no `ssh.socket` handling (**operator lockout** on socket-activated Ubuntu 22.10+/24.04 — the exact scenario the Python installer defends against), no key onboarding (just dies), no sshd rollback on `sshd -t` failure, no uninstall/finish/plant-bait, plus live bugs B2 and B9 — all already fixed on the Python side. Still reachable: `findSetupScript` (`cmd/shardlure/main.go:356-378`) falls back to it.
**Fix:** delete it (or reduce to a 5-line exec-shim around `shardlure.py`); delete its pusher `push-to-vps.sh`.

### R2. One shared NUL/UTF-16 repair helper — eliminates two live bugs
The repair Python is copy-pasted across `fix-go-sources.sh`, `repair-text.sh`, `vps-finish.sh`, `deploy-cowrie-live.sh` (old audit L16) and the copies have independently rotted into B6 and B7.
**Fix:** one `scripts/lib/repair_text.py`; remote callers pipe it over ssh stdin.

### R3. Enrich providers: table-driven spec — clearly worth doing
The 7 IP-reputation fetchers copy-paste the key-gate (5 files), 404-means-no-data (greynoise/shodan), and `Result{Configured: true}` returns; 3 of 7 decode inline and can't be unit-tested offline while the other 4 have a testable `parse(raw, ip)` split.
**Fix:** provider spec `{name, envVar, buildURL, headers, parse, emptyOn404}` + one generic fetcher — ~60 lines removed, all 7 offline-testable, provider #8 becomes a data change.

### R4. Shared chunked-dedup helper for cowrie/journal — prevents O1 recurring
`batchDedupCowrie`/`batchDedupJournal` are near-identical and diverged exactly where it hurts (the planner workaround). One helper parameterized on the identity tuple keeps the workaround single-site.

### R5. Store scan/query dedup
- Five copy-pasted 13-column Artifact scan blocks (`artifacts.go:176,357,391,497,530`) — the recent NULL-hardening commit had to patch four identically, proving the cost. Fix: `artifactColumns` + `scanArtifact`, mirroring the existing `actorColumns`/`scanActorRow` pattern.
- Triplicated actor-list loop (`ListActors`/`TopActorsByEvents`/`TopActorsByRate`) → `queryActors(q, args...)`.
- Event scan loops in 3 shapes (17-col, 16-col-no-raw, intel variants) with silent column drift → shared `eventColumns` + `scanEvent` (+ explicit no-raw variant).
- `parseTime` policy inconsistent: two sites propagate malformed timestamps ("fix #13"), ~10 sites swallow them, bazaar_uploads bypasses `parseTime` entirely. Pick one policy.

### R6. Single source of truth for generated `shardlure.yaml`
Four independent generators already diverged into B10. Fix: `shardlure config emit ...` subcommand in the Go binary or one shared template.

### R7. Web handler boilerplate
- Auth check `if !s.requireDashboardAuth(w, r)` copy-pasted in 22 handlers while `s.guard()` exists (used only for 6 debug routes). Fix: register everything via `s.guard(...)` — also removes the forgot-the-check bug class.
- Repeated window/limit prologue across 6+ intel handlers with two different limit-clamp behaviors → `parseLimit` + `windowEvents` helpers.
- `intelActorRow`/`actorCard` built twice each → small constructors.
- Content-Type charset inconsistency falls out for free.

### R8. Frontend structure (intel.html / index.html)
- ~200 lines of JS duplicated between the two embedded pages, already diverged (`flag()` returns `'??'` vs `''`, `shortURL` 56 vs 72 chars, fetch-wrapper capability drift). Fix: shared `/static/common.js` served like the vendored vis-network asset.
- `setActiveView` monkey-patched 10 deep — replace with a tiny tab-hook registry; also enables per-tab gating (O10).
- `uploadAllToBazaar`/`uploadAllPending` ~45-line near-duplicates → one `uploadShas()`.
- Three HTML-escaping helpers (`esc`, `escHtml` identical; `escAttr` weaker) → keep one full escaper.

### R9. CLI arg parsing (`cmd/shardlure/main.go`)
Three parsing styles; `web` and `live` use different addr heuristics (`live 8080` silently ignored, `web 8080` works); tailscale-URL block verbatim-duplicated (old audit L1); `cmdIngest` silently ignores unknown trailing args (`--repalce` typo flips replace→append silently). Fix: `parseServeArgs` + `printTailscaleURL` helpers; unknown flags fatal.

### R10. Smaller items
- `netmatch.Invalid` duplicates `New`'s parse cascade → shared `parseEntry`.
- Four IP-classification implementations (`isPrivateIP`, `isPublicIP`, `blockedIP`, `safeForEnrichment`) with divergent special-range coverage — the NAT64 gap was fixed for capture only (df93bd4) and can recur elsewhere. Long-term: consolidate in `internal/netmatch`.
- `shardlure.py:384+400` writes cowrie.cfg twice per install (acknowledged in comment) → let `apply_stealth_persona` be the single writer.
- `builder.go` after dead-code removal is coherent (ID helpers, collectors, scoring) — no need to merge into sync.go.

---

## Part 5 — Old AUDIT_REPORT.md (v4) status at 858d16a

| ID | Status |
|---|---|
| L1 (tailscale URL dup) | Remains — folded into R9 |
| L2 (ticker drift) | **Not a bug** — Go tickers drop missed ticks (1-buffer channel); recommend closing |
| L14 (installer config block ×2) | Fixed upstream; residual double-write noted in R10 |
| L16 (NUL repair ×4) | Remains, now with two divergent bugs (B6, B7) — R2 |
| L17 (CLI test coverage) | Remains — `main_test.go` only has `TestAddrPort` |
| L27 (unquoted heredocs) | Remains — `collect-payloads.sh:30,59`, `apply-stealth.sh:41` |
| L28 (/tmp TOCTOU) | Fixed upstream (`mktemp` + trap) |
| L30 (restore_sshd first `#Port`) | Remains — `shardlure.py:882` |

---

## Suggested execution order

1. **B1** (one-line tar fix — deploy is broken today) → then the VPS at `arm` can actually be used to test an install end-to-end.
2. **B2, B9 or R1** (retire bash installer — kills both + lockout risk), **B5, B8, B10** (installer correctness).
3. **B3 + TUI error plumbing** (D-list `model.err`), **B4** (ingest-path consistency), **B11/B12**.
4. Dead-code sweep (Part 2) — mechanical, test-gated; unlocks **O2** (drop the fat index) after **O1** (dedup query fix).
5. Hot-path optimizations **O3–O9** in order; frontend polling **O10**.
6. Refactors **R2–R9** as touch-that-code opportunities, except R2/R3/R4 which are worth doing standalone.

Each step is independently verifiable: `go build ./... && go test ./...` after every change; B1/B6/B7 have one-command reproductions; O1/O2/O9 verifiable via `EXPLAIN QUERY PLAN`.
