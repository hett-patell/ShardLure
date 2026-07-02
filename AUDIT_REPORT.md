# Shardlure Code Audit Report — v4

**Date:** June 10, 2026
**Auditor:** opencode (openrouter/xiaomi/mimo-v2.5-pro)
**Scope:** Full codebase — Go source, shell scripts, Python installer, CI/CD, config

---

## Verification Summary

Every issue from v3 was re-read against the actual source code. **12 issues were fixed** since v3, **1 was a false positive**, and **13 remain**.

### Fixed Since v3 (12)

| v3 ID | Description | How Verified |
|-------|-------------|-------------|
| M6 | Silent error swallowing in backfill | `ingest.go:239-241`: now `log.Printf("cowrie backfill: ingest %s failed: %v", p, err)` |
| M9 | Auth token in query string | `server.go:262-274`: header-only now (`Authorization: Bearer` + `X-ShardLure-Token`), no `r.URL.Query().Get("token")` |
| N1 | `$COWRIE_HOME` interpolated into Python heredoc | `shardlure:265-269`: uses `<<'PY'` (quoted, no expansion) + explicit env vars `COWRIE_HOME=... HONEYPOT_PORT=... python3` |
| L5 | Unbounded queries when limit=0 | `dashboard.go:152-154`: `const defaultTopLimit = 1000; if limit <= 0 { limit = defaultTopLimit }` |
| L9 | Byte vs rune in `isMostlyLowerAlpha` | `playbook.go:105-111`: uses `total` counter incremented per rune, not `len(s)` |
| L11 | `cap` shadows builtin | `runner.go:27`: renamed to `capCfg` |
| L15 | Stale embed of `shardlure.py` in `fix-shardlure-py.sh` | `scripts/fix-shardlure-py.sh` does not exist (glob returned no files) |
| L20 | No `IdleTimeout` on HTTP server | `server.go:219`: `IdleTimeout: 120 * time.Second` |
| L22 | Hardcoded Tailscale IP `100.95.188.127` | `vps-finish.sh:90-91`: replaced with `print("warning: no admin IPs detected...")` |
| L23 | No config validation | `config.go:153`: `if err := c.Validate(); err != nil { return c, err }` |
| L25 | Bash wrapper pip failures ignored | `shardlure:247-249`: `\|\| die "pip install ... failed"` on all three pip commands |
| L29 | Config write logic bug (for/continue/write) | `shardlure:265-269`: Python heredoc rewritten to use env vars; the old buggy pattern is gone |

### Partially Fixed (1)

| v3 ID | Description | Status |
|-------|-------------|--------|
| L28 | TOCTOU race on `/tmp/shardlure` | **Partially fixed**: `shardlure.py:549` now uses `tempfile.mkstemp(prefix=".shardlure.", dir=str(BIN_DIR))`. `vps-finish.sh:56,109` still builds to and copies from `/tmp/shardlure`. |

---

## Remaining Issues (13)

### 🟡 MEDIUM Severity (0)

All MEDIUM issues are resolved.

---

### 🟢 LOW Severity (14)

#### L1. Duplicated Tailscale URL Printing
**File:** `cmd/shardlure/main.go` — `cmdWeb` (~line 96) and `cmdLive` (~line 210)

Both functions have identical tailscale URL printing logic. Should be extracted to a helper.

**Verified:** Both contain `if tailscaleHint { if ip := tailscaleIPv4(); ip != "" { ... } }` with the same formatting.

---

#### L2. Ticker Interval Drift
**File:** `cmd/shardlure/main.go:249-260`

Uses `time.NewTicker` inside a goroutine. If `IngestFileAppend` or `capRunner.Run` takes longer than `interval`, ticks queue up and fire back-to-back.

**Verified:** `select { case <-t.C: ... }` with no drain/guard logic.

---

#### L3. `MaintenancePurge` Ensure-Then-Lock Pattern
**File:** `internal/store/sqlite.go:690-708`

`EnsureEnrichmentTable()` / `ensureCowrieTTYIndex()` / `ensureArtifactsTable()` each acquire and release `writeMu` via `execWrite`. Then `writeMu.Lock()` is acquired for the transaction. Between ensure and lock, another writer could interleave.

**Verified:** The comment at line 704-706 acknowledges this is intentional.

---

#### L6. Two Queries Where One Would Suffice
**File:** `internal/store/bazaar_uploads.go:95-125`

`BazaarUploadStats` runs two queries: one for uploaded/duplicate counts, one for pending count with a `NOT IN` subquery.

**Verified:** Two separate `QueryRow` calls.

---

#### L7. AdminSet Key Recomputed Per Event
**File:** `internal/actor/sync.go:133-135`

`adminSetsEqual` calls `a.Key()` and `b.Key()` which sort and join all entries. Called per-event in live tail.

**Verified:** `return a.Key() == b.Key()` with no caching.

---

#### L12. Duplicated Family Indicator Strings
**File:** `internal/intel/bazaar/classify.go:156-180` vs `213-237`

`matchELFFamily` (binary path) and `classifyScriptFamily` (script path) duplicate family strings (RedTail, XMRig, Coinminer, Traffmonetizer, Komari). Tag sets also diverge — scripts add `"dropper"`, binaries don't. Mirai/Gafgyt only in binary path.

**Verified:** Both functions contain independent `switch` blocks with overlapping family names.

---

#### L14. Config Block Defined Twice in Python Installer
**File:** `scripts/shardlure.py:298-326, 447-474`

`install_cowrie` defines a `[honeypot]`/`[output_jsonlog]`/`[ssh]` block and appends it; `patch_cowrie_cfg` defines a near-identical block. The `if not all(s in text for s in (...))` guard prevents duplication at runtime, but the code duplication is confusing.

**Verified:** Two separate block definitions with overlapping content.

---

#### L16. NUL-Byte Repair Duplicated Across 4 Files
**Files:** `fix-go-sources.sh`, `repair-text.sh`, `vps-finish.sh`, `deploy-cowrie-live.sh`

Nearly identical Python blocks to strip NUL/UTF-16 bytes are copy-pasted across 4 files.

**Verified:** All 4 scripts contain inline Python with the same decode/replace logic.

---

#### L17. Minimal Test Coverage for CLI
**File:** `cmd/shardlure/main_test.go` — only `TestAddrPort` (17 cases)

No tests for `cmdIngest`, `cmdLive`, `cmdWeb`, `tailscaleIPv4`, `findSetupScript`, `shaShort`, or argument parsing ambiguity.

**Verified:** 39-line file with a single test function.

---

#### L19. Cowrie `finalize()` Passes Map by Reference
**File:** `internal/actor/builder.go:468`

```go
actors = append(actors, &AggregatedActor{Actor: a, IPs: st.IPs, Users: st.Users})
```

`st.IPs` and `st.Users` are map references passed directly. Safe only if `st` (the `sessionTracker`) is not reused after `finalize()`. The journal collector defensively copies; the cowrie collector does not.

**Verified:** No copy operation on the maps before passing.

---

#### L21. `parseTime` Errors Silently Zeroed Throughout Store
**Files:** `internal/store/enrichment.go:54`, `sessions.go:149-150`, `events_source.go:55`, and others

All use `e.TS, _ = parseTime(ts)` or `r.FetchedAt, _ = parseTime(fetched)`. Malformed timestamps produce zero `time.Time`, which is misleading (appears as epoch 1970).

**Verified:** Every `parseTime` call in the store discards the error with `_ =`.

---

#### L27. Python Heredoc Variables in Operational Scripts
**Files:** `scripts/collect-payloads.sh:33-34,63-64`, `scripts/apply-stealth.sh:44-46`

`$DB`, `$OUT`, `$COWRIE_HOME`, `$PERSONA` are interpolated into unquoted Python heredocs (`<<PY`). A value containing a single quote breaks the Python code.

**Verified:** `collect-payloads.sh` uses `<<PY` (unquoted) with `Path("$DB")` and `Path("$OUT/...")`. `apply-stealth.sh` uses `<<PY` with `Path("${COWRIE_HOME}")`.

---

#### L28. TOCTOU Race on `/tmp/shardlure` (vps-finish.sh Only)
**File:** `scripts/vps-finish.sh:56,109`

Builds to `/tmp/shardlure` then copies to `$BIN_DIR`. The bash wrapper and Python installer are fixed, but `vps-finish.sh` still uses the predictable `/tmp` path.

**Verified:** `go build -o /tmp/shardlure ./cmd/shardlure` (line 56) and `shutil.copy2("/tmp/shardlure", BIN)` (line 109).

---

#### L30. `restore_sshd` Uncomments First `#Port` Line
**File:** `scripts/shardlure.py:774-778`

Restores the first `#Port ` line in `sshd_config`. If the user had an original `#Port 22` comment before ShardLure, it gets uncommented during uninstall. The `not restored` guard prevents mass uncommenting, but the first-match heuristic can still pick the wrong line.

**Verified:** `if not restored and line.startswith("#Port "): out.append(line[1:])`

---

## Summary

| Severity | v1 | v2 | v3 | v4 |
|----------|----|----|-----|-----|
| 🔴 HIGH  | 9  | 3  | 0   | **0** |
| 🟡 MEDIUM| 20 | 9  | 3   | **0** |
| 🟢 LOW   | 21 | 22 | 22  | **14** |
| **Total**| 50 | 34 | 25  | **14** |

---

## Priority Recommendations

| Priority | Action | Addresses |
|----------|--------|-----------|
| **P2** | Add `IdleTimeout` to HTTP server — already done, verify in prod | ~~L20~~ |
| **P2** | De-duplicate family indicator strings in `classify.go` | L12 |
| **P2** | De-duplicate NUL-byte repair scripts into a shared helper | L16 |
| **P3** | Extract tailscale URL printing to a shared helper | L1 |
| **P3** | Add CLI test coverage for argument parsing | L17 |
| **P3** | Cache `AdminSet.Key()` to avoid per-event recomputation | L7 |
| **P3** | Log or return `parseTime` errors instead of silently zeroing | L21 |
