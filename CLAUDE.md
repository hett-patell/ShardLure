# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

ShardLure derives **attacker identity** from SSH honeypot telemetry. It wraps the [Cowrie](https://github.com/cowrie/cowrie) SSH honeypot (a separate Python process), ingests Cowrie's JSON log + journald sshd lines, clusters attackers into **actors**, enriches their IPs against threat-intel feeds, and serves a live dashboard + forensic TUI. It also shares findings back out (MalwareBazaar payloads, AbuseIPDB reports, STIX IOCs).

Single Go module: `github.com/networkshard/shardlure` (Go 1.22). One binary, subcommand-dispatched from `cmd/shardlure/main.go`.

## Commands

```bash
make build          # go mod tidy && go build -o shardlure ./cmd/shardlure
make test           # go test ./...
go test ./internal/store/ -run TestName   # single package / single test
go vet ./...        # CI runs this; keep it clean
```

CI (`.github/workflows/ci.yml`) runs on push to `main`, tags `v*`, and all PRs: `check-utf8.sh` → `go mod verify` → `go vet` → `go test -coverprofile` → build → `version` smoke → `ci-web-smoke.sh` (boots the web server and checks it serves). Then a cross-build job. There is **no separate lint step** beyond `go vet`; do not add one without asking.

Run locally after building:
```bash
./shardlure ingest journal testdata/sample.journal --replace   # see make run-sample
./shardlure ingest cowrie <cowrie.json> --replace
./shardlure actors [--limit=N]
./shardlure actor show <ip|actor-id>
./shardlure web :8080 [--tailscale]        # dashboard only, static DB
./shardlure live :8080 --cowrie=<path>     # live ingest loop + dashboard (the real daemon)
./shardlure dashboard                       # forensic TUI (tui/app.go, bubbletea)
```

## Deploy workflow — the two non-obvious gotchas

1. **Never `scp` Go/Python sources to the VPS — it silently corrupts them to UTF-16.** Use `make deploy` (`scripts/push-sources.sh`, tar-over-SSH). CI enforces this with `scripts/check-utf8.sh`, which fails the build on any tracked file with a UTF-16 BOM or NUL bytes. If sources arrive mangled, `scripts/fix-go-sources.sh` / `scripts/repair-text.sh` repair them. This is why the check exists — respect it.

2. **Two independent installers, with inverted port defaults.** `scripts/install.sh` downloads a prebuilt release binary (no Go toolchain). `scripts/shardlure.py run` is the richer VPS wrapper: installs Go, *builds* from source, and does the interactive real-SSH-port migration. Their honeypot/admin port defaults are swapped — `shardlure.py` puts the honeypot on **22** and moves real sshd to **2222** (key-only); `install.sh` keeps admin on 22 and the honeypot on 2222. `sudo ./shardlure run` execs into `scripts/shardlure.py run`.

## Architecture

Data flows in one direction, and `pkg/models` (`Event`, `Actor`, `AggregatedActor`, `IPStat`, the `Kind*`/`Source*` consts) is the shared vocabulary that lets `store` and `actor` avoid an import cycle:

```
Cowrie :22 → cowrie.json ─┐
                          ├→ ingest → []Event → cluster → Actor → SQLite → web :8080 / TUI
journald sshd  ───────────┘                                          ├→ enrich (inbound IP rep)
                                                                      └→ share/report (outbound intel)
```

The Go binary and the Cowrie process are **separate systemd units with no IPC** — the only contract between them is the JSON log file on disk (`$DATA_DIR/cowrie/var/log/cowrie/cowrie.json`). `shardlure-live.service` `Wants=cowrie.service`.

### The live daemon is the conductor (`cmd/shardlure/main.go` `cmdLive`)
Seeds history, then runs **three background goroutines** + the web server (main goroutine), all sharing one `*store.Store` and one `*settings.Keystore`, shut down via `signal.NotifyContext`:
1. **journal tail** — `journal.TailFollow` in a capped-backoff restart loop (journalctl -f never self-exits; a scanner error would otherwise silently kill ingest for the process lifetime).
2. **cowrie ticker** (5s) — `cowrie.IngestFileAppend` + `capture.Runner.Run`.
3. **purge ticker** (24h + once at startup) — `store.MaintenancePurge` + `PurgeOldSourceFiles`.

### Ingest (`internal/ingest/{cowrie,journal}`)
Both sources: parse text → `[]*models.Event` → assign actor IDs → persist. Two modes per source: full-replace (`IngestFile`, `--replace`) and incremental append (dedup-based, used live).

- **Incremental Cowrie ingest is genuinely O(new bytes)**, not O(file size). `IngestFileAppend` persists `IngestState{Inode, Offset, HeadSig}` and seeks to the offset. Rotation is detected three ways: inode change, size < offset (truncate), and a sha256 of the first 512 bytes (catches copytruncate — same inode, replaced content). Offset advances by bytes *actually consumed*, never `fi.Size()` (Cowrie may append mid-Stat). Uses a bounded line reader (not `bufio.Scanner`) so one >2MB attacker line is skipped-but-consumed rather than wedging ingest forever.
- **HASSH stamping is essential** (`stampHASSH`, `persistBindings`): Cowrie emits the HASSH fingerprint only on `cowrie.client.kex`, which isn't a persisted event. Ingest extracts session→hassh bindings as a side channel and back-fills `e.HASSH` onto each session's real events. Without this, every Cowrie actor would cluster by IP, defeating the fingerprint premise.
- Shared dedup (`store/events_dedup.go` `IterateEventIdentitiesByTS`) has a load-bearing SQLite-planner workaround: it filters `WHERE ts IN (...)` only and re-applies the `source` filter in Go, because *any* `source=` predicate makes the planner do a full-source scan. Don't "simplify" it back into SQL.

### Actor model (`internal/actor`)
An actor is a **clustered attacker identity, not one-per-IP**:
- `journal:<src_ip>` — clustered by IP (their attempted-username distribution is their personality).
- `cowrie:<hassh>` — clustered by HASSH (one HASSH across 3 IPs = one actor); falls back to `cowrie:<src_ip>` when HASSH is absent.
- **Admin IPs are excluded from all clustering** (`AdminSet` → `netmatch.Set`, accepts IPs + CIDR like Tailscale `100.64.0.0/10`) so you don't classify yourself as an attacker.
- `playbook.go` labels behavior (`fast_dictionary_spray`, `crypto_target`, etc.) from username taste × attempt rate; `ProbeScore` (0–100) and `Confidence` (fixed tiers) feed dashboard sort + report vetting.

### Store (`internal/store`, largest package — SQLite via `modernc.org/sqlite`)
- **Writes are serialized at the app layer by a single `writeMu`** (`WithTx`/`execWrite`), *not* by a 1-connection pool. The pool is 8 connections in WAL mode so reads stay parallel with the single writer. Every write goroutine (journal tail, cowrie ticker, purge, web) goes through `writeMu`. The DB file is chmod 0600 (it holds attacker passwords).
- **Migrations** are a linear ladder v1→v15 in `sqlite.go`, each guarded `if current < N` and stamped `INSERT OR IGNORE` into `schema_migrations`. A base `CREATE TABLE IF NOT EXISTS` block runs first (fresh DBs get everything, ladder is near-no-op); old DBs get `ALTER TABLE ADD COLUMN` backfills. **Most migrations are index tuning driven by EXPLAIN QUERY PLAN** — read the comments before touching them (e.g. v9 *drops* a write-amplifying index; v10 replaces `idx_events_actor` with composite `(actor_id, ts)`). To add schema: append the next version to the ladder, don't renumber.
- Lazy tables (artifacts, ip_enrichment, bazaar_uploads, session_hassh, abuseipdb_reports…) are each created on first use via a `sync.Once` to avoid DDL under `writeMu` on hot calls. When batching writes across several of these in one `WithTx`, call the `ensure*` helpers **before** opening the transaction — they take `writeMu` via `execWrite`, and `writeMu` is not reentrant, so ensuring inside the tx deadlocks (see `RecordSessionBindings`).
- `MaintenancePurge(retentionDays)` deletes events in **5000-row chunks, each its own transaction**, releasing `writeMu` between chunks so a first purge of an aged DB doesn't stall ingest for minutes; then unlinks the corresponding evidence files and runs `PRAGMA optimize` (also run once at `Open` after migrate) so the plan-sensitive queries keep their intended index plans as cardinality shifts.
- **Windowed reads for the UI are bounded.** `EventsSinceCapped(since, limit)` returns at most `limit` (default `defaultWindowEventCap`) newest-first events **plus the true window total**, so callers disclose "N of M" instead of materializing a whole 30d window into RAM. `EventsSinceAll` (uncapped) still exists for non-UI use but shouldn't be reached from a poll path — prefer the capped form.

### Enrichment (`internal/intel/enrich`) — inbound IP reputation
Seven providers (AbuseIPDB, VirusTotal, GreyNoise, Shodan, AlienVault OTX, IPQualityScore, IPinfo; GreyNoise + Shodan work keyless). Each is a `providerSpec{envVar, buildReq, parse, …}` — **adding provider #8 is one file + one row in the `providers` slice.** `LookupAll` gates every IP through `safeForEnrichment` (rejects private/reserved — SSRF defense) then fans out 7 goroutines into fixed slice indices (stable order), each with a 6s timeout. Cache-then-fetch with 24h TTL; only caches `Configured && Error==""` results so adding a key takes effect immediately.

### Outbound intel (`internal/intel/{bazaar,abuseipdb,ioc}`) — the vetting-gate pattern
Each has a single `Vet`/`vet.go` function that **both the CLI and the dashboard call** — policy lives in exactly one place, and **hard-rejects always win over accept signals**. Candidate structs deliberately omit any host/session identifier so nothing leaks to third parties.
- `bazaar` — uploads confirmed-malware payloads to MalwareBazaar; `Vet` enforces abuse.ch policy (no tty transcripts, no SSH keys, ≤10 days old, confirmed-malware OR fetched-during-attacker-session).
- `abuseipdb` — reports confirmed brute-forcers; `Vet` requires `_spray`/`_enum` playbook AND ProbeScore ≥ floor AND ≥20 events AND ≥3 users, excludes admin/private IPs (account-strike defense).
- `ioc` — emits **byte-stable** STIX 2.1 (deterministic UUIDv5 IDs) so re-exports diff cleanly.

### Settings keystore (`internal/settings/keystore.go`)
Leaf package (imports only `store` + stdlib). Precedence on read: **DB value → env var (`SHARDLURE_*` only) → ""**. API keys and knobs (`ui.theme`, `abuseipdb.*`, `home.*`) live in the `app_settings` table, read **live at request time**, so a dashboard Settings save takes effect **without restart**. `main.go` seeds it from config/env at startup so existing systemd deployments are unaffected.

### Capture (`internal/capture`)
Every 5s: extracts URLs from recent commands and quarantine-fetches them, syncs Cowrie's downloads + ttylogs into `evidence/{quarantine,cowrie,cowrie-tty,meta}` (0700/0600). **`SafeFetcher` is SSRF-hardened**: `safeDial` re-resolves DNS and validates the actual IP *at dial time* (closes the resolve→connect TOCTOU / DNS-rebinding hole), size-caps downloads, and **never executes content**. Dedup memos skip the copy+hash *before* the dedup query to avoid GB/min write amplification.

## Web layer (`internal/web`)

- Assets are `go:embed`ed (`embed.go`): `index.html` + `intel.html` (two dashboards), `themes.css`, `cobe-globe.js`/`cobe-boot.js`, `vendor/vis-network.min.js`, and `stickers/*.svg`. HTML is served behind auth; static JS/CSS/stickers are unauthenticated.
- **Two dashboards:** `index.html` = the globe view (polls `/api/dashboard`); `intel.html` = the tabbed analyst console (Overview/Blue/Red/Settings, full `/api/intel/*` surface).
- **Auth is bimodal** around `SHARDLURE_DASH_TOKEN` (read live via the keystore, `crypto/subtle` compare): `/api/*` and `/debug/*` are **header-only** (`guard` → `Authorization: Bearer`); the two *page* routes accept `?token=` in the query too (a browser nav can't set a header — the page then stashes the token and uses the header for all API calls; `fetch` is monkey-patched to inject it). Startup **refuses to bind** if the token is empty AND the listen addr is a public routable IP; otherwise open (designed for Tailscale/loopback).
- **Dashboard query caching lives here, not in `store`** — and it exists for a reason (comments document prior OOM/IO): `summaryStatsCached` (10s TTL) memoizes all whole-table aggregates; `dashExtraCachedValues` (10s TTL) memoizes the two remaining full-window scans `/api/dashboard` used to run uncached (`HourlyEventCounts(72)` + `RecentShellSessions`); `eventsForWindowCached` (15s TTL, per-window, single-flight) memoizes the *bounded* windowed event slice shared by mitre/ttp/deobf/graph/wordlist/ioc — it returns `(events, total, err)`, and every intel handler calls `discloseWindowTruncation(w, len(events), total)` to set an advisory `X-ShardLure-Window-Truncated: returned/total` header when the cap bit; `countriesCached` (10s). Don't remove these without understanding the poll-storm they prevent (N widgets × full scan every 5s).
- **Themes: 3 implemented** — `signal` (default; supports `data-mode="dark|light"`), `meridian`, `sprite`. `themes.css` defines exactly those and `validateSetting` hard-rejects anything else. Persisted as keystore `ui.theme` (+ `ui.mode` for Signal), server > localStorage, synced across tabs via `BroadcastChannel`. **One globe engine (Cobe)** for all themes — globe.gl and the Dragon theme were removed in v2.0.0.

## Performance

The README's four perf claims (incremental ingest, batched writes, dashboard query caching, actors indexes) are all **real and correctly implemented**.

**Fixed 2026-07 (a further perf pass — do not re-introduce the old behavior):**
- **Bounded windowed reads.** `EventsSinceAll` used to be `SELECT … WHERE ts >= ?` with no LIMIT, and `eventsForWindowCached` pinned the whole slice in RAM — a 30d wordlist poll on a multi-million-row DB was a full scan + hundreds-of-MB allocation. Now `EventsSinceCapped` bounds the fetch (`defaultWindowEventCap`) while reporting the true total, and handlers disclose truncation via the `X-ShardLure-Window-Truncated` header. Don't route a poll path back through uncapped `EventsSinceAll`.
- **The 5s landing path is fully cached.** `HourlyEventCounts(72)` and `RecentShellSessions` no longer run uncached on every `/api/dashboard` poll — they're behind `dashExtraCachedValues` (see Web layer).
- **Planner stats + pool tuning.** `PRAGMA optimize` runs at `Open` and each purge; `SetMaxIdleConns(8)` + `ConnMaxLifetime(1h)` stop pool churn.
- **Batched side-channel writes.** Per-tick session bindings (hassh/duration/arch/tty) commit in one `RecordSessionBindings` transaction instead of N separate `writeMu` acquisitions ahead of the event insert.

**Known remaining (LOW, intentional):** `HourlyEventCounts`/`…ByKind` group on `substr(ts,1,13)` and `DistinctGeoCountryCount` does `COUNT(DISTINCT json_extract(...))` — neither can use an index for the *aggregation*, but the `ts >= ?` restriction is index-served and both are now well-cached, so leaving them avoids risking the working plan. Don't "optimize" these into a form that drops the `ts` index restriction.

## Conventions observed in this codebase

- Unknown CLI flags are **fatal, not ignored** (a typo like `--repalce` silently appending was a real bug — see `cmdIngest`). Match that: validate flags, don't swallow.
- Comments here explain *why*, often citing the bug a line prevents. When changing such code, preserve or update the rationale — several guards look removable but aren't (the dedup `source`-in-Go filter, the offset-by-consumed-bytes, the `writeMu`-not-1-conn choice).
- Interfaces decouple `intel/*` from `store` (`UploadRecorder`, `ReportRecorder`, `KeyLookup`) — keep intel packages free of a direct `store` import.
- Secrets are never logged or returned raw; the settings API masks them (`maskSecret`) and reports only a db/env/unset source badge.
