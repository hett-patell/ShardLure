# Reliability hardening progress

Updated 2026-09-18. Work is uncommitted in .worktrees/fix-reliability, branch
fix/reliability, base 552dcf9. Main checkout and ARM deployment are unchanged.
No outbound intelligence submissions or real payload fetches.

## Implemented (not a declaration of overall completion)

- Capture v19 observation/fetch timestamps, successful-fetch freshness, fenced
  leases, attempt budget/backoff, exhaustion recovery, observation-only touch.
- Durable ID-cursor command discovery; queue/cursor commit atomically. Tests
  cover multi-page bursts, reopen, late timestamps and rollback.
- Atomic late HASSH event/actor reconciliation preserving lifetime aggregates;
  bounded historical blank-HASSH repair. Errors stop ingest offset advancement.
- Source-appropriate journal dedup and durable post-dedup username increments
  independent of the bounded memory cache.
- Safe legacy optional NULL decoding and Cowrie flag repair without replacing
  lifetime counts with retained-event counts.
- CLI/web reports qualify target-IP/source evidence in the reporting window.
- API bootstrap cookies, exact-origin cookie writes, API query-token rejection;
  Tailscale resolves an actual CGNAT listen address, never wildcard fallback.
- Request admission/drain and live-worker joins before store close (audit below).
- Python SSH migration: firewall check, dual listeners, public-key verification,
  then final policy; exact rollback on failure/abort, reinstall policy preserved.
  Socket restarts require safe KillMode and restart socket/service together.
- Both installers: dedicated daemon account, restrictive ownership/modes,
  sandboxed units, private dashboard binding. Explicit Cowrie umask and narrow
  group access for reading evidence and unlinking retained downloads/tty files.
- Capture diagnostics no longer retain raw URL/transport/body/filesystem error
  text. Permanent 4xx except 408/425/429 are terminal; partial responses invalid.
  Context-aware DNS, preserved redirect SSRF status, URL digests in worker logs,
  and cancelled ticks do not claim work.
- Generic artifact upsert cannot overwrite capture state, successful-fetch
  provenance or leases. Populated v18 migration/reopen coverage uses exact Go
  timestamp parsing and preserves unknown provenance as NULL.
- Single-SHA Bazaar sharing selects qualifying fetched evidence rather than
  the newest failed/TTY observation (shared CLI/dashboard store selector).
- Report source selection uses shared Vet/priority, one independent source per
  target IP. CLI no longer prefilters by cluster score, duplicates sources, or
  ranks by lifetime activity. Dashboard single/batch/suggestions use the same
  selection and never sum journal and Cowrie counts.
- Reporting classification/counts use seven-day target evidence; displayed and
  submitted rate is the exact fixed 24h rate, including zero for dormant bursts.
- Reporting scans use request cancellation and release connections promptly.
  Advisory evidence is cached for 10s with a 1024-entry LRU bound, one in-flight
  scan, cancellable waiters and no stale success on refresh errors. Cached raw
  evidence is re-vetted against live settings; report POSTs always query fresh.
- Username-grouped evidence scans use constant-size Go classification counters
  and a streaming hash instead of retaining every distinct username. The shared
  playbook classifier preserves exact corpus ratios; SQLite may spill sort work
  to disk. A 24,004-event/12,002-user test covers late rare signals and dedup.
- AbuseIPDB single/batch paths share per-target dedup gates and process-wide,
  cancellable pacing. Target gates release exactly once on success, provider,
  ledger, rate-limit, and cancellation paths. Durable success is reported only
  after the ledger write succeeds.
- URLhaus, ThreatFox, and MalwareBazaar now fail-stop on ledger-write failure,
  pace every request including after 429/5xx, reject responses one byte over
  their caps, and preserve sanitized errors. ThreatFox validates exactly one
  response IOC matching the submitted value and reports partial counts exactly.
- Schema v20 adds exact event epoch nanoseconds without rewriting events during
  Open. New writes use one canonical fixed-width UTC representation; web/live
  backfill legacy events in bounded, resumable transactions. Window, source,
  actor, session, reporting-rate, latest-event, and retention paths compare
  parsed instants with deterministic ID ties and reject malformed timestamps.
- v19 artifact migration is schema-only at Open. A bounded resumable worker
  repairs legacy provenance and quarantines malformed retry/lease schedules.
- Retention selects exact event/artifact/cache/session/actor instants, preserves
  reference-safe evidence unlinking and chunked event deletes, and fails closed
  on malformed timestamps.
- Geo HTTP prefetch propagates its budget context and joins workers before the
  handler returns, so shutdown cannot close MMDB/store resources under a worker.

## Verification evidence

- Current checkpoint: `go test ./... -count=1` PASS on the exact tree after
  the v20, session, retention, provider and geo changes (store 83.625s, web
  23.689s). Canonical event dedup and provider/geo timing regressions also pass
  targeted repeated tests.
- Current: focused reporting race tests PASS in actor/store/AbuseIPDB/web/CLI;
  covers cache expiry/eviction/live-policy, cancellation, POST revalidation,
  source selection, duplicate IPs, recent rate and large username corpus.
- Current: go vet ./..., go mod verify, git diff --check, tracked UTF-8 check,
  native build/version smoke, Linux ARM64 cross-build and web smoke PASS.
  Web smoke required a localhost socket outside the restricted sandbox.
- Current: all 83 Python installer/release tests PASS (mocked/local fixtures).
- Previous continuation: full capture race tests PASS, plus focused Cowrie and
  journal race tests. Full repository race run is now in progress.
- Mocked no-Cowrie shell unit passes systemd-analyze verify. No live installer,
  Ubuntu SSH or real service mount-namespace integration exercised.

## Remaining work and review risks

1. Capture: queue-vs-retention backlog and capped archive download discovery.
2. Timestamp compatibility remains in SQL-only dashboard/credential aggregates
   and Bazaar/URLhaus/ThreatFox ledger list/stat ordering. Merge v20 indexed
   aggregates with bounded legacy fallbacks; do not regress window memory caps.
3. Reports: CLI signal cancellation and cache refresh-error retry storms remain.
4. Username overflow classification/hash/notes, hydration bound, historical
   counters and preserving operator annotations.
5. Lifecycle: startup signals, proxy auth behavior and documentation remain.
6. Installer: custom paths/escaping, ownership races, existing user/service
   conflicts, root CLI WAL ownership, uninstall SSH rollback, per-user Match
   policy, actual Ubuntu integration.
7. Backup/restore and readiness/metrics not implemented. Need consistent online
   snapshot, manifest/checksums/restore verification and bounded operational data.
8. Provider accounting/protocol fixes are implemented; review remaining
   dashboard log sites for local-path or endpoint disclosure.
9. README/operator guidance; finish full Go/vet/race verification and review.
   No merge/deploy without authority.

Preserve the dedup WHERE-ts-only planner invariant, ensure-before-transaction
ordering, lifetime aggregates and fail-closed Vet/admin/SSRF exclusions. Earlier
subagent attempts failed through provider adapters; a read-only reporting
review was requested again this continuation (result pending).
