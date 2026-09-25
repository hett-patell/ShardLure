# ShardLure Reliability Hardening Implementation Plan

> For agentic workers: use the subagent-driven-development or executing-plans skill to implement this plan task-by-task.

**Goal:** Correct the persisted identity, evidence, reporting, authentication, capture, and deployment defects found during the deep inspection.

**Architecture:** Preserve the Go single binary, SQLite/WAL store, Cowrie file contract, shared Vet gates, and embedded UI. Use append-only migrations and bounded workers; never reset production history.

**Tech Stack:** Go 1.27, modernc.org/sqlite, net/http, SQLite migrations, systemd, Python installer tests.

**Spec:** The user request to fix all findings from the preceding ShardLure assessment.

## Global Constraints

- Preserve SQLite/WAL and existing lifetime-aggregate semantics.
- Migrations are append-only and non-destructive.
- Tests use local fakes; do not submit intelligence or fetch real malicious payloads.
- Reports qualify the actual target IP; cluster data is context only.
- Preserve admin-IP, private-address, SSRF, retention, and fail-closed Vet behavior.

---

### Task 1: Canonical HASSH reconciliation

Files: internal/ingest/cowrie/ingest.go, internal/store/transaction.go, internal/store/sqlite.go, relevant tests.

- [ ] Add a two-session late-HASSH regression test asserting one actor, two events, and persisted HASSH values.
- [ ] Make event HASSH and actor ID canonicalized atomically and idempotently.
- [ ] Add a bounded forward migration/repair for already-reconciled rows where a session binding is known.
- [ ] Run Cowrie/store tests and race tests.

### Task 2: Evidence timestamps and capture status

Files: internal/store/artifacts.go, internal/store/sqlite.go, internal/capture/{runner,worker}.go, URLhaus/ThreatFox/share paths, tests.

- [ ] Add immutable first-observed, last-seen, last-fetch-attempt, and last-successful-fetch timestamps.
- [ ] Prove Touch/redelivery cannot refresh fetch eligibility.
- [ ] Define fetched, empty, invalid, transient-failure, and permanent-failure semantics.
- [ ] Use successful fetch time for outbound candidate freshness.

### Task 3: Per-IP report qualification

Files: internal/web/report_candidate.go, cmd/shardlure/report.go, shared store evidence helpers, tests.

- [ ] Add a regression where cluster thresholds pass but the primary IP fails.
- [ ] Compute event, username, playbook, score, and LastSeen evidence for the same target IP/window.
- [ ] Share the helper between CLI and dashboard; apply limits after Vet/dedup.

### Task 4: Username overflow, journal dedup, and timestamps

Files: internal/actor/sync.go, internal/store/sqlite.go, journal ingest/identity code, event queries, migration tests.

- [ ] Prevent bounded overflow state from being written as an exact username count.
- [ ] Unify batch/live journal identity and preserve same-second parallel attempts.
- [ ] Add mixed-precision timestamp ordering tests and implement compatible ordering.
- [ ] Add populated legacy NULL migration/read tests and safe decoding.

### Task 5: Durable capture queue and fenced leases

Files: internal/capture/{runner,worker}.go, internal/store/artifacts.go and migrations, cmd/shardlure/main.go, tests.

- [ ] Add concurrent-claim, lease-expiry, stale-completion, terminal-state, and backoff tests.
- [ ] Ensure ingestion enqueues work without network I/O.
- [ ] Use atomic leases/fencing tokens and bounded global/per-host worker concurrency.

### Task 6: Authentication and shutdown

Files: internal/web/server.go, embedded pages, web tests, cmd/shardlure/main.go.

- [ ] Add fresh-client token bootstrap/API/expiry and CSRF tests.
- [ ] Make page and API use one coherent secure session flow.
- [ ] Wait for handlers and workers before closing shared store/MMDB resources.

### Task 7: Deployment, installer, backup, and observability

Files: service templates, scripts/install.sh, scripts/shardlure.py, config/main, tests/docs.

- [ ] Run ShardLure as a dedicated unprivileged user with systemd filesystem/capability restrictions.
- [ ] Make private/Tailscale binding fail closed and preserve installer rollback/access order.
- [ ] Add SQLite-consistent online backup/restore verification covering DB, evidence, settings, and ledgers.
- [ ] Add health/readiness and bounded metrics for ingest, capture, SQLite, evidence disk, and provider outcomes.
- [ ] Sanitize external HTTP errors and run full verification.
