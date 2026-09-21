# ShardLure v2.8.0 reliability completion design

Date: September 21, 2026.

Status: high-level design approved in conversation; this detailed specification
awaits written-spec review. Implementation and release completion are not claimed.

Baseline: `fix/reliability` at `e0bbe7b0bf6a3c64ce862bb9fe4ee4a46a79bc7d`.
Target: `v2.8.0`, including the new operational tooling rather than deferring it
into a later release.

## 1. Intent and completion boundary

Complete the remaining reliability work so an operator can collect, investigate,
back up, verify, and recover honeypot evidence without silently losing records or
weakening reporting/authentication policy. Then prepare a tested merge/release
and update the repository documentation and public Wiki to the released behavior.

The approved design is additive: retain the Go binary, SQLite/WAL store, Cowrie
file contract, embedded dashboards, and shared outbound Vet gates. New backup,
restore, and operational endpoints belong in the existing application, not an
additional service or external database.

This supersedes the unfinished portions of the
[original implementation plan](../plans/2026-09-08-reliability-hardening.md).
The [progress record](../plans/reliability-progress.md) and
[nine-finding remediation](../plans/2026-09-21-review-remediation.md) remain
historical evidence, not interchangeable declarations of overall completion.

### Required invariants

- Never reset production history, remove historical duplicates speculatively,
  fabricate lost provenance, or use ingestion `--replace` as an upgrade step.
- Preserve existing records, settings, annotations, and submission ledgers.
- Migrations are additive, resumable where necessary, and versioned after v21.
  Do not change an already-shipped migration's meaning.
- Preserve fail-closed admin-IP, private-address, SSRF, authentication, origin,
  eligibility, freshness, lease, and deduplication controls.
- Keep writer transactions, materialized query results, queues in memory,
  diagnostics, and metric-label sets bounded.
- Tests use inert evidence and local provider fixtures. No real public intel
  submission, malware execution, or attacker-URL fetching is a test prerequisite.
- Development, restore tests, SSH migration tests, and installer tests do not run
  against the active ARM collection or the developer host's administrative SSH.
- Backup/restore and release procedures do not automatically delete old backups,
  source evidence, or incomplete recovery output. Existing operator-configured
  retention remains explicit and is additionally constrained by pending-work
  protection; this is not a blanket removal of the retention feature.

### Non-goals

No dashboard redesign, new intelligence provider, fleet coordinator, WebSocket
feed, cloud backup destination, encrypted archive format, scheduled backup
service, or in-place automated production restore. A data backup is not a full
VM image or a replacement for an administrative SSH recovery plan.

## 2. Findings and evidence status

| Area | Baseline evidence | Completion requirement |
| --- | --- | --- |
| Timestamp consumers | Credential/dashboard aggregates still compare timestamp text; ledger lists/statistics still order or MAX variable-width text. Controlled SQL reproductions omit two valid cutoff events and choose an older ledger entry as newest. | Reproduce through the actual store methods, then correct every affected consumer without losing indexed/bounded reads. |
| Capture completeness | File-download archiving repeatedly asks for the newest 200 events rather than using a durable discovery cursor. | Durable catch-up, recoverable file work, and retention coordination. |
| Journal summaries | The resident username map is capped after hydration; classification/hash/notes still consume it. Actor upsert replaces annotation fields. | Exact durable semantics, bounded hydration, and annotation-preserving updates. |
| Startup/authentication | Live signal context is established after seeding/initial capture; origin checks use the direct HTTP connection. | Cancellable startup and an explicit, narrow reverse-proxy origin contract. |
| Installation | Remaining risks include path quoting, account/ownership conflicts, WAL ownership, Match policy, and uninstall rollback. | Confirm individual failures and add real isolated service/SSH integration coverage. |
| Operations | There are manual backup instructions and runtime diagnostics, but no built-in verified backup/restore or dedicated readiness/metrics contract. | Implement the contracts below. |
| Documentation/release | Some checklist and authentication guidance is stale; the Wiki labels the baseline unreleased. | Reconcile completed/open work and publish documentation matching the actual tagged release. |

CLI signal cancellation and report-evidence error-cache backoff already exist.
Retain and regression-test them; do not reimplement them based on stale checklist
entries. Code-inspection risks above require focused reproduction before being
reported as confirmed product defects.

## 3. Component boundaries

| Component | Responsibility |
| --- | --- |
| `internal/store` | Exact time queries, durable capture work/checkpoints, atomic actor state, retention safety, non-migrating snapshot access, bounded operational queries. |
| `internal/capture` | Discovery and processing of file/URL work; safe file publication, retry/fencing, and source-file retention coordination. |
| `internal/actor` | Bounded live state, exact derived classification, and preservation of operator-owned fields. |
| New `internal/backup` | Bundle creation/verification/restore, manifests, checksum/file validation, safe staging and publication. |
| New `internal/observability` | Fixed-cardinality process counters, worker state, health snapshots, and sampling. No dependency on the web package. |
| `internal/web` | Operational HTTP routes and authorization; configured external-origin handling; existing dashboard behavior. |
| `cmd/shardlure` | Dispatch, deadlines/signals, startup/readiness transitions, configuration, and CLI exit behavior. |
| Installer scripts | Safe identity/path handling, atomic configuration writes, SSH access preservation, and reversible transitions. |

Keep these responsibilities in focused files. Do not put all new functionality
into `main.go`, `server.go`, or `sqlite.go`. Preserve existing interfaces that keep
`intel/*` independent of the store; optional observability hooks must not create
an import cycle or make provider tests require a running web server.

## 4. Timestamp correctness

Use the existing migrated/legacy event-query split as the foundation for the
remaining credential, dashboard, hourly, activity, tunnel, and capture readers.
Compare parsed instants and apply deterministic ties where a list requires them.
Normalize hourly buckets to UTC, including historical timestamps with offsets.

For migrated events, preserve selective indexes and canonical fixed-width time
keys. For legacy events, use exact parsing over the relevant bounded/scoped
population. Do not replace indexed LIMIT/count queries with a full-window Go
slice, a millisecond bucket, or an unconditional full-history scalar scan.

Submission ledgers need equivalent semantics for latest time, ordering, and any
cutoff. New writes use a canonical representation. Existing rows remain readable
without a destructive rewrite; any normalization is bounded and resumable.
Bad timestamps must not become fabricated zero-time successes, silently disappear
from exact counts, or leak raw input through a public error.

Acceptance includes whole-second and fractional boundaries, all supported
fraction widths, equivalent offsets, nanosecond ties, pre/post-backfill reads,
malformed values, empty windows, SQL query plans, and allocation bounds. Tests
must call the actual affected store/API methods, not only restate SQL in a second
language. The observed expected-two/actual-zero case becomes a regression.

## 5. Durable capture completeness and retention

Replace the newest-200 file-download scan with bounded primary-key discovery and
a durable checkpoint. A discovery transaction records enough work/provenance to
resume processing and advances the checkpoint together. File copying and network
requests occur outside that transaction and outside the ingestion transaction.

Each applicable source event must end in one of three durable outcomes:

1. A queued unit of work containing the necessary source/session/actor metadata.
2. An idempotently recognized existing result without falsifying its provenance.
3. An explicit terminal rejection/failure with a bounded reason code.

File work has bounded retries and fenced leases. A missing source file can be
retried when appropriate; it cannot be silently counted as archived. Malformed
events must be diagnosed without permanently blocking later discovery pages.
Do not reset an existing quarantine-fetch lease or invent successful-fetch
freshness when the same URL also appears in a Cowrie download event.

Resolve source files inside the configured download roots, never from an
attacker-supplied absolute path. Publish completed evidence through a temporary
file and atomic finalization. Verify the bytes/hash before marking work complete.
After a crash between file publication and ledger commit, replay verifies and
records the existing file rather than duplicating work or deleting it.

### Retention contract

- When capture is enabled, retention must not delete an event still required by
  an active discovery checkpoint before its work/provenance is durable.
- Queued or leased file work protects the source bytes it still needs. Source
  deletion must coordinate with this state, not merely use file mtime.
- Once work is terminal, ordinary retention/reference rules apply. A terminal
  failure remains distinguishable from successful archival.
- Disabling capture does not promise discovery of all future events after they
  age out; document that explicitly. Already-queued work remains recoverable and
  protected while paused rather than being silently discarded.
- Expose backlog/retention-hold state so an operator can see why disk usage is
  growing. Do not solve a stalled consumer by deleting its required input.

Acceptance includes more than 200 downloads between ticks, discovery behind a
large history, late timestamps, rotation, missing/late files, cancellation,
restart, transaction rollback, stale workers, simultaneous retention, duplicate
URLs/hashes, and bounded memory. Existing capture-lease regressions remain green.

## 6. Journal state and annotations

The bounded username cache is an optimization, never the authoritative corpus.
Use durable per-username state and bounded streaming/aggregate computation to
derive exact distinct counts, hashes, classifier inputs, and generated summaries.
Avoid loading an unbounded map first and only then trimming it on hydration.
Retain the existing post-dedup atomic username increments.

Preserve `campaigns` and other operator-owned annotations across live ingestion,
batch append, reconciliation, and reclassification. Separate generated summary
text from preserved annotations. Do not guess that arbitrary legacy `notes` text
is disposable; retain it conservatively and use an additive derived-summary
field where needed. Existing API annotation fields keep their meaning.

Historical repairs may use authoritative complete evidence when available, but
must not replace lifetime totals with a retained-window subtotal. When historical
coverage is insufficient, retain the existing data and surface uncertainty rather
than inventing an exact repaired count or hash.

Acceptance covers usernames first observed after the cache cap, eviction/reopen,
large hydration, late rare classification signals, duplicate events, retained
versus lifetime history, and annotations surviving every writer path.

## 7. Startup, shutdown, and reverse-proxy authentication

Establish signal cancellation before blocking startup work. Thread it through
seeding, subprocesses, backfills, capture startup, waits, and server shutdown.
Resource ownership remains explicit: stop admission, cancel producers, join
handlers/workers, and only then close the store and MMDB.

After configuration, store initialization, and authentication/bind validation,
start the HTTP listener before long history seeding. Readiness remains false
until initial collection setup succeeds. This does not claim that the HTTP
listener is available before configuration or schema initialization completes.
Startup cancellation must not result in an implicit retry or a success marker.
During initial seeding, ordinary application routes return a retryable `503`;
operational routes remain available through their normal security guard. In
`web` mode, readiness does not require live-ingestion workers that do not exist.
Bounded background backfills need not finish before readiness when their worker
is operational; readiness is not a claim that every historical repair is complete.

### Explicit external-origin configuration

Add `dashboard.public_origin` and `dashboard.trusted_proxies` as startup options,
both empty by default. Using proxy-origin mode requires both. Validate the origin
as an exact HTTP(S) scheme/host/port with no credentials, query, fragment, or
subpath. Proxy entries must be literal IP addresses or valid CIDRs, not hostnames;
reject malformed entries and the universal `0.0.0.0/0` and `::/0` ranges.

Only a direct TCP peer in the configured proxy allowlist may use the configured
external origin for cookie bootstrap/Secure behavior and same-origin write
checks. The proxy must preserve the configured external Host. For other peers,
retain direct-connection origin checks. No trust in arbitrary Forwarded or
X-Forwarded-* headers is added. This mode does not redefine admin-IP exclusions
or application authorization.

Keep API query tokens rejected, explicit bearer/header credentials supported,
strict cookie origin checks, and fail-closed private/Tailscale binding. Tests cover
HTTPS termination through a trusted proxy, untrusted peers, spoofed headers,
Host/port mismatches, cross-site writes, direct access, token rotation, and startup
and shutdown under load. Document the default and opt-in behavior precisely.

## 8. Backup, verification, and restore

### CLI contract

Proposed commands, not currently implemented commands:

```text
shardlure -config CONFIG backup create --output NEW_BUNDLE [--include-file FILE] [--timeout 30m]
shardlure backup verify --input BUNDLE [--timeout 30m]
shardlure backup restore --input BUNDLE --to NEW_DATA_DIR [--dry-run] [--timeout 30m]
```

`--include-file` is repeatable and explicitly includes selected administrative
files as protected metadata; it never implies copying all of `/etc` or the process
environment. Default backups include the selected YAML, DB-backed settings and
ledgers, referenced evidence, and available configured Cowrie logs/downloads/TTY
sources. They exclude binaries, a Python virtualenv, unrelated service secrets,
and arbitrary files outside declared roots. Additional Cowrie customization or
host-recovery files can be included explicitly or backed up separately.

Creation requires an existing, explicitly resolved database/configuration. A typo
must not open a fresh default database. Verify/restore dispatch before the normal
store-opening path: neither may migrate the source DB, initialize the production
store, or start collection. All operations support cancellation/deadlines and
return nonzero on incomplete verification. Errors have stable bounded categories;
secrets and file contents are never printed.
Creation runs under the database's actual owner and must have read access to each
included file, consistent with the sidecar-ownership rule below. Unreadable
optional administrative files are an explicit error when requested, not a reason
to escalate silently; an administrator can back them up separately. The commands
do not require an external `sqlite3` executable or an additional running service.

### Versioned directory bundle

Use an inspectable directory, not an automatically extracted executable archive:

```text
BUNDLE/
  manifest.json
  database/shardlure.db
  files/evidence/...
  files/cowrie-logs/...
  files/cowrie-downloads/...
  files/cowrie-tty/...
  metadata/config.yaml
  metadata/included/...
```

Manifest format v1 records: format version, completion state, application
version/commit, database schema, UTC creation time, logical source-root mapping,
snapshot table counts, and a deterministic list of relative file names, roles,
byte lengths, and SHA-256 hashes. Source/log files additionally declare the copied
prefix length and observation time. No API key or raw environment dump belongs
in the manifest. The bundle can still contain credentials in its DB/config: it
is sensitive, unencrypted material, not an anonymized export.

Directories are owner-only `0700` and files `0600`. Do not restore executable,
setuid, device, socket, FIFO, hardlink, symlink, or supplied ownership metadata.
Only regular file content and validated logical mappings are portable data.

### Creation and consistency guarantees

1. Validate that the new destination is distinct from source roots and cannot
   recursively include itself. Check permissions and conservative space needs.
   Create protected staging beside the intended destination; refuse an existing
   destination and recheck at publication.
2. Use the pinned SQLite driver's online backup API through a dedicated,
   non-migrating source connection. Establish a stable read snapshot and step the
   backup in bounded, cancellable chunks with bounded busy handling. Do not copy
   just the live main DB file or manipulate live WAL/SHM files.
3. Derive mandatory evidence references from the completed DB snapshot. Stream
   the required evidence and declared source inventory using descriptor-relative,
   root-confined, no-symlink access and bounded buffers. Validate recorded hashes
   where available; check for source replacement/truncation or unstable content.
   Multiply linked files in untrusted evidence/source roots are unsupported and
   rejected; path confinement must not become a way to export an outside inode.
4. Immutable evidence must match the snapshot. Live logs may append: preserve and
   declare a verified prefix, not an allegedly atomic filesystem snapshot. A file
   created after inventory is not part of that inventory. Required missing files,
   rotation races that cannot be resolved safely, or unstable bytes fail the
   backup rather than yielding a misleading complete archive.
5. Close/flush the snapshot into a standalone DB, check SQLite integrity and
   declared counts, hash every entry, and perform the same verification used by
   the standalone verifier. Publish the completion manifest last and atomically
   publish the directory with no overwrite; flush files and parent directories.
   Finalize the snapshot's journal state so later read-only verification needs
   no WAL/SHM creation. Verification must leave both bytes and directory entries
   of the source bundle unchanged.

The guarantee is a consistent database plus verified required evidence and
declared per-file source prefixes—not a single instant across the whole live
filesystem. Retention/capture may race an online attempt; detected incompleteness
is an explicit failure, not an excuse to silently omit evidence or pause all live
writers indefinitely. Operators needing a whole-host point in time must quiesce
writers or use coordinated filesystem snapshots.

On failure/cancellation, leave a clearly marked, owner-only incomplete staging
directory and report it to the operator. Never publish it as a verified backup,
overwrite a previous backup, or automatically delete potentially useful partial
recovery material. Repeated failures are visible disk usage, not silent cleanup.

### Verification and safe restore

Verification is read-only. Reject incomplete/unknown formats, duplicate or
escaping names, absolute data-entry paths, NULs, unsupported types, missing or
unexpected files, hash/size/count mismatches, unsupported schema, and invalid
SQLite data. Enforce parser/resource limits before allocation: a 64 MiB manifest
cap and at most 1,000,000 entries; stream file bytes and database checks rather
than buffering the bundle. These limits fail clearly, never truncate coverage.

Restore requires a destination that does not exist, even if an existing directory
is empty. No `--force` overwrite mode is included. Verify first, stage beside the
destination, recheck space and confinement throughout, and publish with an atomic
no-replace operation. Source bundle and live DB/evidence/WAL/SHM remain unchanged.

After copying, remap operational evidence paths and Cowrie file-cursor paths to
the new roots through narrowly specified DB updates. Do not rewrite event bodies,
timestamps, actor identities, settings, or submission history. Inodes/cursors
must be safely rebased so later optional replay is deduplicated, not silently
skipped. Check original bundle hashes before remapping, then verify restored
logical data and references after remapping; record the transformation in a
recovery report outside the original bundle.

Write a separate recovery configuration for the new paths with retention and
capture disabled. Preserve the original config as metadata and preserve restored
settings rather than overwriting them. DB-backed settings can override YAML;
therefore the recovery config is not a claim of an enforced offline mode.
Restore/verification themselves perform no provider calls and start no services.
An operator must review effective settings and service-account ownership before
deliberately activating the recovered data. Included system/SSH files are never
installed automatically.
Restored files belong to the invoking user, not numerical owners from the source
manifest. No source-schema migration runs during verification or restore;
known-supported older schemas are preserved, with version-appropriate path
remapping only. A later explicit normal application startup owns any migration.

`--dry-run` verifies the bundle and destination feasibility without creating the
destination, copying data there, modifying source state, or starting a service.
Checksum manifests detect corruption, not hostile replacement of both manifest
and data; authenticity and encryption remain the operator's storage concerns.

Acceptance includes live WAL writes during snapshot, concurrent retention/file
changes, cancellation and ENOSPC, corruption, symlink/path traversal and hardlink
attacks, oversized manifests, repeated/existing destinations, crash before
publication, and round-trip restoration into a separate directory. Compare event
and ledger content, annotations/settings, evidence bytes, and logical references.

## 9. Health, readiness, and bounded metrics

Add GET/HEAD `/healthz`, `/readyz`, and `/metrics` to the existing listener. No
extra listening port or anonymously public health surface is introduced.
Use an operational read guard with the current debug security boundary: when a
token exists, require dashboard authentication; without a token, allow only a
direct loopback peer. Query tokens and wrong methods remain rejected.

- `/healthz`: lightweight process/conductor liveness, no DB scan; `200` while the
  initialized HTTP process is serving and `503` once shutdown begins. It does not
  claim the collection is ready merely because HTTP is responding.
- `/readyz`: `200` only when startup seeding/setup is complete and required
  components are operational; `503` while starting, stopping, or degraded. Return
  a fixed status and bounded reason codes, not errors, paths, IPs, or commands.
- `/metrics`: Prometheus-compatible text containing bounded process counters and
  operational gauges. Disabled/unavailable measurements are distinguishable from
  successful zero values.

Readiness checks a bounded database probe, supervisor state for enabled ingest
workers, and evidence-directory access/space when capture is enabled. Worker
progress/health is independent of whether attackers sent events. Idle healthy
workers stay ready; cancellation, dead workers, exhausted checks, and stale
health samples do not claim readiness. A normal fetch timeout budget must not be
mistaken for a dead capture worker.

Operational sampling runs every 5 seconds by default, with a 1-second per-cycle
budget and cancellation on shutdown. Use cheap probes plus instrumented counters;
expensive aggregate gauges refresh independently at most once per minute and
retain explicit sample age/error state. HTTP handlers consume bounded snapshots,
not fresh unbounded table scans or filesystem walks. A required health sample
older than 15 seconds cannot assert readiness. Sampling intervals/budgets are
fixed implementation defaults with injected clocks in tests, not new UI knobs.
The startup setting `observability.min_free_bytes` defaults to 268,435,456
(256 MiB) on each required data/evidence volume; it must be nonnegative, and `0`
explicitly disables only that free-space threshold. Document that this signals
degradation, not automatic deletion or a guarantee against disk exhaustion.

Required measurements cover:

- Readiness, startup state, uptime, and worker running/error/last-success state.
- Ingest commits/errors by the fixed journal/Cowrie source set.
- Capture work depth/outcomes, discovery lag, retry/lease state, and retention
  holds without URL, hash, filename, session, or actor labels.
- SQLite reachability, pool pressure, and bounded operation-failure counters.
- Data/evidence free bytes with logical volume roles, never path labels.
- Provider request outcomes and separate durable-sharing outcomes. An upstream
  success followed by a ledger failure must not be labeled durable success.

Provider/source/outcome labels are closed enumerations. No attacker-controlled
string becomes a metric name or label. Counters are process-scoped and reset on
restart; do not imply that a web process observes another CLI process's requests.
Health and metric scrapes never initiate enrichment, sharing, or payload fetching.

Acceptance includes startup-to-ready-to-draining transitions, quiet traffic,
disabled features, stalled/erroring components, trusted proxy handling, auth and
method rejection, sample expiry, cancelled scrapes, scrape storms, fixed series
cardinality under adversarial input, and concurrent shutdown.

## 10. Installer and deployment safety

Confirm and fix each remaining risk with controlled fixtures before changing
behavior. Both installers must meet the same contracts even where their port
defaults differ:

- Correct systemd/shell encoding for supported paths, including spaces, quotes,
  dollars, percent signs, apostrophes, and backslashes. Validate every affected
  directive, not only the Tailscale executable argument. Unsupported inputs fail
  before any configuration mutation.
- Preflight existing service users, group membership, directories, and installed
  services; refuse incompatible identities instead of taking ownership of
  unrelated data. Filesystem operations reject symlink/replacement races and
  avoid broad recursive permission changes.
- Preserve data-owner/WAL/SHM access. The CLI must not silently create root-owned
  sidecars that prevent a dedicated service account from continuing. Refuse
  unsafe ownership mismatches before mutation with actionable instructions to
  run as the actual service user; never silently chown a running collection.
- Validate effective SSH policy for the actual operator, including Match blocks.
  Preserve existing sessions and an administrative listener during transitions.
- Uninstall restoration is transactional: retain rollback material until both
  configuration validation and activation succeed. Coordinate Cowrie port
  conflicts; do not remove the working admin listener until restored access is
  verified. A failed restore must leave or restore working management access.
- Preserve customized Cowrie source and validate patch compatibility before
  applying any patch. A binary upgrade is not a full reinstall.

Unit tests/mock commands are necessary but not a substitute for a disposable
Ubuntu systemd/sshd integration run. Exercise fresh install, existing install,
custom paths, dedicated user access, socket activation/Match rules, interrupted
setup, failure rollback, and uninstall. The test guest is isolated; host SSH,
firewall, accounts, and the live ARM VM are not its test targets.

## 11. Documentation, verification, and release acceptance

Update README, CLI help, configuration examples, CLAUDE.md, the progress ledger,
and Wiki together. Remove stale assertions about header-only API auth, worker
counts, pending work already implemented, and unqualified completion. Clearly
separate defaults, opt-ins, release behavior, manual operations, and tested
environment coverage. Add Wiki navigation from the README.

The implementation plan must map each unresolved original-plan item to a code
change/test or explicit evidence that it was already resolved. This specification
does not silently defer the approved backup/readiness feature work.

Required release evidence:

1. Actual method-level regressions fail on the deficient behavior and pass with
   fixes; query-plan/memory bounds accompany correctness tests.
2. Full Go tests, race tests, vet, module verification, UTF-8/format checks,
   installer/release tests, pinned Cowrie patch checks, and dashboard smoke pass.
3. Backup/restore round trips and lifecycle/retention concurrency tests preserve
   data, permissions, provenance, annotations, settings, and ledgers.
4. Disposable installer/upgrade/recovery integration passes. An unavailable test
   environment is reported as an unfulfilled acceptance item, not called a pass.
5. AMD64, ARM64, and ARMv7 builds pass relevant architecture checks; ARM runtime
   validation uses inert fixtures and disposable data before a live rollout.
6. Sync with current main without discarding its changes, open/update the PR,
   and require CI and final review on the exact integrated revision.
7. After integration approval, merge and create the annotated `v2.8.0` tag on the
   verified main commit. The existing release workflow builds, checksums, and
   publishes artifacts; verify all release assets rather than publishing early.
8. Update the Wiki's baseline, source links, examples, and release notes only
   after the corresponding implementation/release is real. Do not document a
   proposed interface as an already shipped command.

A later ARM rollout needs its own fresh verified rollback, explicit retention
decision, staged migration check, baseline record/file preservation checks, and
HTTP/ingestion verification. The previously paused runtime retention policy must
not be accidentally replaced with startup deletion. Do not run restore or a full
installer against the live collection to prove release readiness. Old-backup
cleanup remains an explicit, exact-target operation after successful verification.

## 12. Review handoff

This file specifies behavior, boundaries, and acceptance criteria; it is not the
step-by-step implementation plan or a completion checklist marked green.
After written-spec approval, produce the implementation plan with file-level
tasks, test-first sequences, dependencies, and review checkpoints. Implementation
follows that approved plan. No application code, production configuration, Wiki
content, tag, or release is changed by preparing this specification.

Reference for snapshot semantics: [SQLite Online Backup API](https://www.sqlite.org/backup.html).
The locally pinned `modernc.org/sqlite v1.34.5` provides the corresponding backup
handle methods; their cleanup, busy, snapshot, and cancellation behavior must be
covered by the implementation tests, not assumed from a different driver version.
