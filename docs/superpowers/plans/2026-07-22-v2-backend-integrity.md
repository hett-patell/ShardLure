# ShardLure v2 Backend Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the approved v2 backend release blockers with atomic journal persistence, source-correct actor hydration, bounded/retriable capture, and reference-safe evidence retention.

**Architecture:** Keep the current single-process SQLite/write-mutex model. Add one journal transaction primitive, one artifact retry migration, and a single coalescing capture worker. Do not broaden v2 into actor taxonomy, generic blob normalization, or unrelated configuration cleanup.

**Tech Stack:** Go, modernc SQLite, existing package tests.

## Fixed design decisions

- Deduplicate live journal replay by exact normalized raw line and event identity inside the same transaction as insertion; do not add a unique index over legacy data.
- `actor.SyncJournalEvent` owns event plus actor persistence. Duplicate/error invalidates the mutated collector entry so the next event rehydrates from durable state.
- Capture uses one worker, a capacity-one coalescing trigger, eight URL attempts per run, and a two-minute deadline.
- Migration v16 adds `attempt_count` and `next_attempt_at`; the latter is both retry time and capture lease expiry.
- `fetched` and `blocked` are terminal. `failed` and expired `capturing` retry with exponential one-minute-to-one-hour backoff.
- Retention rechecks `local_path` references after row deletion while holding `writeMu`; a blob/refcount redesign is deferred.

---

### Task 1: Source-Qualified Journal Hydration

**Files:**
- Create: `internal/store/journal_ipstats_test.go`
- Modify: `internal/store/journal_ipstats.go`
- Modify: `internal/actor/sync.go`
- Modify: `internal/actor/live_collector_test.go`

- [ ] Write `TestLoadJournalIPStatsIsActorQualified`: seed newer Cowrie and older journal actor rows for one IP; assert journal counters/users are returned.
- [ ] Run `go test ./internal/store -run TestLoadJournalIPStatsIsActorQualified -count=1`; expect failure from the IP-only query.
- [ ] Change the API to `LoadJournalIPStats(actorID, ip string)` and query `actor_ips WHERE actor_id=? AND ip=?`; load users by that same actor ID.
- [ ] Call `st.LoadJournalIPStats(JournalActorID(e.SrcIP), e.SrcIP)` from actor sync.
- [ ] Add `TestLiveCollectorHydratesJournalRowWhenCowrieIsNewer` and run `go test ./internal/store ./internal/actor -count=1`.
- [ ] Commit: `fix(actor): qualify journal hydration by actor id`.

---

### Task 2: Atomic Journal Event and Actor Storage

**Files:**
- Create: `internal/store/journal_atomic_test.go`
- Modify: `internal/store/transaction.go`

- [ ] Add failing tests `TestAppendJournalEventAtomicDeduplicatesRawLine`, `TestAppendJournalEventAtomicRollsBackEventOnActorFailure`, and `TestAppendJournalAcceptedAtomicWithoutActor`. The rollback test installs a trigger that aborts actor writes, then asserts no event remains.
- [ ] Run `go test ./internal/store -run TestAppendJournal -count=1`; expect missing API failure.
- [ ] Add:

```go
type JournalActorUpdate struct {
	Actor     *models.Actor
	IPFirst   time.Time
	IPLast    time.Time
	IPCount   int
	Username  string
	UserCount int
}

func (s *Store) AppendJournalEventAtomic(e *models.Event, update *JournalActorUpdate) (inserted bool, err error)
```

Inside one `WithTx`, check exact journal identity (`ts`, source, kind, IP/port, sanitized username, raw); return `false,nil` on replay; insert event; optionally upsert actor/IP/user; commit all or none.
- [ ] Run the targeted store tests and commit: `fix(store): persist journal events and actors atomically`.

---

### Task 3: Transaction-Aware Live Actor Sync

**Files:**
- Modify: `internal/actor/sync.go`
- Modify: `internal/actor/sync_test.go`
- Modify: `internal/actor/live_collector_test.go`

- [ ] Write `TestSyncJournalEventDuplicateDoesNotAdvanceCollector`: unique, identical replay, then distinct event; expect two events and actor count two.
- [ ] Run `go test ./internal/actor -run TestSyncJournalEventDuplicateDoesNotAdvanceCollector -count=1`; expect failure.
- [ ] Make `SyncJournalEvent` return `(inserted bool, err error)` and call the atomic store API instead of requiring an earlier `InsertEvent`.
- [ ] Add collector `invalidate(ip)` that removes both map and LRU entries. Invalidate after a duplicate or transaction error so uncommitted increments cannot leak forward.
- [ ] Remove explicit event inserts from actor tests and run `go test -race ./internal/actor -count=1`.
- [ ] Commit: `fix(actor): invalidate live journal state after rejected writes`.

---

### Task 4: Follow Journald From Now

**Files:**
- Create: `internal/ingest/journal/tail_test.go`
- Modify: `internal/ingest/journal/tail.go`

- [ ] Add failing tests `TestJournalctlFollowArgsStartsAtNow`, `TestConsumeTailDeduplicatesReplayedLine`, and `TestConsumeTailDeduplicatesAcceptedLineWithoutActor`.
- [ ] Extract:

```go
func journalctlFollowArgs(unit string) []string
func consumeTail(ctx context.Context, r io.Reader, st *store.Store, admin *netmatch.Set) error
```

Arguments are exactly `-u <unit> -n 0 -f -o short-iso --no-pager`. Accepted non-admin telemetry calls `AppendJournalEventAtomic(e,nil)`; attack events call refactored actor sync; duplicate lines are silent.
- [ ] Run `go test ./internal/ingest/journal ./internal/actor ./internal/store -count=1`.
- [ ] Commit: `fix(journal): prevent tail replay and atomically sync actors`.

---

### Task 5: Artifact Retry Migration v16

**Files:**
- Modify: `internal/store/artifacts.go`
- Modify: `internal/store/sqlite.go`
- Modify: `internal/store/migrate_test.go`

- [ ] Add failing `TestMigrationV16UpgradesLegacyArtifacts` and `TestMigrationV16PreservesLazyArtifactCreation`; update the idempotence test to expect v16.
- [ ] Run `go test ./internal/store -run TestMigration -count=1`; expect version/column failures.
- [ ] Extend lazy creation with `attempt_count INTEGER NOT NULL DEFAULT 0`, `next_attempt_at TEXT`, and index `idx_artifacts_capture_due(origin,status,next_attempt_at)`.
- [ ] Append migration 16: if artifacts exists, add each missing column and index; if absent, only stamp v16 so lazy creation remains valid. Existing failed/capturing rows with NULL retry time are immediately eligible once.
- [ ] Run migration tests and commit: `fix(store): persist artifact capture retry state`.

---

### Task 6: Atomic Artifact Claim and Completion

**Files:**
- Create: `internal/store/artifacts_retry_test.go`
- Modify: `internal/store/artifacts.go`

- [ ] Add failing tests for lease enforcement, due failure retry, terminal rejection, stale completion rejection, retries outside the recent event window, and missing fetched files.
- [ ] Extend `Artifact` with `AttemptCount` and `NextAttemptAt` and add:

```go
func (s *Store) DueArtifactCaptures(now time.Time, limit int) ([]Artifact, error)
func (s *Store) ClaimArtifactCapture(a Artifact, now, leaseUntil time.Time) (attempt int, claimed bool, err error)
func (s *Store) CompleteArtifactCapture(a Artifact, attempt int, nextAttempt time.Time) (completed bool, err error)
```

New/eligible rows become `capturing` with an incremented attempt and lease. Fetched/blocked never claim. Completion is conditional on URL, attempt, and `capturing`; failure stores retry time, terminal outcomes clear it. A fetched completion whose local file no longer exists becomes retryable failure.
- [ ] Run `go test ./internal/store -run ArtifactCapture -count=1`.
- [ ] Commit: `fix(capture): claim and complete retries atomically`.

---

### Task 7: Bounded URL Work With Persistent Retry

**Files:**
- Create: `internal/capture/runner_retry_test.go`
- Modify: `internal/capture/runner.go`

- [ ] Add failing tests for exponential/capped delay, not-before scheduling, failure-then-success, eight-attempt cap, persisted retry outside the newest 500 events, and context expiry.
- [ ] Add defaults:

```go
const (
	defaultMaxURLFetches = 8
	retryBase = time.Minute
	retryMax = time.Hour
	captureLease = 5 * time.Minute
)
```

Add test-overridable clock and max-attempt fields. Process persisted due rows first, then new recent URLs; claim before fetch; stop after eight claims or context cancellation; memoize only fetched/blocked. Leave pseudo-URL handling for Cowrie downloads and TTY files unchanged.
- [ ] Run `go test ./internal/capture -run 'Retry|Runner' -count=1`.
- [ ] Commit: `fix(capture): bound URL attempts and retry transient failures`.

---

### Task 8: Coalescing Capture Worker

**Files:**
- Create: `internal/capture/worker.go`
- Create: `internal/capture/worker_test.go`
- Modify: `cmd/shardlure/main.go`

- [ ] Add failing tests for nonblocking trigger, trigger coalescing, two-minute deadline, and parent cancellation using a fake blocking run function.
- [ ] Implement `Worker` with a capacity-one channel, `Trigger()` nonblocking send, and `Run(ctx)` wrapping each call in `context.WithTimeout`. `NewWorker` accepts result logging callback.
- [ ] Create the signal context before capture in `cmdLive`; start worker; trigger initial work asynchronously; after Cowrie ingest call `Trigger()` instead of `Runner.Run`. Web startup must not wait for capture.
- [ ] Run `go test ./internal/capture ./cmd/shardlure -count=1`.
- [ ] Commit: `fix(live): decouple capture from startup and ingest ticks`.

---

### Task 9: Reference-Safe Evidence Unlink

**Files:**
- Modify: `internal/store/purge_test.go`
- Modify: `internal/store/sqlite.go`

- [ ] Add failing `TestMaintenancePurgePreservesSharedArtifactFile` and passing-control `TestMaintenancePurgeDeletesUnreferencedArtifactFile`.
- [ ] Run `go test ./internal/store -run MaintenancePurge -count=1`; expect shared file deletion failure.
- [ ] Hold `writeMu`; begin transaction; collect distinct expired paths; delete reference rows; query remaining artifact references inside the transaction; commit; while still locked unlink only zero-reference paths and `.txt` siblings; unlock. Close rows before deletes.
- [ ] Run purge tests and commit: `fix(retention): preserve evidence with live artifact references`.

---

### Task 10: Backend Contract Documentation and Verification

**Files:**
- Modify: `CLAUDE.md`

- [ ] Document the capture worker, `-n 0`/atomic journal path, v16, persistent retry/lease rules, and reference-safe unlink.
- [ ] Run:

```bash
go test -count=1 ./cmd/... ./pkg/... ./tui/... ./internal/config/... ./internal/store/... ./internal/ingest/... ./internal/capture/... ./internal/actor/... ./internal/netmatch/... ./internal/settings/...
go test -race -count=1 ./internal/store ./internal/ingest/journal ./internal/capture ./internal/actor
go vet ./...
git diff --check
```

- [ ] Confirm both migration from v15 and fresh startup; commit: `docs: document v2 backend reliability guarantees`.

## Explicit deferrals

Intent taxonomy, generic same-second batch dedup, `max_bytes:0`, session side-table retention, keystore ordering, symlink hardening, strict YAML, CLI/keystore unification, TTY UTF-8, memo LRU, and blob normalization remain post-v2 work.
