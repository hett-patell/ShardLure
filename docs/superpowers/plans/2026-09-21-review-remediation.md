# Branch review remediation — September 21, 2026

Scope: nine findings reviewed against base 552dcf9 through branch head 962d1b1.
Changes are in the isolated fix/reliability worktree. This remediation does not
claim completion of the wider backup/readiness/installer audit backlog.

## Confirmed causes and fixes

1. Legacy event dedup: timestamp text differs before/during v20 backfill.
   Match both writer formats through the timestamp index and canonicalize read
   identities. Regression covers journal/Cowrie, whole/fractional seconds and
   replay before/after backfill. Original live-append fixture duplicated a row.
   Paired keys stay inside one SQL chunk: an additional test reproduced backfill
   moving a row between separate format probes; grouped pairs now prevent it.
2. Capture lease invalidation: backfill read before its writer transaction and
   overwrote current capture fields. Read/repair/cursor now share a bounded
   transaction. Modern leases, completed outcomes and fetch provenance survive.
3. Active evidence retention: the purge preferred first_observed_at. It now uses
   last_seen_at (legacy ts fallback); immutable fetch freshness stays unchanged.
   Regression checks both the retained ledger row and inert evidence file.
4. Fresh SFTP captures: pinned Cowrie created 0600 files regardless of umask.
   Idempotent close/finalization patch sets 0640 before publishing the event,
   including duplicate destinations, without granting execute/other access.
5. Touched legacy artifact omission: requiring both observation columns NULL
   skipped partially repaired rows. A fresh repair cursor revisits them, and
   touch/discovery/claim preserve old provenance before replacing source fields.
6. Mixed timestamp ordering: SQLite rounding and integer truncation placed
   legacy/native events into incompatible buckets. Exact timestamp/ID ordering
   now occurs in SQL, with a strict Go-backed scalar parser for legacy rows.
7. Capped/latest query cost: restore indexed normal reads, SQL LIMIT and scalar
   counts; schema v21 adds only a shrinking legacy-row index. A read snapshot
   makes capped count/page consistent. No whole-millisecond Go buffers remain.
8. ThreatFox partial successes: early stops erased previously recorded IOC
   counts. Candidate finalization now reports durable partial results on ledger,
   authentication and cancellation failures, without continuing submissions.
9. Tailscale executable: render the detected path with systemd-safe quoting.
   Behavior tests exercise a custom path, readiness, timeout and loopback mode.

## Confirmation evidence

- New correctness regressions failed on the reviewed implementations, then passed.
- A cap=1 allocation check failed against the old window reader: 195 allocations
  for 10 rows versus 47,960 for 3,010 rows. Fixed reader: 59 versus 60 allocations.
- Local 50,000-row benchmark: latest-event ~0.079 ms; newest-one ~0.192 ms;
  capped result plus exact total ~14 ms. Review baseline for the first two was
  ~42 ms and ~490 ms. These are local measurements, not production guarantees.
- Independent final review found an overbroad legacy-index hint on scoped actor
  reads. A query-plan regression reproduced the scan; the helper now preserves
  actor/source index selection for scoped reads and the regression passes.
- Final full Go suite PASS (store 56.804s, web 22.103s), final vet PASS.
- Full repository race suite PASS after the SQL index adjustment (store 327.630s,
  web 112.669s); additional race regressions after the final dedup chunk fix PASS
  in store, Cowrie and journal packages.
- All 88 Python installer/release tests PASS. Native and ARM64 cross-builds,
  local dashboard smoke, shell/Python syntax, UTF-8 and diff checks PASS.
- Pinned Cowrie patch tests cover 3 behavior cases, 16 partial-state rejection
  cases, idempotence and atomic preflight; independently rerun and PASS.

## Deployment boundary

No live installer, ARM restart, database repair, provider submission, or payload
fetch was performed for this remediation. The deployment remains the previously
installed commit until these branch changes are deployed separately. Existing
historic duplicates or provenance already erased by an older run need a separate
production-data assessment; these fixes do not guess at historical repairs.
