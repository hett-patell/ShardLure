# ARM deployment evidence — September 23, 2026

Status: deployed and verified. ARM runs dev-review.3ac1721 from commit
3ac17216cf35d1363f5ed15c677b7fcca0720e6a. This is a development build, not a
v2.8.0 release or a declaration that the remaining completion-plan tasks passed.

Candidate 7d435e8 passed a fresh full Go suite, full race suite, vet,
UTF-8 check, Cowrie patch contracts, and short parser fuzz runs (journal
163,241 executions, Cowrie 112,501, TTY 37,599). ARM64 staging checksum was
0f2f68b932d98a20d9fef4d87dbd71bc74f00d27d8b45b7720695aa12df7f6e6.
No installer, SSH configuration change, real intel submission or payload
execution was used. Three independent review dispatches failed due model
capacity; no independent review is claimed.

## Preservation and findings

- Runtime retention is zero via /run/shardlure-deploy-e0bbe7b/shardlure.yaml;
  saved policy defaults to 90 days. The pause must survive the upgrade.
- A first backup failed closed on three pre-existing artifact references to
  two missing evidence files. Both files were recovered using byte-identical
  existing copies, verified against recorded hashes, with no-overwrite creation.
  No database record was changed.
- A fresh built-in backup succeeded: 2,655 files, schema 21, approximately
  4.3 GiB, at /var/lib/shardlure/backups/deploy-7d435e8-20260923.
  The earlier verified deploy-e0bbe7b-20260921 backup remains intact.
  Only this attempt's redundant failed 1.7 GiB staging directory was removed
  after the new backup passed verification.
- Disposable restore reproduced a compatibility bug: a canonical absolute
  checkpoint for a historical import outside the configured Cowrie log root
  makes path remapping reject the complete backup. Production is not modified
  by that failed restore; its incomplete staging is retained for diagnosis.

Ruling: keep canonical absolute out-of-root Cowrie import paths as inert
checkpoint metadata and clear inode/offset/head signature, while remapping
configured-root cursors normally. Such paths are not opened, copied or
automatically replayed. Evidence paths still fail closed outside their root,
and malformed paths remain invalid. This satisfies the existing preservation
and safe replay contract without inventing a new location for absent imports.
Cost: an operator replaying a separately supplied historical import rereads it
with normal event deduplication instead of reusing a stale foreign cursor.

The real-SQLite TestRestoreRoundTripPreservesLogicalData regression failed
before the fix and passed afterward. It covers two distinct external imports
with the same basename. Seven malformed-path/evidence-escape cases continue to
refuse. Fresh post-fix full Go suite passed (store 101.923s, web 27.361s),
focused recovery race checks passed (store 24.643s, backup 10.165s, CLI 4.408s),
and vet passed. The subsequent complete ARM restore passed: 2,657 restored
files, preserved schema 21, and no automatic service activation.

## Rehearsal verification

The disposable service had its own network namespace (loopback only, no route
to the Internet), read-only access outside its dedicated recovery directory,
dummy provider credentials, disabled retention, and disabled URL fetching.
No captured payload was executed.

- Schema 21 to 24: hashes of all original columns in all 15 original application
  tables matched before and after migration, excluding intentionally reset
  ingest cursors and migration records. This included 1,697,494 events, 9,323
  actors, annotations, settings, session side channels and all sharing ledgers.
- 143 API checks passed, plus 60 bounded concurrent reads across six clients.
  Thirteen additional checks passed for cookie auth, CSRF, token rotation,
  disabled reporting, network errors, metrics privacy and readiness.
- Ten CLI checks passed, including all three sharing dry-runs, AbuseIPDB
  reporting dry-run, actor/status/IOC views and reclassification dry-run.
  Events, annotations and submission ledgers were unchanged by those checks.
  The TUI rendered in a sized terminal and quit cleanly.
- Full restored-history replay was canceled after approximately 276 seconds
  while still starting; shutdown was graceful. This was not represented as a
  completed full replay. Restore intentionally resets cursors, so this path
  differs materially from upgrading an existing installation.
- For the actual upgrade scenario, all 83 configured source logs were checked
  against backup hashes and their original checkpoints mapped to the copied
  inodes. The isolated live service became ready within 48 seconds of probing.
  Three appended inert test events and a non-executable text file were ingested
  and archived within six seconds. Bytes, permissions and absence of fabricated
  successful-network-fetch provenance were checked.
- The retained e0bbe7b binary started against the schema-24 copy; six dashboard,
  capture, settings and runtime reads passed without a database downgrade.
  This is a binary read-compatibility check, not an exhaustive downgrade test.

## Production rollout and preservation

The deployed binary SHA-256 is
ae6fc5d34c08377b1b97b6198d9dab129940939c14b1916d799ed49cc28559c5.
Only ShardLure was restarted, at September 23, 2026, 11:36:55 IST. Its PID
changed from 19556 to 277467; Cowrie stayed at PID 95769. Both units are active
with zero automatic restarts. The listener remains restricted to the Tailscale
address on port 8080, not a wildcard/public listener.

A second, immediately pre-swap consistent snapshot preserves 1,698,050 events
in the private deployment directory. Production checks confirmed:

- Schema 24 and SQLite quick_check returning ok.
- Every pre-swap event ID still present; 1,698,076 events at the preservation
  check, with continued collection afterward.
- All pre-swap actor notes/campaigns, settings and original submission-ledger
  columns unchanged.
- All 1,655 evidence files referenced in the verified backup still match their
  byte sizes and SHA-256 hashes.
- All 96 applicable production API checks passed. The deployment intentionally
  has no dashboard token and uses private Tailscale access; that existing policy
  was preserved. Non-loopback operational requests are correctly refused, while
  genuine loopback probes report healthy/ready. Authenticated-mode and cookie
  tests were performed on the isolated token-configured instance.
- Six configured read-only provider tests passed: AbuseIPDB, VirusTotal, OTX,
  IPinfo, MalwareBazaar and the shared abuse.ch key check exposed for URLhaus.
  The URLhaus check calls MalwareBazaar read-only; it does not prove acceptance
  of an actual URLhaus submission. No real intelligence was submitted.
- A 20-second final soak observed event-ID and Cowrie-offset advancement,
  healthy readiness/database probes, zero worker errors, and approximately
  7.05% of one CPU core during that short sample. This is not a long-duration
  reliability or performance guarantee.

## Operational handoff

The retention pause now survives service restarts via the root-only
/etc/systemd/system/shardlure-live.service.d/90-reviewed-retention-pause.conf
drop-in. It selects the root-only runtime-retention-paused.yaml inside
/var/lib/shardlure/deploy-review-7d435e8-20260923. The saved original policy
was not changed; it still defaults to 90 days. Do not remove this pause without
deliberately deciding to resume retention.

Both verified backups remain in /var/lib/shardlure/backups. The deployment
directory also retains pre-swap.db, the prior binary, checksummed candidates,
API/metrics/soak/provider receipts and scoped validation scripts. Recovery data
is sensitive, unencrypted and owner-only. No data ownership was changed and
neither installer ran. Only failed test staging and the stopped disposable
rehearsal copy were removed; their original data remains in production and the
verified backups. Disk free space was approximately 6.0 GiB at handoff.

If rollback is needed, prefer a controlled binary rollback while retaining the
retention pause and current DB; do not overwrite the live database with an older
snapshot and silently discard intervening collection. The older binary's
schema-24 read compatibility was rehearsed, but monitor any actual rollback.

Still outside this deployment: unfinished installer/SSH integration tasks,
independent whole-branch review, merge/release and Wiki publication. Those are
not marked complete by these deployment checks. Existing installer edits were
left untouched and unstaged.
