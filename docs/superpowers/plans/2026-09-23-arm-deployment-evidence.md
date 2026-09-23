# ARM deployment evidence — September 23, 2026

Status: deployment gated; production still runs dev-review.e0bbe7b.

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
and vet passed. Real ARM restore is being repeated; deployment remains gated.
