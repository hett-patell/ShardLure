# Strix audit — validated triage (2026-06-20)

Every finding validated against actual source. Verdicts: FIX (real, will fix),
ALREADY (fixed in v1.11), REJECT (invalid/no-op), NIT (cosmetic, low value).

## Code findings

| # | Sev | Verdict | Notes |
|---|-----|---------|-------|
| 1/51 | HIGH→LOW | FIX (partial) | parseTime swallowed at scan sites. Harmless under write invariant (always RFC3339Nano), yields zero-time. Not HIGH. Will add a shared helper that logs once on corrupt data; not rewrite 30 sites. |
| 2 | HIGH | **FIX** | api_intel.go:757 leaks raw DB err in HTTP body. Real info-leak. Use httpError() (already exists). |
| 3 | HIGH | **FIX** | api_intel.go:1114 leaks share err in JSON. Same fix. |
| 4/101 | HIGH | **FIX** | copyArtifact no size cap → disk exhaustion. Add io.LimitReader at MaxBytes. |
| 5/122 | HIGH | **FIX** | install.sh writes DASH_TOKEN into mode-644 unit. chmod 600 the unit (or systemd creds). |
| 6/123/124 | HIGH | REJECT(doc) | setcap on venv python: real but it's how cowrie binds :22 unprivileged; documented tradeoff. Mitigate: prefer authbind (already used) — verify, else note. |
| 7/127 | HIGH | **FIX** | load_finish_ports int() no try/except → crash on bad env. Wrap + range-check. |
| 8 | HIGH | **FIX** | vps-finish.sh overwrites go.mod no backup. dev helper, but destructive — guard/backup. |
| 9/26 | MED | **FIX** | parseReader always returns nil err. Real: readLineBounded err discarded. Propagate. |
| 10/18 | MED | **FIX** | cmdIOC header says "journal actors", lists all. One-line header/filter fix. |
| 11/52 | MED→LOW | **FIX** | MaintenancePurge orphans evidence files if SELECT errors. Log the error. |
| 12/33 | MED | **FIX** | buildJournalActorsFromDB streams ALL events every tick — O(all history). Real perf bug (cowrie path was already optimized; journal wasn't). |
| 13/54 | MED | **FIX** | NULL→string scan ERRORS (confirmed empirically, aborts query). Never NULL today but fragile. Use sql.NullString in artifact scans. |
| 14/60 | MED | **REJECT** | UpsertActor first_seen: NOT data loss. Both paths recompute min: buildJournalActorsFromDB streams full history; liveJournalCollector always hydrates stored.First before add (sync.go:166-170) and First only moves earlier (sync.go:263). Verified. |
| 15/43 | LOW | FIX | builder.go finalize aliases st.Users map — latent. Copy on return. |
| 16/103 | MED | **FIX** | copyArtifact errors swallowed in syncCowrieTTY — add log/count. |
| 21/35 | LOW | **FIX** | my v1.11 buf=nil re-accumulates (oscillates to max repeatedly); comment wrong. Bound correctly. Memory still capped at max, so not HIGH. |
| 22/82 | LOW | DOC | IPQS key in URL path — API design, unavoidable. Document. |

## Script findings (FIX the real ones)
17/128, 19/130, 20/138 — unchecked apt/git returns + /dev/null: FIX (check returns, keep stderr).
18/143 — rmtree-then-copytree no rollback: FIX (copy to temp, swap).
139/140/141 — missing `set -o pipefail`: FIX (cheap, real).

## REJECTED false-positives (agreed with Strix's own FP list + my validation)
FK pragma (no FKs), migration-v3-tx (idempotent single stmt), io.EOF last-event
(correct Go iterator), interval-as-address (HasPrefix matches first), hardcoded
paths (operator-controlled), weak honeypot creds (intentional bait), bash TOCTOU
(dead elif), redundant hydration (intentional).
