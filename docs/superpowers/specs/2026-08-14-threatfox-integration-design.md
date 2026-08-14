# ThreatFox integration — research & design

**Date:** 2026-08-14
**Status:** research complete + live-API-verified; decisions settled; implementing
**Goal:** add ThreatFox as a fourth abuse.ch give-back channel, sharing the malware-hosting IOCs ShardLure captures — completing the file (MalwareBazaar) → URL (URLhaus) → **IOC (ThreatFox)** triad on the one shared Auth-Key.

---

## 1. What ThreatFox is, and what it requires

ThreatFox (abuse.ch) is a free platform for **sharing indicators of compromise** — IPs, domains, URLs, and hashes tied to a malware family. It is the IOC-level sibling of MalwareBazaar (files) and URLhaus (URLs).

**API contract (studied from https://threatfox.abuse.ch/api/):**
- **Endpoint:** `POST https://threatfox-api.abuse.ch/api/v1/`, JSON body, dispatched by a `query` field.
- **Auth:** `Auth-Key` HTTP header — **the same abuse.ch key** ShardLure already resolves for MalwareBazaar/URLhaus (`abuseCHKeyLive()` / `abuseCHKey()`). Required for `submit_ioc`.
- **Submit request (`query: "submit_ioc"`):**
  | field | req | value |
  |---|---|---|
  | `threat_type` | yes | e.g. `payload_delivery`, `botnet_cc` (from `types` endpoint) |
  | `ioc_type` | yes | `url`, `domain`, `ip:port`, `md5_hash`, `sha256_hash` (from `types`) |
  | `malware` | yes | **Malpedia label**, e.g. `elf.mirai` — from `malware_list` / resolved via `get_label` |
  | `confidence_level` | no | 0–100, default 50 |
  | `reference` | no | a URL |
  | `tags` | no | list, chars `[A-Za-z0-9.- ]` |
  | `iocs` | yes | list of IOC strings |
  | `comment` | no | free text |
  | `anonymous` | no | `1`/`0` |
- **Response:** standard `{"query_status": "ok", ...}` envelope (abuse.ch does not publish a `submit_ioc` success/duplicate example; treat unknown statuses verbatim, exactly as the urlhaus client already does).

**Policy (the load-bearing constraints):**
- **"Please do only submit confirmed / vetted IOCs."** Repeated junk → account **banned from contributing.** Since this is the *same account* that carries MalwareBazaar + URLhaus, a ThreatFox ban would kill all three channels. **The vetting bar must be at least as strict as urlhaus's.**
- IOCs older than 6 months expire; `get_iocs` only returns ≤7 days. (Only matters if we ever *consume* ThreatFox; this design is submit-only.)
- `malware` must be a real Malpedia family label — a submission with a wrong/unknown family is exactly the "junk" that gets banned.

---

## 2. What ShardLure has, mapped to ThreatFox's requirements

Two candidate IOC sources exist in the data. **Only one is safe.**

### 2a. REJECTED source: tunnel / pivot targets (`direct-tcpip`)
The obvious idea — "share the IPs attackers pivot to through the honeypot as `botnet_cc`" — is **wrong and dangerous.** Live data (top `dst_ip:dst_port`):
```
1.1.1.1:53 (x1194)   8.8.8.8:443 (x67)   google.com:80/443   icanhazip.com   ip-who.com
```
These are **connectivity/DNS checks**, not C2. Submitting them as botnet C2 would poison ThreatFox with Cloudflare/Google infrastructure and get the account banned. There is no reliable signal in the honeypot to tell a real C2 pivot from a liveness check, and `malware` family can't be attributed to a bare pivot IP anyway (no `malware` label → fails the required field). **Tunnel targets are out of scope. Documented here so nobody re-proposes them.**

### 2b. ACCEPTED source: malware-hosting IOCs from confirmed fetches
The safe, high-quality source is the payload-delivery infrastructure ShardLure **fetched malware from first-hand**: `origin=quarantine_fetch`, `status=fetched`, real `http(s)` URL, a captured payload with a sha256 — the exact provenance urlhaus already vets. From each such fetch we can derive up to three ThreatFox IOCs, all `threat_type=payload_delivery`:
- the **URL** (`ioc_type=url`),
- the **host** if it is a public IP:port (`ioc_type=ip:port`) or a domain (`ioc_type=domain`),
- and we can reference the **sha256** as a linked sample.

Crucially, this source **already carries a family label**: `bazaar.Classify()` runs on the fetched file and emits one of `mirai, gafgyt, redtail, xmrig, komari, c3pool, traffmonetizer, proxyware, botnet, miner` — which map cleanly to Malpedia labels. This is what satisfies ThreatFox's mandatory `malware` field with a *real* value, not a guess.

**Provenance chain (all first-hand, no inference):** attacker ran `wget http://host/x` → SafeFetcher downloaded it → sha256 + `Classify()` family → the URL/host demonstrably served that family's payload. That is precisely a `payload_delivery` IOC ThreatFox wants.

### 2c. The family → Malpedia label mapping
ShardLure's family strings are informal (`mirai`), ThreatFox wants Malpedia labels (`elf.mirai`). A small explicit map handles the ~10 families the classifier emits; anything the classifier leaves **unclassified is NOT submittable** (no family = fails the required field = would be junk). This is a *feature*: it means only confidently-attributed IOCs go out.

---

## 3. Design — a new `internal/intel/threatfox` package

Mirror the urlhaus package almost line-for-line (it is the closest analog: outbound abuse.ch submission gated by a single `Vet`, on the shared key).

### 3a. Files
- `internal/intel/threatfox/client.go` — `POST` to `https://threatfox-api.abuse.ch/api/v1/`, `Auth-Key` header, `query:"submit_ioc"` body. Key passed per-call (never stored on the struct, matching bazaar/urlhaus so a logged client can't leak it).
- `internal/intel/threatfox/vet.go` — the single policy gate. Hard rejects (win over accept signals):
  - `origin != quarantine_fetch` or `status != fetched` → reject (only first-hand fetches).
  - payload `size < 64` (`MinSampleBytes`, shared floor) → reject.
  - no resolvable Malpedia family (classifier returned empty/unknown) → reject.
  - host is private/reserved (`netmatch.IsPublicIP`, RFC1597/6890) → reject — same SSRF/pollution guard urlhaus uses.
  - URL shortener host → reject (reuse urlhaus's `shortenerHosts`).
  - fetch older than `active_days` (default 3, tightenable only) → reject.
  - benign kinds (SSH key, honeypot artefact) → reject (reuse the bazaar/urlhaus benign set).
- `internal/intel/threatfox/malpedia.go` — the family→label map + `MalpediaLabel(family) (string, ok)`.
- `internal/intel/threatfox/share.go` — `Share(ctx, rec, candidates, opts)` orchestrator: Vet → dedup → submit → record, with `MaxSubmissions` bounding **submissions after the gate** (the D3 lesson — never a pre-gate SQL LIMIT), `OnLimitReached`, and `Options.Now` injectable clock (the time-bomb lesson from the urlhaus tests). Dedup ledger `threatfox_submissions` (url+ioc_type), **never purged**, exactly like `urlhaus_submissions`.

### 3b. Store
- `store.ThreatFoxCandidates(activeDays, limit)` — SQL selecting `quarantine_fetch`/`fetched` artifacts with a real http(s) url, sha256, size ≥ 64, within the window, NOT already in `threatfox_submissions`. **Identical shape to `URLhausCandidates`** (and its stats subquery must stay in lockstep, per the existing urlhaus invariant). The `limit` here is a coarse pool cap only; the real budget is enforced in `Share`.
- `store.ThreatFoxSubmitted(ioc) (bool, error)` + `RecordThreatFoxSubmission(...)` — the dedup ledger (lazy table via `sync.Once`, like the others).
- The family label comes from `Classify(local_path)` at candidate-build time in the caller (store must not import `intel/*`), same as urlhaus reads the classifier for `FileKind`.

### 3c. CLI + web (reuse existing seams)
- `cmd/shardlure/share_threatfox.go` — `shardlure share threatfox [--dry-run] [--limit N] [--active-days N]`, resolving the key via the shared `abuseCHKey(cfg, keys, "SHARDLURE_THREATFOX_KEY")`. **No new keystore field** — the one-key invariant holds (a ThreatFox-specific key setting would let the abuse.ch account silently split; deliberately avoided, exactly as urlhaus has no separate key). `--limit` → `Options.MaxSubmissions`, printed as `submit-limit=` in the header. Wire into the `cmdShare` dispatcher next to `bazaar`/`urlhaus`.
- Web: a `panel-threatfox` on the Blue Team tab mirroring `panel-urlhaus` — renders each candidate's Vet decision *including the rejection reason*, `handleThreatFoxSubmit` re-runs the gate server-side (button can't bypass policy), `threatfoxBatchMu` guards double-clicks. Optional for a first cut; the CLI is the MVP.

### 3d. What is deliberately NOT built
- No tunnel-target submission (§2b).
- No ThreatFox *consumption* (`get_iocs` enrichment) — possible future, out of scope here.
- No separate Auth-Key setting (one-key invariant).
- No `botnet_cc` submissions in v1 — everything is `payload_delivery`, the only threat_type we have first-hand proof for.

---

## 4. Testing (matching the bar set this session)
- `vet_test.go` — table of accept/reject cases: each hard reject fires (private host, shortener, no-family, stale, benign SSH key, wrong origin), accept only when all hold. Public-IP fixtures (RFC5737 doc ranges are reserved and would be wrongly rejected — the lesson from the abuseipdb tests).
- `share_test.go` — `MaxSubmissions` bounds submissions not candidates; dry-run previews == real run; `Options.Now` pins the clock (no wall-clock time-bomb); dedup skip costs no budget; every skip reports via `OnProgress`.
- `malpedia_test.go` — every family the classifier can emit maps to a label or is explicitly unsubmittable; no silent "" that would become junk.
- CLI: extend `outbound_limit_test.go`'s taint-tracking guard to cover `share_threatfox.go` (no pre-gate `cands` slice / no `*limit` into a `*Candidates` collector) — the same guard that now covers all three siblings.
- Store: `ThreatFoxCandidates` SQL == stats subquery (the urlhaus drift lesson).

## 5. Rollout
Go-only change (new package + CLI wiring + optional web panel); **no Cowrie/persona change, no schema migration** beyond the lazy `threatfox_submissions` ledger. Manual subcommand, off by default, same as `share urlhaus`. Verify with `--dry-run` against the live DB (20 candidate fetch-URLs exist today) before any real submission; confirm each accepted candidate has a real family label and a public host.

## 6. Decisions (settled 2026-08-14)
1. **Scope:** CLI **and** Blue Team web panel, full urlhaus parity. Server-side re-vet on the button is the safety.
2. **Family confidence: STRICT.** Only families that resolve to a single confident Malpedia label are submittable; everything else is unsubmittable (no generic guess — that is exactly the junk that bans the shared account).
3. **IOC breadth:** the **URL** plus the **host** (public IP → `ip:port`, hostname → `domain`) plus the **sha256** as a `payload` IOC — all first-hand from the same fetch. Each row is independently gated.

## 7. Live-API-verified facts (2026-08-14, queried with the arm abuse.ch key)
- **`types` confirmed:** `url`/`domain`/`ip:port` each carry `payload_delivery` (types 1/2/3); `sha256_hash` carries `payload` (type 10). So a captured sample hash is a first-class IOC, not just a `reference`.
- **Malpedia label map — VERIFIED against the live 3,855-entry `malware_list`. Only these four map to a single confident `elf.*` label:**
  | classifier family | Malpedia `malware` label |
  |---|---|
  | `mirai` | `elf.mirai` |
  | `gafgyt` | `elf.bashlite` (Malpedia files Gafgyt under Bashlite; **`elf.gafgyt` does NOT exist** — a naive map would be rejected) |
  | `redtail` | `elf.redtail` |
  | `xmrig` | `elf.xmrig` |
- **Unsubmittable (no clean Malpedia label — `get_label` returns no match or many unrelated families):** `komari`, `c3pool`, `traffmonetizer`, `proxyware` (ShardLure-internal names), and the generic buckets `botnet`, `miner`, `coinminer`. These are dropped by the gate, not guessed. This is the strict decision in force.
- **`get_label` must be resolved at BUILD time from a static map, not at submit time** — the four labels are hard-verified and frozen in `malpedia.go`; no live `get_label` call in the hot path (offline-capable, deterministic, testable). A `malpedia_test.go` documents that the map was verified against the live list on this date and that adding a family requires re-verifying its label.
- **Threat type:** everything is `payload_delivery` (url/domain/ip:port) or `payload` (sha256). No `botnet_cc` in v1 — we have no first-hand C2 proof (see §2a).
