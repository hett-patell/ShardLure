# ELF malware-family classifier — design

**Date:** 2026-08-14
**Status:** IMPLEMENTED. Live validation on arm (757 payloads): **4 Mirai ELFs newly attributed** (was 0) via the resilient anchors, **100 samples gained the `packed` tag**, script-dropper families unchanged. NOTE: the earlier "5 Mozi" estimate was a measurement error — a crude case-insensitive `mozi` probe false-matched `Mozilla` (the browser UA Mirai uses for HTTP-flood spoofing). There are NO genuine Mozi samples in the corpus, and the classifier's word-boundary check correctly refuses `Mozilla` — which is exactly the false-positive the precision-first design exists to prevent. mozi/tsunami mappings are kept for when real samples arrive.
**Goal:** raise family attribution on captured Linux/IoT ELF botnet samples so more payloads get correct MalwareBazaar tags AND become eligible ThreatFox IOCs — WITHOUT ever emitting a wrong family (a false positive bans the shared abuse.ch account).

## Motivation (measured on the live arm deployment)

The ThreatFox eligibility investigation found the bottleneck is upstream of the submission gate: `bazaar.matchELFFamily` does a literal case-insensitive substring search for family names (`"mirai"`, `"gafgyt"`, …), which fails on real IoT malware. Of 24 distinct URL-bearing ELF payloads captured:

| class | count | why the current classifier misses it |
|---|---|---|
| UPX-packed | 12 | family name is compressed away |
| **Mozi** | 5 | **classifier has no Mozi case at all** |
| Mirai (lazily-stripped) | 1 | name isn't a literal string; leaked-source symbols are |
| genuinely ambiguous | 6 | insufficient signal |

The classifier assigned a family to **0 of 142 ELF samples** across all history (only shell-script droppers get families, via text signatures). Fixing this lifts MalwareBazaar tags, ThreatFox eligibility, and the Red Team payload panel at once (one shared classifier).

## Governing principle (from published-YARA research + live samples)

Mirai, Gafgyt/Bashlite, and Mozi share a code lineage, so single generic strings (`PING`, `/bin/busybox`, `TSource Engine Query`, IRC verbs, raw `0xDEADBEEF`) are LOW precision and must NEVER carry a family attribution alone. **A family label is emitted only when a Tier-A anchor matches.** Precision ≫ recall: leave a sample `unknown` rather than guess. This mirrors the existing `bazaar.Vet` two-axis discipline — verdict ("is it malware") is separate from attribution ("which family").

Second structural fact: stripping removes the symbol table but NOT `.rodata`/`.data` string constants. So the resilient Mirai signature is the XOR-obfuscated credential wordlist in `.rodata` (stripping never touches it), not the leaked-source function names (which only survive in un-stripped builds).

## Scope (settled)

- **Fingerprints only** — no UPX decompression, no execution, no new dependencies. Packed-and-unattributable samples stay family-`unknown`.
- **Shared classifier** — rewrite `matchELFFamily` in `internal/intel/bazaar/classify.go`; all channels already use it.
- **Add a `packed` tag** (and `upx` when the magic/tamper-markers are found) — a useful MalwareBazaar signal that also marks *why* a family wasn't attributed. Packed-ness gates attribution (withhold family on packed-unattributable) but is itself a verdict signal, not an attribution.

## The matchers (Tier-A anchors — all from published YARA rules, confirmed in live samples)

Each family emits its Malpedia label only on a Tier-A hit. Labels re-verified against the live ThreatFox `malware_list` on 2026-08-14: `elf.mozi`, `elf.mirai`, `elf.bashlite`, `elf.tsunami` all present; `elf.gafgyt` does NOT exist (Gafgyt → `elf.bashlite`).

- **Mozi → `elf.mozi`** (5 live samples): literal `Mozi`/`Mozi.m`/`Mozi.a`, OR the 16-byte XOR key `4E 66 5A 8F 80 C8 AC 23 8D AC 47 06 D5 4F 6F 7E` together with the on-disk config marker `15 15 29 D2`. NOT the BitTorrent DHT bootstrap hosts (`dht.transmissionbt.com`, etc.) — those are real BitTorrent infrastructure and would false-positive on benign clients.
- **Mirai → `elf.mirai`** (1 live sample, resilient path covers stripped): a `.rodata` XOR pass — XOR candidate byte-runs by 0x22 (from key 0xDEADBEEF) and 0x54 (0xDEDEFBAF) and look for `{nameserver, administrator, listening, /bin/busybox}` in the decoded output; OR the NUL-embedded flood template `POST /cdn-cgi/\x00\x00 HTTP/1.1\r\nUser-Agent: \x00\r\nHost:` as a raw byte-pattern; OR the `/bin/busybox <TOKEN>` + `<TOKEN>: applet not found` pair. Un-stripped bonus: leaked-source symbols `table_init`/`table_unlock_val`/`resolve_cnc`/`util_local_addr` (corroborating, present in the 1 live sample).
- **Gafgyt/Bashlite → `elf.bashlite`**: the misspelled `gayfgt` busybox handshake (`echo -e 'gayfgt'`, literal or octal `\147\141\171\146\147\164`), OR `TELNET LOGIN CRACKED - %s:%s:%s` / `REPORT %s:%s:%s`, OR the `HOLD`+`JUNK` verb pair (Mirai uses numeric attack IDs, not these).
- **Tsunami/Kaiten → `elf.tsunami`**: `GETSPOOFS` AND (`TSUNAMI` OR `PAN`) AND an IRC marker (`NOTICE %s :` / `PRIVMSG`).
- **XMRig → tool tag `xmrig` (NOT a botnet family)**: `donate.v2.xmrig.com` / `donate.ssl.xmrig.com`, OR ≥2 of {`XMRig/%s libuv`, algo set `rx/0`+`cn/r`}. A miner is a tool, not a family — never attribute it to Mirai/Kinsing/etc. `Family` stays a coinminer tag, matching today's `xmrig`/`Coinminer` behaviour.

Lineage tie-break: if Mirai-specific tells co-occur with Bashlite-shared strings, prefer Mirai/Mozi.

## The danger list (hard-coded as forbidden anchors)

A named `var lowPrecisionMarkers` documents, in code, the signatures that must NEVER attribute alone — with a test that asserts a buffer containing ONLY these classifies as family-`unknown`: raw `0xDEADBEEF` (`EF BE AD DE`), bare `Mozilla/5.0…` UA, `8.8.8.8`, `/bin/busybox` alone, `TSource Engine Query`, bare `PING`/`PONG` (no bang), IRC verbs alone, BitTorrent-DHT bootstrap hosts, `stratum+tcp` alone, `argon2` alone, `Remote IRC Bot`. This is the account-safety guard: it stops a future edit from promoting a shared string to an attribution anchor.

## Packing detection

`isPackedELF(buf, path)` returns (packed bool, tags []string): `UPX!` magic (`55 50 58 21`) in header or tail; the tamper-markers `YTS`/`F5 96 A4 B5`; the `$Info: This file is packed with the UPX` banner; and a structural fallback — bimodal section entropy (one section ~0, one >7.2) or a Writable+Executable `PT_LOAD` via `debug/elf`. Packed ⇒ add `packed` (+`upx` on a UPX signal) to Tags, and SKIP family attribution unless a Tier-A cleartext anchor still matched (rare but possible for partial packing). This is fail-closed: keep the malicious verdict, withhold the guess.

## Implementation

- Rewrite `matchELFFamily(buf []byte) (family string, tags []string)` in `classify.go` around the Tier-A matchers + the XOR-decode pass + the danger-list guard.
- Add `isPackedELF` and wire the `packed`/`upx` tags into `classifyELF`.
- The 256 KiB scan window already exists; the XOR pass operates on that buffer (family strings live in the first data sections, well within 256 KiB — confirmed on the live samples).
- Keep the existing script-dropper path (`classifyScript`) unchanged — it already family-matches text droppers correctly.

## Testing

- **Synthetic byte-buffer fixtures** (`classify_family_test.go`): each family gets a minimal buffer — a valid ELF header prefix + the exact Tier-A signature bytes (including the XOR-encoded wordlist built programmatically, and the NUL-embedded template as raw bytes) — asserted to classify to the expected Malpedia-mapped family. This tests the matcher logic precisely without shipping malware (respects the repo's `check-utf8` no-binary convention; the matcher operates on `[]byte`, so a synthetic buffer is a faithful input).
- **False-positive guards**: buffers containing ONLY danger-list strings (BitTorrent-DHT blob, plain Mozilla-UA binary, bare `/bin/busybox`) MUST classify family-`unknown`. This is the account-safety test.
- **Packing test**: a UPX-magic buffer and a tampered-`YTS` buffer get the `packed`/`upx` tags and no family.
- **Live validation on arm** (not committed): run the built classifier over the real evidence dir; confirm the 5 Mozi + 1 Mirai now attribute and nothing previously-benign flips to a family. This is the end-to-end proof on real malware without committing any.
- Every Malpedia label the classifier can emit stays covered by `threatfox/malpedia_test.go` (add mozi/tsunami mappings there, re-verified against the live list).

## Compatibility

Go-only, one classifier function rewritten + tests. No schema, no config, no Cowrie change. Existing script-dropper families and ELF arch tags are unchanged. `threatfox/malpedia.go` gains `mozi→elf.mozi` and `tsunami→elf.tsunami` (verified), so the newly-attributed samples become ThreatFox-eligible.

## Out of scope

UPX decompression, running samples, non-ELF families, telfhash/imphash clustering, any submission-gate change (the gates already consume `Family` correctly).
