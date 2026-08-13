# Cowrie stealth hardening — design

**Date:** 2026-08-13
**Status:** approved, implementing
**Goal:** raise honeypot capture fidelity so automated bots that currently detect Cowrie's shell proceed to their payload-delivery stage, increasing what ShardLure captures.

## Motivation (from live log analysis)

Analysis of ~214k sessions on the arm deployment showed traffic is ~99.6% automated. Several bot families run honeypot-detection probes and disengage before dropping a payload. The failed-command census exposed the exact gaps:

| Probe | Fails observed | What it is |
|---|---|---|
| `command -v python3` / `! command -v curl` | 482 | tool-presence gate before the download stage |
| `echo -e "p\np\np" \| passwd` | 89 | prompt desync — `Enter new UNIX password:` echoed as next command |
| `./xxxxxx`, `scp -t /bin/<rand>` → run | ~15 sessions | execute-a-binary honeypot test |
| persona clock | n/a | motd frozen at 2026-05-19, 86 days stale vs live `date` |

Two observed "fails" are deliberately **out of scope** because fixing them would reduce realism: `lockr -ia .ssh` (376 — not a standard tool; a real box also fails it, and bots ignore it) and the 6,010 `uname → quit` sessions (one-shot recon triage, not detection).

## Hard boundary

ShardLure must **never actually execute an attacker-supplied binary.** Doing so converts the honeypot into a live malware-execution host (outbound C2, propagation, legal/ISP exposure). "Fake success" in unit 3 is a canned exit-0 with no process spawned — not execution. The captured payload is obtained at the *download* step (SafeFetcher), which precedes every exec test, so no capture is lost by refusing real execution.

## Approach

Extend the existing deploy-time patch + persona system (`install/persona/`). New patches follow the established idempotent, `--check`-preflighted style of the three current patches and register in `apply-patches.py`'s `PATCHES` tuple. Rejected alternatives: config/txtcmds-only (cannot implement `command`/`type`, which require code) and forking Cowrie (unmaintainable).

## Units

### 1. `patches/command-type-builtins.py` — the download-gate (482 fails)
Cowrie ships no `command` or `type` builtin, and `which` resolves only against PATH in the fake FS. The fake FS already contains `/usr/bin/{python3,curl,wget,perl,…}`, so the tools "exist"; the resolver is just unwired. Implement `command -v NAME` / `command -V NAME` / `type NAME` to resolve against `$PATH` + the command registry and print the resolved path with exit 0, or nothing with exit 1 — byte-matching bash. Effect: profiler bots clear the gate and proceed to download.

### 2. `patches/passwd-stdin.py` — prompt desync (89 fails)
Cowrie's `passwd` writes `Enter new UNIX password:` to stdout; the shell consumes the next piped line as a command (the tell). Patch it to drain piped stdin and emit the standard success flow (`passwd: password updated successfully`) without desyncing, so `echo -e "…"|passwd` behaves like a real box.

### 3. `patches/exec-emulation.py` — exec fidelity + scoped fake-success
(a) **Fidelity:** byte-exact bash errors and exit codes for run attempts — `-bash: ./x: No such file or directory` (127), `-bash: ./x: Permission denied` (126) — so `./xxxxxx` reads as a normal locked-down box.
(b) **Scoped fake-success:** when the attacker runs a file **written during this same session** (scp/wget into a writable path) that has been chmod'd executable, return exit 0 / no output instead of an error. Scoped to session-written files only, because faking success on *every* binary is itself a tell. No process is spawned; the artifact was already captured at download.

### 4. `gen-time-persona.py` extension — the 86-day clock tell
Add `honeyfs/etc/motd` (and a scan for any other absolute-date-bearing persona file) to the deploy-time regeneration so `date`, `uptime`, `last`, `who`, and motd all track the live clock and agree. Highest-value single fix: it is the tell seen before the attacker types anything.

## Data flow / integration

```
deploy → apply-patches.py --check (preflight all)
       → apply-patches.py (bashparse, grep, capture-redirect, command-type, passwd-stdin, exec-emulation)
       → gen-time-persona.py COWRIE_HOME   (now also rewrites motd)
       → systemctl restart cowrie
```

No change to ShardLure's Go side, the JSON-log contract, or the ingest path. These are Cowrie-source and persona-file changes only.

## Testing

- Every patch ships a `--check` preflight that verifies idempotency (already-applied → clean exit) and the presence of its anchor text (fails loudly if upstream Cowrie moved the code).
- Probe-replay: apply patches to a *copy* of the deployed tree, drive the exact probes (`command -v python3`, `echo -e|passwd`, `./xxxxxx`, scp+run), assert byte-exact output and exit codes before touching live.
- Persona: internal-consistency assertion — boot instant, uptime seconds, and `last` weekdays all agree.

## Deploy & verify (live, approved)

1. Back up the deployed cowrie tree on arm.
2. Apply patches to a throwaway copy; run probe-replay.
3. On pass: apply to the live tree, regen persona, `systemctl restart cowrie`.
4. Watch live traffic for the profiler family proceeding past the `command -v` gate into downloads.
All transfer via tar/stdin-over-SSH (never scp — UTF-16 corruption rule); patch files UTF-8-clean for `check-utf8.sh`.

## Out of scope

`lockr` handling, `uname→quit` recon, real binary execution, any ShardLure Go-side change.
