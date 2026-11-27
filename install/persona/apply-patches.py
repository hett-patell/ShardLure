#!/usr/bin/env python3
"""Preflight and apply ShardLure's Cowrie source patches in fixed order."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


PATCHES = (
    # Pinned Cowrie is v3.1.8 (install/cowrie.commit; moved from v3.1.1).
    # Patches upstream made redundant are gone for good: the grammar rewrite
    # in #40611 gave real subshell pipelines (bashparse-subshell-pipe),
    # f6f5f9fb routes command-not-found through the shell's stderr, so
    # `e=$(./x 2>&1)` captures it (honeypot-capture-redirect), and v3.1.2's
    # GNU exit statuses (9388a335) took two of cat-exit's three blocks. Where
    # an entry below names v3.1.1, that is where the fault was measured;
    # v3.1.8 still has it unless the entry says otherwise.
    #
    # Stealth hardening (2026-08-13): close the honeypot-detection gaps found in
    # live log analysis so bots proceed to payload delivery.
    # command-type-builtins is re-anchored on v3.1.1's getCommand(cmd, paths,
    # cwd): the pin-era text applied cleanly and then raised TypeError, hanging
    # every `command -v` session (scripts/behaviour command-v-wget catches it).
    "command-type-builtins.py",
    # which prints every PATH hit (v3.1.8 only added exit 1 for a missing
    # name); 22.04 is usr-merged, so `which ls` gave /usr/bin/ls and /bin/ls
    # and `ls -lh $(which ls)` failed. Shares which.py with
    # command-type-builtins on a disjoint anchor (class body).
    "which-first.py",
    "passwd-stdin.py",
    # v3.1.1 folds "too large" and "binary" into one refusal; only an
    # attacker's own binary, run directly, is answered with a silent exit 0.
    "exec-emulation.py",
    # scp droppers upload on one channel and run on the next; v3.1.1 rebuilt
    # the fake filesystem per channel, so the run found nothing (26 of 26 prod
    # scp sessions).
    "connection-shared-fs.py",
    # ...and Cowrie (v3.1.8 as v3.1.1) saves the upload under the C-record's
    # name, ignoring the `scp -t <path>` target the bot then runs. Upstream
    # main's d0855fb6 does the same; once released, only this patch's
    # trailing-slash refusal is left to keep.
    "scp-sink-target.py",
    # GNU ls -l dates: v3.1.1 prints the --time-style=long-iso form, a tell on
    # any `ls -l`, including a dropper listing the file it just uploaded.
    "ls-date-format.py",
    # ls -lh rounded to one decimal at every scale (135.0K); GNU rounds up
    # and drops the decimal from 10 on (135K). Disjoint from ls-date-format.
    "ls-human-size.py",
    # Persona commands (payload-yield Phase B). v3.1.8's grep gained -i -q -c
    # and exit 2, but still compiles every pattern as Python re (no BRE, -E
    # or -F), ignores -v -l -o -n -w -x -H -e, and has no time budget:
    # `grep -E '(a+)+$'` on a 41-byte line froze stock v3.1.8, every session,
    # for 13+ minutes. This is GNU grep 3.7 under a per-grep SIGALRM budget.
    "grep-options.py",
    # lspci is a registered command that shadows txtcmds/usr/bin/lspci with a
    # desktop AMD/GeForce board; the profiler's GPU field reads it (and
    # `busybox lspci`, which BusyBox 1.20.2 has no applet for).
    "lspci-persona.py",
    # v3.1.8's free reads the fake /proc/meminfo (v3.1.1 read the host's:
    # arm's 24 GB behind an 8 GB persona) but computes procps 4.0.2's used
    # (total - available): `free -m` said 1739 where 22.04's procps 3.3.17,
    # ported here, says 1527.
    "free-meminfo.py",
    # uname folded -m -p -i into one flag; GNU prints three fields, so a real
    # `uname -a` ends "x86_64 x86_64 x86_64 GNU/Linux" (~720 sessions/30d).
    "uname-a.py",
    # Persona time (Phase B Task 5): last printed the caller's own exec
    # session and none of the box's history; it now prints the persona's wtmp,
    # sessions anchored to now, reboot and wtmp begins at boot_time().
    "last-persona.py",
    # uptime and w: procps format, the fake /proc/loadavg, and w's rows from
    # last-persona's admin_session (so it must come after last-persona).
    # Command_w shares commands/base.py with passwd-stdin; disjoint anchors.
    "uptime-loadavg.py",
    # who printed the caller where w and last name the persona's ubuntu
    # session; it reads last-persona's helpers too (after last-persona).
    # A third disjoint block in commands/base.py.
    "who-persona.py",
    # 22.04 is usr-merged: /usr/bin/uname and /bin/uname are one file, but
    # Cowrie registers one spelling, so the other ran the pickle's ELF node
    # ("cannot execute binary file"). Shares shell/protocol.py with
    # connection-shared-fs; disjoint anchors.
    "usr-bin-aliases.py",
    # `cat -n` wrote two spaces where coreutils writes a TAB. (Its exit-status
    # blocks, `cat /x || fallback`, are upstream since v3.1.2.)
    "cat-exit.py",
    # crontab -l printed "no crontab for root" on stdout with exit 0; cron
    # writes it to stderr and exits 1 (it ended up inside droppers' crontabs).
    "crontab-list.py",
    # awk parsed only /regex/ patterns: `df -h | awk 'FNR == 2 {print $2;}'`
    # printed nothing. Comparison patterns and FNR, compared as mawk does.
    "awk-patterns.py",
    # `command -v python3` passes the bots' gate, then `python3 -c` hit "No
    # such file or directory". python3 answers as 22.04's: fake success,
    # never execution (the patch's docstring and test_python3_fake.py).
    "python3-emulation.py",
    # The shell parses on the single reactor thread, and v3.1.8 still parses
    # a $(...) body again on every evaluation (a 116-byte `while` line held
    # every session 22 s; nested $( froze all sessions 189 s live) and
    # re-parses a line-fed construct's whole pending text with each new line.
    # Every grammar run now goes through one budgeted entry (_lark_parse:
    # 30 s per connection, then refused): $(...) bodies reuse their enclosing
    # tree at all three sites, each connection remembers recent results
    # (backtick bodies have no tree to reuse), nesting past 16 is refused
    # before the grammar runs, and a RecursionError fails one parse
    # (production nests at most 6).
    "shell-parse-bounds.py",
    # The live daemon uses a separate account with read access via this group.
    # scripts/install.sh fetches this one file standalone, so it must stay in
    # PATCHES and apply on the pin (test_release_contracts and
    # check-cowrie-patches.sh's install_sh_patches enforce both).
    "sftp-capture-permissions.py",
)


def main() -> int:
    args = sys.argv[1:]
    if (
        len(args) not in (1, 2)
        or not args[0]
        or args[0] == "--check"
        or (len(args) == 2 and args[1] != "--check")
    ):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2

    cowrie_home = args[0]
    check_only = len(args) == 2
    patches_dir = Path(__file__).resolve().parent / "patches"

    first_failure = 0
    for name in PATCHES:
        patch = patches_dir / name
        proc = subprocess.run(
            [sys.executable, str(patch), cowrie_home, "--check"],
            check=False,
        )
        if proc.returncode != 0 and first_failure == 0:
            first_failure = proc.returncode
    if first_failure != 0:
        print("[cowrie-patches] preflight failed; no patches were applied", file=sys.stderr)
        return first_failure

    if check_only:
        print("[cowrie-patches] all patch preflights passed")
        return 0

    for name in PATCHES:
        patch = patches_dir / name
        proc = subprocess.run(
            [sys.executable, str(patch), cowrie_home],
            check=False,
        )
        if proc.returncode != 0:
            return proc.returncode
    print("[cowrie-patches] all patches applied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
