#!/usr/bin/env python3
"""Preflight and apply ShardLure's Cowrie source patches in fixed order."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


PATCHES = (
    # Pinned Cowrie is v3.1.1 (install/cowrie.commit). Two former patches are
    # gone for good because upstream fixed the same faults: the grammar rewrite
    # in #40611 gave real subshell pipelines (bashparse-subshell-pipe), and
    # f6f5f9fb routes command-not-found through the shell's stderr, so
    # `e=$(./x 2>&1)` captures it (honeypot-capture-redirect).
    #
    # Stealth hardening (2026-08-13): close the honeypot-detection gaps found in
    # live log analysis so bots proceed to payload delivery.
    # command-type-builtins is re-anchored on v3.1.1's getCommand(cmd, paths,
    # cwd): the pin-era text applied cleanly and then raised TypeError, hanging
    # every `command -v` session (scripts/behaviour command-v-wget catches it).
    "command-type-builtins.py",
    "passwd-stdin.py",
    # v3.1.1 folds "too large" and "binary" into one refusal; only an
    # attacker's own binary, run directly, is answered with a silent exit 0.
    "exec-emulation.py",
    # scp droppers upload on one channel and run on the next; v3.1.1 rebuilt
    # the fake filesystem per channel, so the run found nothing (26 of 26 prod
    # scp sessions).
    "connection-shared-fs.py",
    # ...and v3.1.1 saved the upload under the C-record's name, ignoring the
    # `scp -t <path>` target the bot then runs.
    "scp-sink-target.py",
    # GNU ls -l dates: v3.1.1 prints the --time-style=long-iso form, a tell on
    # any `ls -l`, including a dropper listing the file it just uploaded.
    "ls-date-format.py",
    # Persona commands (payload-yield Phase B). grep honours -i -q -c -v -l -o
    # and GNU's exit status (supersedes grep-case-insensitive, whose anchor
    # v3.1.1 refactored away): the profiler's `lspci | grep -i vga` GPU probe.
    "grep-options.py",
    # lspci is a registered command that shadows txtcmds/usr/bin/lspci with a
    # desktop AMD/GeForce board; the profiler's GPU field reads it (and
    # `busybox lspci`, which BusyBox 1.20.2 has no applet for).
    "lspci-persona.py",
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
