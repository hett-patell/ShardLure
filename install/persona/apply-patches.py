#!/usr/bin/env python3
"""Preflight and apply ShardLure's Cowrie source patches in fixed order."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


PATCHES = (
    "bashparse-subshell-pipe.py",
    "grep-case-insensitive.py",
    "honeypot-capture-redirect.py",
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
