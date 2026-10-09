#!/usr/bin/env python3
"""Patch cowrie/commands/ls.py: GNU ls -l dates instead of ISO dates.

WHY: Cowrie v3.1.1's `ls -l` prints every timestamp as `2026-10-05 17:51`
(time.strftime("%Y-%m-%d %H:%M")). GNU ls on Ubuntu 22.04 prints that form
only with --time-style=long-iso; its default, in the C and en_US locales the
persona speaks, is
    "%b %e %H:%M"   (Oct  5 17:51)  for a time within the last six months
    "%b %e  %Y"     (Jan 10  2024)  otherwise (older, or in the future)
so any `ls -l` is a one-line honeypot tell. It matters most right after an
scp upload: a dropper that lists the file it just wrote (scripts/behaviour
scp-cross-channel) sees the ISO stamp beside a correct size.

Fix: format with GNU's rule (coreutils ls.c: recent iff six months ago <
time <= now, six months = 31556952 / 2 s). Only the date column changes;
sizes, owners, names and the rest of the line are untouched.
"""
import sys
from pathlib import Path


OLD = """\
                formatted_sizes[i].rjust(filesize_str_extent),
                time.strftime("%Y-%m-%d %H:%M", ctime),
"""

NEW = """\
                formatted_sizes[i].rjust(filesize_str_extent),
                # ShardLure (install/persona/patches/ls-date-format.py): GNU
                # ls's default dates; the ISO form is --time-style=long-iso.
                time.strftime(
                    "%b %e %H:%M"
                    if time.time() - 15778476 < file[fs.A_CTIME] <= time.time()
                    else "%b %e  %Y",
                    ctime,
                ),
"""


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/commands/ls.py"
    content = path.read_text(encoding="utf-8")
    old_count, new_count = content.count(OLD), content.count(NEW)
    if old_count == 0 and new_count == 1:
        print(f"  [skip] {path}: already patched")
        return 0
    if old_count != 1 or new_count != 0:
        print(f"  [FAIL] {path}: target is neither pristine nor fully patched", file=sys.stderr)
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    path.write_text(content.replace(OLD, NEW, 1), encoding="utf-8")
    print(f"  [ok] {path}: patched (GNU ls -l dates)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
