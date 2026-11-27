#!/usr/bin/env python3
"""Patch cowrie/commands/cat.py: GNU cat's `-n` column.

WHY (payload-yield Phase B Task 7; factsheet-phaseB 5 #16): `cat -n` numbers
lines as "%6d\t" (coreutils' next_line_num). Cowrie writes two spaces
instead of the TAB, so `echo Hi | cat -n` (25 sessions in 30 days) printed
"     1  Hi" where a real box prints "     1<TAB>Hi". The pinned v3.1.8 still
does.

History: on v3.1.1 this patch also made cat exit 1 on a bad option, a
missing file and a directory operand (GNU cat 8.32; a probe's
`cat /etc/os-release || cat /etc/issue` never fell back). Upstream fixed
exactly that in 9388a335 (#40662, v3.1.2), so those two blocks are gone and
only the `-n` column is left. The file keeps its name so the PATCHES entry
and its history stay traceable.
"""
import sys
from pathlib import Path

# output(): the line-number column of `cat -n`. Named OLD/NEW because
# check-cowrie-patches.sh's drift fixture and test_release_contracts read
# every active patch's OLD (it was OLD_NUMBER beside two dropped blocks).
OLD = r'''                self.write(f"{self.linenumber:>6}  ")
'''

NEW = r'''                # coreutils prints "%6d\t" (ShardLure cat-exit.py).
                self.write(f"{self.linenumber:>6}\t")
'''

BLOCKS = ((OLD, NEW),)


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/commands/cat.py"
    content = path.read_text(encoding="utf-8")
    counts = [(content.count(old), content.count(new)) for old, new in BLOCKS]
    if all(c == (0, 1) for c in counts):
        print(f"  [skip] {path}: already patched")
        return 0
    if not all(c == (1, 0) for c in counts):
        print(
            f"  [FAIL] {path}: target is neither pristine nor fully patched "
            f"(old/new counts {counts}) - upstream cat changed",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    for old, new in BLOCKS:
        content = content.replace(old, new, 1)
    path.write_text(content, encoding="utf-8")
    print(f"  [ok] {path}: patched (cat -n writes a TAB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
