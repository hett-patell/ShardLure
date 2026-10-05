#!/usr/bin/env python3
"""Patch cowrie/commands/uname.py: -m, -p and -i are three fields.

WHY (payload-yield Phase B Task 6; factsheet-phaseB 3 #3, 5 #8): on Ubuntu
22.04 x86_64, `uname -a` ends "x86_64 x86_64 x86_64 GNU/Linux": GNU uname
prints the machine (-m), processor (-p) and hardware platform (-i) as three
fields, and on that box all three are "x86_64". v3.1.1 folds -m -p -i into
one "machine" flag, so its `uname -a` ends "x86_64 GNU/Linux", a one-glance
difference on the second most common probe on prod (`uname -a`, ~720
sessions in 30 days from 15 actors).

Each of the three now has its own flag, printed in GNU's order (-s -n -r -v
-m -p -i -o), so `uname -a`, `uname -m -p -i` and `uname -mi` all match the
real box. All three print [shell] hardware_platform, as -m already did; the
persona sets it to x86_64. Preferred over setting hardware_platform to
"x86_64 x86_64 x86_64", which would break `uname -m` and the profiler's ARCH
line.
"""

import sys
from pathlib import Path

# The flags dict, the -m/-p/-i flag row and the machine output line.
OLD = r'''            "node": False,
            "machine": False,
        }
'''

NEW = r'''            "node": False,
            "machine": False,
            # ShardLure persona (uname-a.py): -p and -i print on their own.
            "processor": False,
            "platform": False,
        }
'''

OLD_FLAGS = r'''            (["m", "machine", "p", "processor", "i", "hardware-platform"], "machine"),
'''

NEW_FLAGS = r'''            (["m", "machine"], "machine"),
            (["p", "processor"], "processor"),
            (["i", "hardware-platform"], "platform"),
'''

OLD_OUT = r'''        if opts["machine"]:
            output.append(hardware_platform())
        if opts["os"]:
'''

NEW_OUT = r'''        if opts["machine"]:
            output.append(hardware_platform())
        # GNU uname's order is -s -n -r -v -m -p -i -o; on x86_64 Ubuntu all
        # three of -m -p -i are "x86_64", so -a prints it three times.
        if opts["processor"]:
            output.append(hardware_platform())
        if opts["platform"]:
            output.append(hardware_platform())
        if opts["os"]:
'''

BLOCKS = ((OLD, NEW), (OLD_FLAGS, NEW_FLAGS), (OLD_OUT, NEW_OUT))


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/commands/uname.py"
    content = path.read_text(encoding="utf-8")
    counts = [(content.count(old), content.count(new)) for old, new in BLOCKS]
    if all(c == (0, 1) for c in counts):
        print(f"  [skip] {path}: already patched")
        return 0
    if not all(c == (1, 0) for c in counts):
        print(
            f"  [FAIL] {path}: target is neither pristine nor fully patched "
            f"(old/new counts {counts}) - upstream uname changed",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    for old, new in BLOCKS:
        content = content.replace(old, new, 1)
    path.write_text(content, encoding="utf-8")
    print(f"  [ok] {path}: patched (uname -m -p -i as three fields)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
