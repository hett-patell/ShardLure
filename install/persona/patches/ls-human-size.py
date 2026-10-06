#!/usr/bin/env python3
"""Patch cowrie/commands/ls.py: `ls -lh` sizes in GNU's human-readable form.

WHY (payload-yield Phase B Task 7; factsheet-phaseB 3 #13): GNU ls -h rounds
UP (human_ceiling) and shows one decimal only below 10: 22.04's 138216-byte
/usr/bin/ls is `135K`, a 4096-byte directory `4.0K`, and 1048575 bytes
`1.0M`. v3.1.1 printed `size / 1024` with one decimal at every scale
(`135.0K`, `147.8K`, `100.0M`), a tell on the probe `ls -lh $(which ls)`
(35 sessions in 30 days) and on any `ls -lh` an operator runs. Every value
below was checked with ubuntu:22.04 `ls -lh` on truncated files of that
size: 0..1023 -> N, 1024 -> 1.0K, 1025 -> 1.1K, 10239 -> 10K, 10241 -> 11K,
138216 -> 135K, 1048575 -> 1.0M, 1572864 -> 1.5M, 5000000000 -> 4.7G.
"""
import sys
from pathlib import Path

OLD = '''            if self.showHumanReadable:
                for x in files:
                    size = x[fs.A_SIZE]  # Original size
                    if size >= 1024 * 1024 * 1024:
                        formatted_size = f"{size / 1024 / 1024 / 1024:.1f}G"
                    elif size >= 1024 * 1024:
                        formatted_size = f"{size / 1024 / 1024:.1f}M"
                    elif size >= 1024:
                        formatted_size = f"{size / 1024:.1f}K"
                    else:
                        formatted_size = str(size)

                    formatted_sizes.append(formatted_size)
'''

NEW = '''            if self.showHumanReadable:
                # ShardLure (install/persona/patches/ls-human-size.py): GNU
                # human_readable() with human_ceiling, in integer arithmetic:
                # round up, one decimal below 10, the next unit at 1024.
                def _gnu_human(size: int) -> str:
                    if size < 1024:
                        return str(size)
                    for exp, unit in enumerate("KMGTPE", 1):
                        div = 1024**exp
                        tenths = -(-size * 10 // div)
                        if tenths < 100:
                            return f"{tenths // 10}.{tenths % 10}{unit}"
                        whole = -(-size // div)
                        if whole < 1024:
                            return f"{whole}{unit}"
                    return f"{-(-size // 1024**6)}E"

                for x in files:
                    formatted_sizes.append(_gnu_human(x[fs.A_SIZE]))
'''

BLOCKS = ((OLD, NEW),)


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/commands/ls.py"
    content = path.read_text(encoding="utf-8")
    counts = [(content.count(old), content.count(new)) for old, new in BLOCKS]
    if all(c == (0, 1) for c in counts):
        print(f"  [skip] {path}: already patched")
        return 0
    if not all(c == (1, 0) for c in counts):
        print(
            f"  [FAIL] {path}: target is neither pristine nor fully patched "
            f"(old/new counts {counts}) - upstream ls changed",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    for old, new in BLOCKS:
        content = content.replace(old, new, 1)
    path.write_text(content, encoding="utf-8")
    print(f"  [ok] {path}: patched (GNU human-readable sizes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
