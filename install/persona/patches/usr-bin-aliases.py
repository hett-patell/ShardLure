#!/usr/bin/env python3
"""Patch cowrie/shell/protocol.py: every registered /bin/X also answers as /usr/bin/X.

WHY (payload-yield Phase B Task 7; factsheet-phaseB 2 UNAME, 5 #14): Ubuntu
22.04 is usr-merged. /bin, /sbin and /lib are symlinks into /usr, so
/bin/uname and /usr/bin/uname are one file, and the pinned pickle agrees
(/bin -> usr/bin). Cowrie's command registry spells each command one way
only. `uname` is registered as uname and /bin/uname, so `/usr/bin/uname`
resolved to the pickle's ELF node and answered "cannot execute binary file:
Exec format error" (rc 126). The same happened to /usr/bin/bash, /usr/bin/cat
and /usr/bin/grep, and to /bin/curl and /bin/wget the other way. The
profiler's own UNAME fallback chain tries `/bin/uname || /usr/bin/uname`,
and droppers run `/usr/bin/bash -c ...`.

After the registry is built, every /bin/X or /sbin/X entry gains its
/usr/bin/X or /usr/sbin/X twin, and every /usr/... entry gains its short
twin. An existing registration is never replaced (setdefault), so where
upstream registers both spellings, each keeps its own class.
"""
import sys
from pathlib import Path

OLD = '''    commands: ClassVar[dict] = {}
    for c in cowrie.commands.command_modules:
        try:
            module = import_module(f"cowrie.commands.{c}")
            commands.update(module.commands)
        except ImportError:
            _log.failure("Failed to import command {cmd}", cmd=c)

    def __init__(self, avatar):
'''

# NEW inserts the alias loop between the registry loop and __init__, so OLD
# (which runs up to __init__) does not survive inside NEW.
NEW = '''    commands: ClassVar[dict] = {}
    for c in cowrie.commands.command_modules:
        try:
            module = import_module(f"cowrie.commands.{c}")
            commands.update(module.commands)
        except ImportError:
            _log.failure("Failed to import command {cmd}", cmd=c)
    # ShardLure (install/persona/patches/usr-bin-aliases.py): 22.04 is
    # usr-merged, so /bin/X and /usr/bin/X are one file; a command registered
    # under one spelling answers to the other (/usr/bin/uname ran the
    # pickle's ELF node: "cannot execute binary file"). Never replaces an
    # existing registration. Plain loops: a class-body comprehension cannot
    # see `commands`.
    for _shardlure_name in list(commands):
        for _shardlure_short, _shardlure_long in (("/bin/", "/usr/bin/"), ("/sbin/", "/usr/sbin/")):
            if _shardlure_name.startswith(_shardlure_short):
                commands.setdefault(
                    _shardlure_long + _shardlure_name[len(_shardlure_short):],
                    commands[_shardlure_name])
            elif _shardlure_name.startswith(_shardlure_long):
                commands.setdefault(
                    _shardlure_short + _shardlure_name[len(_shardlure_long):],
                    commands[_shardlure_name])

    def __init__(self, avatar):
'''

BLOCKS = ((OLD, NEW),)


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/shell/protocol.py"
    content = path.read_text(encoding="utf-8")
    counts = [(content.count(old), content.count(new)) for old, new in BLOCKS]
    if all(c == (0, 1) for c in counts):
        print(f"  [skip] {path}: already patched")
        return 0
    if not all(c == (1, 0) for c in counts):
        print(
            f"  [FAIL] {path}: target is neither pristine nor fully patched "
            f"(old/new counts {counts}) - upstream protocol changed",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    for old, new in BLOCKS:
        content = content.replace(old, new, 1)
    path.write_text(content, encoding="utf-8")
    print(f"  [ok] {path}: patched (/bin and /usr/bin spellings alias)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
