#!/usr/bin/env python3
"""Patch cowrie/commands/crontab.py: "no crontab" goes to stderr, exit 1.

WHY (payload-yield Phase B Task 7; factsheet-phaseB 3 #14): cron 3.0pl1's
crontab (Ubuntu 22.04) answers `crontab -l` and `crontab -r` for a user with
no crontab by printing "no crontab for root" on stderr and exiting 1
(crontab.c: fprintf(stderr, ...); exit(ERROR_EXIT)). Its usage errors go to
stderr with exit 1 too. v3.1.1 wrote all of these to stdout and exited 0.

`crontab -l` (35 sessions in 30 days) is a probe in itself. Its stdout also
matters for persistence droppers: `(crontab -l 2>/dev/null; echo "* * * * *
/tmp/x") | crontab -` pipes it into the new crontab, so on Cowrie the line
"no crontab for root" ended up inside the attacker's own job list.
"""
import sys
from pathlib import Path

OLD = '''        except getopt.GetoptError as err:
            self.write(f"crontab: invalid option -- '{err.opt}'\\n")
            self.write("crontab: usage error: unrecognized option\\n")
            self.help()
            self.exit()
            return
'''

NEW = '''        except getopt.GetoptError as err:
            # ShardLure (crontab-list.py): cron's usage() writes to stderr and
            # exits 1.
            self.errorWrite(f"crontab: invalid option -- '{err.opt}'\\n")
            self.errorWrite("crontab: usage error: unrecognized option\\n")
            self.write = self.errorWrite  # help() below goes to stderr too
            self.help()
            self.exit(1)
            return
'''

OLD_LIST = '''        elif opt in ["-l", "-r", "-i"]:
            self.write(f"no crontab for {user}\\n")
            self.exit()
            return
'''

NEW_LIST = '''        elif opt in ["-l", "-r", "-i"]:
            # ShardLure (crontab-list.py): cron prints this on stderr and
            # exits 1, so `(crontab -l 2>/dev/null; echo job) | crontab -`
            # does not copy it into the new crontab.
            self.errorWrite(f"no crontab for {user}\\n")
            self.exit(1)
            return
'''

BLOCKS = ((OLD, NEW), (OLD_LIST, NEW_LIST))


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/commands/crontab.py"
    content = path.read_text(encoding="utf-8")
    counts = [(content.count(old), content.count(new)) for old, new in BLOCKS]
    if all(c == (0, 1) for c in counts):
        print(f"  [skip] {path}: already patched")
        return 0
    if not all(c == (1, 0) for c in counts):
        print(
            f"  [FAIL] {path}: target is neither pristine nor fully patched "
            f"(old/new counts {counts}) - upstream crontab changed",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    for old, new in BLOCKS:
        content = content.replace(old, new, 1)
    path.write_text(content, encoding="utf-8")
    print(f"  [ok] {path}: patched (no crontab: stderr, exit 1)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
