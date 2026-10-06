#!/usr/bin/env python3
"""Patch cowrie/commands/cat.py: GNU cat's exit status and `-n` column.

WHY (payload-yield Phase B Task 7; factsheet-phaseB 5 #16): v3.1.1's cat
always exits 0. On a missing file it prints "No such file or directory" and
still succeeds, so a probe's fallback chain never falls back:
`cat /etc/os-release || cat /etc/issue`, `cat /proc/x 2>/dev/null || echo
none`. A directory operand and an invalid option behave the same way. GNU
cat 8.32 exits 1 in all three cases, and it still prints every readable
operand (`cat /nope /etc/hostname` prints the hostname, exit 1).

`cat -n` numbers lines as "%6d\t" (coreutils' next_line_num). Cowrie wrote
two spaces instead of the TAB, so `echo Hi | cat -n` (25 sessions in 30
days) printed "     1  Hi" where a real box prints "     1<TAB>Hi".
"""
import sys
from pathlib import Path

OLD_OPT = r'''        except getopt.GetoptError as err:
            self.errorWrite(
                f"cat: invalid option -- '{err.opt}'\nTry 'cat --help' for more information.\n"
            )
            self.exit()
            return
'''

NEW_OPT = r'''        except getopt.GetoptError as err:
            # ShardLure (cat-exit.py): GNU cat exits 1 on a bad option.
            self.errorWrite(
                f"cat: invalid option -- '{err.opt}'\nTry 'cat --help' for more information.\n"
            )
            self.exit(1)
            return
'''

OLD = r'''        if len(args) > 0:
            for arg in args:
                if arg == "-":
                    self.output(self.input_data)
                    continue

                pname = self.fs.resolve_path(arg, self.cwd)

                if self.fs.isdir(pname):
                    self.errorWrite(f"cat: {arg}: Is a directory\n")
                    continue

                try:
                    contents = self.fs.file_contents(pname)
                    self.output(contents)
                except FileNotFound:
                    self.errorWrite(f"cat: {arg}: No such file or directory\n")
            self.exit()
'''

NEW = r'''        if len(args) > 0:
            # ShardLure (cat-exit.py): every operand is still printed, but one
            # that could not be read makes cat exit 1, as GNU cat does, so a
            # `cat /missing || fallback` chain falls back.
            failed = False
            for arg in args:
                if arg == "-":
                    self.output(self.input_data)
                    continue

                pname = self.fs.resolve_path(arg, self.cwd)

                if self.fs.isdir(pname):
                    self.errorWrite(f"cat: {arg}: Is a directory\n")
                    failed = True
                    continue

                try:
                    contents = self.fs.file_contents(pname)
                    self.output(contents)
                except FileNotFound:
                    self.errorWrite(f"cat: {arg}: No such file or directory\n")
                    failed = True
            self.exit(1 if failed else 0)
'''

OLD_NUMBER = r'''                self.write(f"{self.linenumber:>6}  ")
'''

NEW_NUMBER = r'''                # coreutils prints "%6d\t" (ShardLure cat-exit.py).
                self.write(f"{self.linenumber:>6}\t")
'''

BLOCKS = ((OLD_OPT, NEW_OPT), (OLD, NEW), (OLD_NUMBER, NEW_NUMBER))


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
    print(f"  [ok] {path}: patched (GNU exit status and -n column)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
