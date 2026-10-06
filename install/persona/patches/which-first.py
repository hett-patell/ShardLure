#!/usr/bin/env python3
"""Patch cowrie/commands/which.py: which prints the first match, as debianutils does.

WHY (payload-yield Phase B Task 7; factsheet-phaseB 3 #13, 5 #7): v3.1.1's
which prints EVERY $PATH hit. 22.04 is usr-merged (/bin -> usr/bin), so root's
PATH finds each binary twice and `which ls` printed /usr/bin/ls AND /bin/ls.
The probe `ls -lh $(which ls)` (35 sessions in 30 days) then ran
`ls -lh /usr/bin/ls /bin/ls`, which Cowrie answered with
"ls: cannot access '/usr/bin/ls\\n/bin/ls'", and every exit status was 0.

Now a port of debianutils 5.5's /usr/bin/which (the 22.04 shell script):
  which NAME..   -> the first PATH entry holding a regular executable file
                    (`-f && -x`), printed as "$ELEMENT/$NAME"; an empty PATH
                    element is "."; a name with a slash is checked as given.
  which -a NAME  -> every match.
  exit status    -> 0 if every name was found, else 1; no names is 1.
  bad option     -> dash getopts' "Illegal option -x" on stderr, then
                    "Usage: /usr/bin/which [-a] args", exit 2.
Options stop at the first non-option word or `--`, as getopts does.

Shares commands/which.py with command-type-builtins.py: that patch anchors
on the registry line after this class, this one on the class body, so the
two blocks are disjoint and either applies with or without the other.
"""
import sys
from pathlib import Path

OLD = '''class Command_which(HoneyPotCommand):
    # Do not resolve args
    resolve_args = False

    def call(self) -> None:
        """
        Look up all the arguments on PATH and print each (first) result
        """

        # No arguments, just exit
        if not len(self.args) or "PATH" not in self.environ:
            return

        # Look up each file
        for f in self.args:
            for path in self.environ["PATH"].split(":"):
                resolved = self.fs.resolve_path(f, path)

                if self.fs.exists(resolved):
                    self.write(f"{path}/{f}\\n")
'''

NEW = '''class Command_which(HoneyPotCommand):
    """debianutils 5.5 which (ShardLure which-first.py): the first match only,
    every match with -a, exit 1 when a name is missing."""

    # Do not resolve args
    resolve_args = False

    def _executable(self, path: str) -> bool:
        # `[ -f P ] && [ -x P ]` as root: a regular file with any x bit.
        from cowrie.shell.fs import A_MODE

        if not self.fs.isfile(path):
            return False
        node = self.fs.getfile(path)
        return node is not None and bool(node[A_MODE] & 0o111)

    def call(self) -> None:
        args = list(self.args)
        all_matches = False
        while args and args[0].startswith("-") and args[0] != "-":
            opt = args.pop(0)
            if opt == "--":
                break
            for ch in opt[1:]:
                if ch != "a":
                    self.errorWrite(f"Illegal option -{ch}\\n")
                    self.write("Usage: /usr/bin/which [-a] args\\n")
                    self.exit_code = 2
                    return
                all_matches = True
        # debianutils: no names is a failure.
        self.exit_code = 0 if args else 1
        # A trailing ":" is a last, empty element (the current directory);
        # split() keeps it, as debianutils' PATH="$PATH:" fix-up does.
        path = self.environ.get("PATH", "")
        for name in args:
            found = False
            if "/" in name:
                if self._executable(self.fs.resolve_path(name, self.cwd)):
                    self.write(f"{name}\\n")
                    found = True
            else:
                for element in path.split(":"):
                    element = element or "."
                    if self._executable(self.fs.resolve_path(f"{element}/{name}", self.cwd)):
                        self.write(f"{element}/{name}\\n")
                        found = True
                        if not all_matches:
                            break
            if not found:
                self.exit_code = 1
'''

BLOCKS = ((OLD, NEW),)


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/commands/which.py"
    content = path.read_text(encoding="utf-8")
    counts = [(content.count(old), content.count(new)) for old, new in BLOCKS]
    if all(c == (0, 1) for c in counts):
        print(f"  [skip] {path}: already patched")
        return 0
    if not all(c == (1, 0) for c in counts):
        print(
            f"  [FAIL] {path}: target is neither pristine nor fully patched "
            f"(old/new counts {counts}) - upstream which changed",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    for old, new in BLOCKS:
        content = content.replace(old, new, 1)
    path.write_text(content, encoding="utf-8")
    print(f"  [ok] {path}: patched (which prints the first match)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
