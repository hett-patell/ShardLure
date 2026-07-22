#!/usr/bin/env python3
"""Patch cowrie/commands/fs.py: make grep -i actually case-insensitive.

Cowrie's grep parsed the -i flag but never applied it — the regex was always
compiled without re.IGNORECASE. This patch threads the flag through.
"""
import sys
from pathlib import Path

args = sys.argv[1:]
if (
    len(args) not in (1, 2)
    or not args[0]
    or args[0] == "--check"
    or (len(args) == 2 and args[1] != "--check")
):
    print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
    sys.exit(2)
check_only = len(args) == 2
cowrie_home = Path(args[0])
path = str(cowrie_home / "src/cowrie/commands/fs.py")
with open(path) as f:
    content = f.read()

if "self.ignore_case" in content:
    print(f"  [skip] {path}: already patched")
    sys.exit(0)

# Fix 1: grep_application — accept and use a case_insensitive flag
OLD_GREP_APP = """\
    def grep_application(self, contents: bytes, match: str) -> None:
        bmatch = os.path.basename(match).replace('"', "").encode("utf8")
        matches = re.compile(bmatch)"""

NEW_GREP_APP = """\
    def grep_application(self, contents: bytes, match: str) -> None:
        bmatch = os.path.basename(match).replace('"', "").encode("utf8")
        flags = re.IGNORECASE if self.ignore_case else 0
        matches = re.compile(bmatch, flags)"""

if OLD_GREP_APP not in content:
    print(f"  [FAIL] {path}: grep_application block not found", file=sys.stderr)
    sys.exit(1)

# Fix 2: start() — track -i flag
OLD_START_OPTS = """\
            for opt, _arg in optlist:
                if opt == "-h":
                    self.help()"""

NEW_START_OPTS = """\
            for opt, _arg in optlist:
                if opt == "-i":
                    self.ignore_case = True
                if opt == "-h":
                    self.help()"""

if OLD_START_OPTS not in content:
    print(f"  [FAIL] {path}: start() optlist block not found", file=sys.stderr)
    sys.exit(1)

# Fix 3: initialize ignore_case at the top of start()
OLD_START_BEGIN = """\
    def start(self) -> None:
        if not self.args:"""

NEW_START_BEGIN = """\
    def start(self) -> None:
        self.ignore_case = False
        if not self.args:"""

if OLD_START_BEGIN not in content:
    print(f"  [FAIL] {path}: start() begin block not found", file=sys.stderr)
    sys.exit(1)

if check_only:
    print(f"  [check] {path}: compatible")
    sys.exit(0)

content = content.replace(OLD_GREP_APP, NEW_GREP_APP)
content = content.replace(OLD_START_OPTS, NEW_START_OPTS)
content = content.replace(OLD_START_BEGIN, NEW_START_BEGIN)

with open(path, 'w') as f:
    f.write(content)
print(f"  [ok] {path}: patched")
