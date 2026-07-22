#!/usr/bin/env python3
"""Patch cowrie/shell/honeypot.py: expose temp_pp in command-not-found redirect path.

When a command-not-found occurs with redirections (e.g. ./xx 2>&1) inside a
command substitution ($(...)), the error message was written to a temporary
PipeProtocol that nobody read. This patch assigns it to protocol.pp so the
capture shell can retrieve the redirected output.

Without this fix, $(./nonexistent 2>&1) returns empty instead of the error.
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
path = str(cowrie_home / "src/cowrie/shell/honeypot.py")
with open(path) as f:
    content = f.read()

OLD = """\
                    temp_pp.errReceived(message)
                    for real_path, virtual_path in temp_pp.redirect_real_files:"""

NEW = """\
                    temp_pp.errReceived(message)
                    if self.redirect:
                        self.protocol.pp = temp_pp
                    for real_path, virtual_path in temp_pp.redirect_real_files:"""

if "self.protocol.pp = temp_pp" in content:
    print(f"  [skip] {path}: already patched")
    sys.exit(0)
if OLD not in content:
    print(f"  [FAIL] {path}: target block not found", file=sys.stderr)
    sys.exit(1)

if check_only:
    print(f"  [check] {path}: compatible")
    sys.exit(0)

content = content.replace(OLD, NEW)
with open(path, 'w') as f:
    f.write(content)
print(f"  [ok] {path}: patched")
