#!/usr/bin/env python3
"""Patch cowrie/commands/base.py: make `passwd` read piped stdin.

WHY (measured on the arm deployment): 89 failed-command events were the literal
string `Enter new UNIX password:`. A bot family runs
`echo -e "new\\nnew\\nnew" | passwd` to reset root's password. Cowrie's passwd
only handles the INTERACTIVE path: start() writes the prompt and flips the shell
into password_input mode waiting for lineReceived. With piped input there is no
interactive line — the prompt is emitted to the shell, which then parses
"Enter new UNIX password:" as the NEXT command and fails it. That failed command
is the honeypot tell.

Fix: when input_data is present (piped), drive the SAME ask_again/finish
callbacks from the piped lines, so the whole exchange stays inside passwd and the
shell never sees a stray prompt. Output matches real bash and Cowrie's own
test_base_commands.py expectation:
  "Enter new UNIX password: Retype new UNIX password: passwd: password updated successfully"
The interactive path is untouched.
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
path = str(cowrie_home / "src/cowrie/commands/base.py")
with open(path) as f:
    content = f.read()

OLD = '''    def start(self) -> None:
        self.write("Enter new UNIX password: ")
        self.protocol.password_input = True
        self.callbacks = [self.ask_again, self.finish]
        self.passwd = None'''

NEW = '''    def start(self) -> None:
        self.callbacks = [self.ask_again, self.finish]
        self.passwd = None
        # Piped invocation (echo -e "p\\np" | passwd): real passwd reads its
        # lines from stdin. Cowrie's interactive path leaked the prompt to the
        # shell, which parsed it as a command (89 failed-command tells on the
        # arm box). Drive the same callbacks from the piped lines so the
        # exchange stays inside passwd. Prompts are still written so the
        # captured output matches a real terminal.
        if self.input_data is not None:
            lines = self.input_data.split(b"\\n")
            self.write("Enter new UNIX password: ")
            first = lines[0].decode("utf8", "replace") if len(lines) > 0 else ""
            self.ask_again(first)
            second = lines[1].decode("utf8", "replace") if len(lines) > 1 else ""
            self.finish(second)
            return
        self.write("Enter new UNIX password: ")
        self.protocol.password_input = True'''

if NEW in content:
    print(f"  [skip] {path}: already patched")
    sys.exit(0)

if content.count(OLD) != 1:
    print(
        f"  [FAIL] {path}: passwd start() anchor not found exactly once "
        f"(count={content.count(OLD)}) — upstream base.py changed",
        file=sys.stderr,
    )
    sys.exit(1)

if check_only:
    print(f"  [check] {path}: compatible")
    sys.exit(0)

content = content.replace(OLD, NEW, 1)
with open(path, "w") as f:
    f.write(content)
print(f"  [ok] {path}: patched (passwd reads piped stdin)")
