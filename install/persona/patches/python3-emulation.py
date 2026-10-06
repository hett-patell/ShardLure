#!/usr/bin/env python3
"""Patch cowrie/commands/python.py: python3 answers as 22.04's, and never runs anything.

WHY (payload-yield Phase B Task 7, controller ruling after the Task 7 review):
the observed tool gate is `command -v python3` (factsheet-phaseB 3 #7), and
it passes. The bot's next step is `python3 -c '...'`, which v3.1.1 answered
`bash: line 1: /usr/bin/python3: No such file or directory` (rc 127): Cowrie
registers only python (2.7) and the pickle's python3 node has no content. A
gate that passes followed by an interpreter that is not there is a tell at
the payload step.

FAKE SUCCESS, NEVER EXECUTION. Attacker Python is never executed, parsed,
compiled or imported, here or anywhere: Command_python3 only looks at its
options, as exec-emulation.py only looks at whether an upload is a binary.
  python3 --version / -V   -> "Python 3.10.12" (22.04's 3.10.12-1~22.04.3);
                              -VV adds the build line
  python3 -h / --help      -> 22.04's help text, verbatim
  python3 -c CODE, -m MOD  -> exit 0, no output
  python3 FILE             -> exit 0, no output when FILE exists in the fake
                              fs; python3's own "can't open file" (rc 2) or
                              "can't find '__main__'" (rc 1) otherwise
  bad option / missing arg -> python3's usage error, rc 2
  python3 with no program  -> piped stdin is consumed; on a terminal the 22.04
                              REPL banner and `>>> ` prompts, exit on EOF or
                              exit(); stdin lines are logged, never evaluated
Capture is unchanged: Cowrie logs the whole command line (any URL in the -c
text) as cowrie.command.input before the command runs, and ShardLure's
capture runner extracts URLs from it. What this costs: a -c that would print
(`python3 -c 'print(1)'`) prints nothing. install/persona/test_python3_fake.py
proves nothing is executed (a -c that would touch a file on the host leaves
none) and that the class has no route to eval/exec/compile/import/subprocess.

The pickle's /usr/bin/python3 pointed at python3.11, which 22.04 does not
ship; apply_persona_fs (scripts/shardlure.py) makes it python3.10.
"""
import sys
from pathlib import Path

OLD = r'''    def eofReceived(self) -> None:
        self.exit()


commands["/usr/bin/python"] = Command_python
commands["python"] = Command_python
'''

NEW = r'''    def eofReceived(self) -> None:
        self.exit()


# --- ShardLure (install/persona/patches/python3-emulation.py) ---------------
class Command_python3(HoneyPotCommand):
    """python3 as Ubuntu 22.04 ships it (ShardLure python3-emulation.py).

    FAKE SUCCESS, NEVER EXECUTION. Nothing an attacker hands python3 is ever
    run, parsed, compiled or imported: the -c text, a script file, a -m
    module and stdin are not even read for meaning. python3 answers the
    things a real interpreter answers without running code (--version, -VV,
    -h, a missing file, a bad option), and everything else exits 0 with no
    output, the same policy exec-emulation.py applies to an uploaded binary.
    Capture is unaffected: the full command line (and so any URL in the -c
    text) is logged as cowrie.command.input before this runs, and live stdin
    lines are logged below.
    """

    consumes_stdin = True
    VERSION = "Python 3.10.12"
    BUILD = "(main, Nov 20 2023, 15:14:05) [GCC 11.4.0]"
    USAGE = "usage: python3 [option] ... [-c cmd | -m mod | file | -] [arg] ...\n"
    FLAGS = "bBdEhiIOqsSuvVx"
    WITH_ARG = "cmWX"
    HELP = """usage: python3 [option] ... [-c cmd | -m mod | file | -] [arg] ...
Options and arguments (and corresponding environment variables):
-b     : issue warnings about str(bytes_instance), str(bytearray_instance)
         and comparing bytes/bytearray with str. (-bb: issue errors)
-B     : don't write .pyc files on import; also PYTHONDONTWRITEBYTECODE=x
-c cmd : program passed in as string (terminates option list)
-d     : turn on parser debugging output (for experts only, only works on
         debug builds); also PYTHONDEBUG=x
-E     : ignore PYTHON* environment variables (such as PYTHONPATH)
-h     : print this help message and exit (also -? or --help)
-i     : inspect interactively after running script; forces a prompt even
         if stdin does not appear to be a terminal; also PYTHONINSPECT=x
-I     : isolate Python from the user's environment (implies -E and -s)
-m mod : run library module as a script (terminates option list)
-O     : remove assert and __debug__-dependent statements; add .opt-1 before
         .pyc extension; also PYTHONOPTIMIZE=x
-OO    : do -O changes and also discard docstrings; add .opt-2 before
         .pyc extension
-q     : don't print version and copyright messages on interactive startup
-s     : don't add user site directory to sys.path; also PYTHONNOUSERSITE
-S     : don't imply 'import site' on initialization
-u     : force the stdout and stderr streams to be unbuffered;
         this option has no effect on stdin; also PYTHONUNBUFFERED=x
-v     : verbose (trace import statements); also PYTHONVERBOSE=x
         can be supplied multiple times to increase verbosity
-V     : print the Python version number and exit (also --version)
         when given twice, print more information about the build
-W arg : warning control; arg is action:message:category:module:lineno
         also PYTHONWARNINGS=arg
-x     : skip first line of source, allowing use of non-Unix forms of #!cmd
-X opt : set implementation-specific option. The following options are available:
         -X faulthandler: enable faulthandler
         -X showrefcount: output the total reference count and number of used
             memory blocks when the program finishes or after each statement in the
             interactive interpreter. This only works on debug builds
         -X tracemalloc: start tracing Python memory allocations using the
             tracemalloc module. By default, only the most recent frame is stored in a
             traceback of a trace. Use -X tracemalloc=NFRAME to start tracing with a
             traceback limit of NFRAME frames
         -X importtime: show how long each import takes. It shows module name,
             cumulative time (including nested imports) and self time (excluding
             nested imports). Note that its output may be broken in multi-threaded
             application. Typical usage is python3 -X importtime -c 'import asyncio'
         -X dev: enable CPython's "development mode", introducing additional runtime
             checks which are too expensive to be enabled by default. Effect of the
             developer mode:
                * Add default warning filter, as -W default
                * Install debug hooks on memory allocators: see the PyMem_SetupDebugHooks()
                  C function
                * Enable the faulthandler module to dump the Python traceback on a crash
                * Enable asyncio debug mode
                * Set the dev_mode attribute of sys.flags to True
                * io.IOBase destructor logs close() exceptions
         -X utf8: enable UTF-8 mode for operating system interfaces, overriding the default
             locale-aware mode. -X utf8=0 explicitly disables UTF-8 mode (even when it would
             otherwise activate automatically)
         -X pycache_prefix=PATH: enable writing .pyc files to a parallel tree rooted at the
             given directory instead of to the code tree
         -X warn_default_encoding: enable opt-in EncodingWarning for 'encoding=None'
         -X int_max_str_digits=number: limit the size of int<->str conversions.
             This helps avoid denial of service attacks when parsing untrusted data.
             The default is sys.int_info.default_max_str_digits.  0 disables.

--check-hash-based-pycs always|default|never:
    control how Python invalidates hash-based .pyc files
file   : program read from script file
-      : program read from stdin (default; interactive mode if a tty)
arg ...: arguments passed to program in sys.argv[1:]

Other environment variables:
PYTHONSTARTUP: file executed on interactive startup (no default)
PYTHONPATH   : ':'-separated list of directories prefixed to the
               default module search path.  The result is sys.path.
PYTHONHOME   : alternate <prefix> directory (or <prefix>:<exec_prefix>).
               The default module search path uses <prefix>/lib/pythonX.X.
PYTHONPLATLIBDIR : override sys.platlibdir.
PYTHONCASEOK : ignore case in 'import' statements (Windows).
PYTHONUTF8: if set to 1, enable the UTF-8 mode.
PYTHONIOENCODING: Encoding[:errors] used for stdin/stdout/stderr.
PYTHONFAULTHANDLER: dump the Python traceback on fatal errors.
PYTHONHASHSEED: if this variable is set to 'random', a random value is used
   to seed the hashes of str and bytes objects.  It can also be set to an
   integer in the range [0,4294967295] to get hash values with a
   predictable seed.
PYTHONINTMAXSTRDIGITS: limits the maximum digit characters in an int value
   when converting from a string and when converting an int back to a str.
   A value of 0 disables the limit.  Conversions to or from bases 2, 4, 8,
   16, and 32 are never limited.
PYTHONMALLOC: set the Python memory allocators and/or install debug hooks
   on Python memory allocators. Use PYTHONMALLOC=debug to install debug
   hooks.
PYTHONCOERCECLOCALE: if this variable is set to 0, it disables the locale
   coercion behavior. Use PYTHONCOERCECLOCALE=warn to request display of
   locale coercion and locale compatibility warnings on stderr.
PYTHONBREAKPOINT: if this variable is set to 0, it disables the default
   debugger. It can be set to the callable of your debugger of choice.
PYTHONDEVMODE: enable the development mode.
PYTHONPYCACHEPREFIX: root directory for bytecode cache (pyc) files.
PYTHONWARNDEFAULTENCODING: enable opt-in EncodingWarning for 'encoding=None'.
"""

    def _usage_error(self, message: str) -> None:
        self.errorWrite(f"{message}\n{self.USAGE}Try `python -h' for more information.\n")
        self.exit(2)

    def start(self) -> None:
        args = list(self.args)
        versions = 0
        target = None  # ("-c" | "-m" | "file", value)
        while args and target is None:
            arg = args.pop(0)
            if arg == "--":
                break
            if arg in ("--help", "--version"):
                if arg == "--help":
                    self.write(self.HELP)
                    self.exit(0)
                    return
                versions += 1
                continue
            if arg.startswith("--check-hash-based-pycs"):
                if "=" not in arg and args:
                    args.pop(0)
                continue
            if arg.startswith("--"):
                self._usage_error(f"unknown option {arg}")
                return
            if not arg.startswith("-") or arg == "-":
                target = ("file", arg)
                break
            letters = arg[1:]
            for i, ch in enumerate(letters):
                if ch in self.WITH_ARG:
                    value = letters[i + 1:] or (args.pop(0) if args else None)
                    if value is None:
                        self._usage_error(f"Argument expected for the -{ch} option")
                        return
                    if ch in "cm":
                        target = (f"-{ch}", value)
                    break
                if ch not in self.FLAGS:
                    self._usage_error(f"Unknown option: -{ch}")
                    return
                if ch == "h":
                    self.write(self.HELP)
                    self.exit(0)
                    return
                if ch == "V":
                    versions += 1
        if target is None and args:
            target = ("file", args.pop(0))
        if versions:
            self.write(self.VERSION + (f" {self.BUILD}" if versions > 1 else "") + "\n")
            self.exit(0)
            return
        if target is not None and target[0] == "file" and target[1] != "-":
            path = self.fs.resolve_path(target[1], self.cwd)
            if self.fs.isdir(path):
                self.errorWrite(f"/usr/bin/python3: can't find '__main__' module in "
                                f"'{target[1]}'\n")
                self.exit(1)
                return
            if not self.fs.exists(path):
                self.errorWrite(f"python3: can't open file '{path}': "
                                "[Errno 2] No such file or directory\n")
                self.exit(2)
                return
        if target is not None and target[1] != "-":
            # -c CODE, -m MOD or an existing script: a silent success. The
            # code is never evaluated (see the class docstring).
            self.exit(0)
            return
        # No program: the interpreter reads stdin. Piped data is consumed,
        # not run.
        if self.input_data is not None:
            self.exit(0)
            return
        from cowrie.shell.protocol import HoneyPotExecProtocol

        if not isinstance(self.protocol, HoneyPotExecProtocol):
            # A terminal: the REPL banner and prompt, as 22.04 prints them.
            self.write(f"{self.VERSION} {self.BUILD} on linux\n"
                       'Type "help", "copyright", "credits" or "license" for more information.\n'
                       ">>> ")
        # Otherwise wait for stdin to end (lineReceived/eofReceived).

    def lineReceived(self, line: str) -> None:
        # Logged like Cowrie's python does; never evaluated.
        self.protocol.events.dispatch(
            "cowrie.command.input",
            "INPUT (%(realm)s): %(input)s",
            realm="python3",
            input=line,
        )
        from cowrie.shell.protocol import HoneyPotExecProtocol

        if line.strip() in ("exit()", "quit()", "exit", "quit"):
            self.exit(0)
        elif not isinstance(self.protocol, HoneyPotExecProtocol):
            self.write(">>> ")

    def eofReceived(self) -> None:
        from cowrie.shell.protocol import HoneyPotExecProtocol

        if not isinstance(self.protocol, HoneyPotExecProtocol):
            self.write("\n")
        self.exit(0)


commands["/usr/bin/python3"] = Command_python3
commands["python3"] = Command_python3
commands["/usr/bin/python3.10"] = Command_python3
commands["python3.10"] = Command_python3
commands["/usr/bin/python"] = Command_python
commands["python"] = Command_python
'''

BLOCKS = ((OLD, NEW),)


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/commands/python.py"
    content = path.read_text(encoding="utf-8")
    counts = [(content.count(old), content.count(new)) for old, new in BLOCKS]
    if all(c == (0, 1) for c in counts):
        print(f"  [skip] {path}: already patched")
        return 0
    if not all(c == (1, 0) for c in counts):
        print(
            f"  [FAIL] {path}: target is neither pristine nor fully patched "
            f"(old/new counts {counts}) - upstream python changed",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    for old, new in BLOCKS:
        content = content.replace(old, new, 1)
    path.write_text(content, encoding="utf-8")
    print(f"  [ok] {path}: patched (python3: fake success, never execution)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
