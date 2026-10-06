#!/usr/bin/env python3
"""Prove the patched python3 never executes attacker Python.

Runs the checked-out Cowrie's real Command_python3
(install/persona/patches/python3-emulation.py) without Twisted: the command
plumbing, the protocol and the fake filesystem are stand-ins. Two proofs:

- Dynamic: every input form (-c, -m, a script file, piped stdin, a live
  stdin line, a REPL line) carries code that would create a marker file on
  the host. No marker appears; a CPython audit hook sees no exec, compile,
  os.system, subprocess, spawn, fork or file write while the command runs;
  the fake filesystem's contents and write methods are never touched.
- Static: Command_python3's source contains no call that could run or load
  code (eval, exec, compile, __import__, open, system, popen, runpy...) and
  imports nothing but cowrie.shell.protocol.

Usage: test_python3_fake.py COWRIE_HOME [-v]
"""

import ast
import importlib.util
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

# Audit events that mean code is being run or loaded, or a process or file
# created. "open" is filtered to write modes below.
FORBIDDEN_EVENTS = {
    "exec", "compile", "os.system", "os.exec", "os.posix_spawn", "os.spawn",
    "os.fork", "os.forkpty", "subprocess.Popen", "ctypes.dlopen", "import",
}
RECORDING = []
_ARMED = [False]


def _audit(event, args):
    if not _ARMED[0]:
        return
    if event in FORBIDDEN_EVENTS:
        RECORDING.append((event, repr(args)[:120]))
    elif event == "open" and len(args) > 1 and isinstance(args[1], str) and any(
            m in args[1] for m in "wax+"):
        RECORDING.append((event, repr(args)[:120]))


sys.addaudithook(_audit)


class HoneyPotCommand:
    """The slice of cowrie.shell.command.HoneyPotCommand the command uses."""

    def __init__(self, protocol, args, fs, input_data=None):
        self.protocol = protocol
        self.args = list(args)
        self.fs = fs
        self.cwd = "/root"
        self.input_data = input_data
        self.out, self.err = [], []
        self.exit_code = None

    def write(self, data):
        self.out.append(data)

    def errorWrite(self, data):
        self.err.append(data)

    def exit(self, code=None):
        if self.exit_code is None:
            self.exit_code = code if code is not None else 0


class ReadOnlyFs:
    """Answers path questions only. Reading a file's contents or any write
    fails the test: the command must not look inside what it is given."""

    def __init__(self, files=(), dirs=("/", "/root", "/tmp", "/etc")):
        self.files, self.dirs = set(files), set(dirs)

    @staticmethod
    def resolve_path(path, cwd):
        return os.path.normpath(path if path.startswith("/") else os.path.join(cwd, path))

    def exists(self, path):
        return path in self.files or path in self.dirs

    def isdir(self, path):
        return path in self.dirs

    def __getattr__(self, name):
        raise AssertionError(f"python3 touched the fake filesystem: fs.{name}")


class Events:
    def __init__(self):
        self.lines = []

    def dispatch(self, eventid, fmt, **kw):
        self.lines.append((eventid, kw))


class HoneyPotExecProtocol:
    def __init__(self):
        self.events = Events()


class HoneyPotInteractiveProtocol:
    def __init__(self):
        self.events = Events()


def load_python3():
    for name in ("cowrie", "cowrie.shell", "cowrie.commands"):
        sys.modules.setdefault(name, types.ModuleType(name))
    command = types.ModuleType("cowrie.shell.command")
    command.HoneyPotCommand = HoneyPotCommand
    sys.modules["cowrie.shell.command"] = command
    protocol = types.ModuleType("cowrie.shell.protocol")
    protocol.HoneyPotExecProtocol = HoneyPotExecProtocol
    sys.modules["cowrie.shell.protocol"] = protocol
    spec = importlib.util.spec_from_file_location(
        "cowrie.commands.python", COWRIE_HOME / "src/cowrie/commands/python.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Python3NeverExecutesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_python3()
        cls.cls = cls.module.Command_python3
        cls.tmp = tempfile.TemporaryDirectory()
        cls.marker = Path(cls.tmp.name) / "executed"

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def payload(self):
        return f'import os; os.system("touch {self.marker}"); open("{self.marker}", "w")'

    def run_command(self, args, protocol=None, fs=None, input_data=None, lines=(), eof=False):
        protocol = protocol or HoneyPotExecProtocol()
        cmd = self.cls(protocol, args, fs or ReadOnlyFs(), input_data)
        RECORDING.clear()
        _ARMED[0] = True
        try:
            cmd.start()
            for line in lines:
                cmd.lineReceived(line)
            if eof:
                cmd.eofReceived()
        finally:
            _ARMED[0] = False
        self.assertEqual(RECORDING, [], "python3 ran or loaded code")
        self.assertFalse(self.marker.exists(), "attacker code ran on the host")
        return "".join(cmd.out), "".join(cmd.err), cmd.exit_code, protocol.events.lines

    def test_c_code_is_not_run(self):
        for args in (["-c", self.payload()], [f"-c{self.payload()}"], ["-uc", self.payload()],
                     ["-c", f"__import__('os').system('touch {self.marker}')"],
                     ["-c", f"exec(compile('open(\"{self.marker}\",\"w\")', 'x', 'exec'))"]):
            with self.subTest(args=args[:1]):
                self.assertEqual(self.run_command(args)[:3], ("", "", 0))

    def test_module_and_script_are_not_run(self):
        fs = ReadOnlyFs(files={"/tmp/x.py"})
        self.assertEqual(self.run_command(["-m", "http.server"])[:3], ("", "", 0))
        self.assertEqual(self.run_command(["/tmp/x.py", "arg"], fs=fs)[:3], ("", "", 0))
        out, err, rc, _ = self.run_command(["/tmp/missing.py"])
        self.assertEqual((out, rc), ("", 2))
        self.assertEqual(err, "python3: can't open file '/tmp/missing.py': "
                              "[Errno 2] No such file or directory\n")

    def test_stdin_is_not_run(self):
        code = self.payload().encode()
        self.assertEqual(self.run_command([], input_data=code)[:3], ("", "", 0))
        self.assertEqual(self.run_command(["-"], input_data=code)[:3], ("", "", 0))
        # Live stdin on an exec channel: logged for capture, never evaluated.
        out, err, rc, events = self.run_command([], lines=[self.payload()], eof=True)
        self.assertEqual((out, err, rc), ("", "", 0))
        self.assertEqual(events, [("cowrie.command.input",
                                   {"realm": "python3", "input": self.payload()})])

    def test_repl_is_not_run(self):
        out, _, rc, _ = self.run_command([], protocol=HoneyPotInteractiveProtocol(),
                                         lines=[self.payload(), "exit()"])
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith("Python 3.10.12 (main, Nov 20 2023, 15:14:05) "
                                       "[GCC 11.4.0] on linux\n"), out)
        self.assertEqual(out.count(">>> "), 2)

    def test_version_and_errors(self):
        self.assertEqual(self.run_command(["--version"])[:3], ("Python 3.10.12\n", "", 0))
        self.assertEqual(self.run_command(["-V"])[:3], ("Python 3.10.12\n", "", 0))
        self.assertEqual(self.run_command(["-VV"])[0],
                         "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]\n")
        _, err, rc, _ = self.run_command(["-z"])
        self.assertEqual(rc, 2)
        self.assertTrue(err.startswith("Unknown option: -z\nusage: python3 [option]"))
        _, err, rc, _ = self.run_command(["-c"])
        self.assertEqual((err.splitlines()[0], rc), ("Argument expected for the -c option", 2))

    def test_source_has_no_route_to_running_code(self):
        source = (COWRIE_HOME / "src/cowrie/commands/python.py").read_text()
        node = next(n for n in ast.parse(source).body
                    if isinstance(n, ast.ClassDef) and n.name == "Command_python3")
        banned = {"eval", "exec", "compile", "__import__", "open", "system", "popen",
                  "Popen", "run", "call", "check_output", "spawn", "execfile",
                  "import_module", "run_path", "run_module", "file_contents", "getattr"}
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                func = sub.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                self.assertNotIn(name, banned, f"Command_python3 calls {name}()")
            if isinstance(sub, ast.ImportFrom):
                self.assertEqual(sub.module, "cowrie.shell.protocol")
            self.assertNotIsInstance(sub, ast.Import)


if __name__ == "__main__":
    COWRIE_HOME = Path(sys.argv.pop(1))
    unittest.main()
