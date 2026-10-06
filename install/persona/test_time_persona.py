#!/usr/bin/env python3
"""Exercise the checked-out Cowrie's last (and, once patched, uptime and w)
against the persona clock, over days of simulated time.

Runs the real pinned, patched Command_last (last-persona.py) without Twisted
or a honeypot: the command plumbing, the protocol (boot_time, clientIP,
logintime) and the clock are stand-ins. Every output is judged by the
behavioural harness's own comparison (scripts/cowrie-behaviour-test.py and
its expected files), so this proves offline what the rehearsal proves live,
and for Cowrie process ages a rehearsal cannot reach: the Task 1 review
constraint is that the profiler's LAST must still pass after Cowrie has run
for days, which boot-anchored sessions fail after ~5 h.

Usage: test_time_persona.py COWRIE_HOME [-v]
"""

import importlib.util
import os
import sys
import time
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent
CASES = ROOT / "scripts" / "behaviour" / "expected"
BOOT_OFFSET = 3640620

_hspec = importlib.util.spec_from_file_location(
    "cowrie_behaviour_test", ROOT / "scripts" / "cowrie-behaviour-test.py")
cbt = importlib.util.module_from_spec(_hspec)
sys.modules[_hspec.name] = cbt
_hspec.loader.exec_module(cbt)

_gspec = importlib.util.spec_from_file_location(
    "gen_time_persona", ROOT / "install" / "persona" / "gen-time-persona.py")
gtp = importlib.util.module_from_spec(_gspec)
_gspec.loader.exec_module(gtp)


class HoneyPotCommand:
    """The slice of cowrie.shell.command.HoneyPotCommand the commands use."""

    def __init__(self, protocol, args, user="root", loadavg=b"0.38 0.42 0.45 1/287 18234\n"):
        self.protocol = protocol
        self.args = list(args)
        self.user = {"username": user}
        self.out, self.err = [], []
        self.exit_code = None
        self.fs = types.SimpleNamespace(file_contents=lambda path: self._file(path, loadavg))

    @staticmethod
    def _file(path, loadavg):
        if path == "/proc/loadavg" and loadavg is not None:
            return loadavg
        raise FileNotFoundError(path)

    def write(self, data):
        self.out.append(data)

    def errorWrite(self, data):
        self.err.append(data)

    def exit(self, code=None):
        if self.exit_code is None:
            self.exit_code = code if code is not None else 0


class _Protocol:
    def __init__(self, start, client="127.0.0.1", login=None):
        self.start = start
        self.clientIP = client
        self.logintime = login if login is not None else time.time()

    def boot_time(self):
        return self.start - BOOT_OFFSET

    def uptime(self):
        return time.time() - self.boot_time()


class HoneyPotExecProtocol(_Protocol):
    pass


class HoneyPotInteractiveProtocol(_Protocol):
    pass


def _install_stubs():
    for name in ("cowrie", "cowrie.shell", "cowrie.core", "cowrie.commands"):
        sys.modules.setdefault(name, types.ModuleType(name))
    command = types.ModuleType("cowrie.shell.command")
    command.HoneyPotCommand = HoneyPotCommand
    sys.modules["cowrie.shell.command"] = command
    protocol = types.ModuleType("cowrie.shell.protocol")
    protocol.HoneyPotExecProtocol = HoneyPotExecProtocol
    sys.modules["cowrie.shell.protocol"] = protocol
    utils = types.ModuleType("cowrie.core.utils")
    utils.uptime = lambda s: "unused"
    sys.modules["cowrie.core.utils"] = utils


def load_module(rel, name):
    spec = importlib.util.spec_from_file_location(name, COWRIE_HOME / rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def run(cls, protocol, args=(), now=None, **kw):
    cmd = cls(protocol, args, **kw)
    with mock.patch("time.time", return_value=now):
        cmd.call()
    cmd.exit()
    return "".join(cmd.out), "".join(cmd.err), cmd.exit_code


def harness(case, output, now, age, rc=0):
    exp = cbt.parse_expected((CASES / f"{case}.out").read_text())
    dt = datetime.fromtimestamp(now, timezone.utc)
    clk = cbt.Clock(start=dt, end=dt, cowrie_age=age)
    return cbt.compare(case, exp, output, rc, False, clk)


# Cowrie process ages (s) and sample instants: a fresh rehearsal, the ~5 h at
# which boot-anchored sessions broke, and production's days to weeks; each
# sampled across two days at an interval coprime with the 4 h step.
AGES = (0, 3600, 5 * 3600 + 13 * 60, 6 * 3600, 86400 + 7, 30 * 86400 + 11)
T0 = datetime(2026, 10, 6, 6, 15, 52, tzinfo=timezone.utc).timestamp()
SAMPLES = [T0 + k * 13 * 60 + 7 for k in range(0, 2 * 24 * 60 // 13)]


class LastTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.last = load_module("src/cowrie/commands/last.py", "cowrie.commands.last")

    def test_persona_table_is_gen_time_personas(self):
        want = tuple(
            (int(off.total_seconds()), None if ln is None else int(ln.total_seconds()), tty, ip)
            for off, ln, tty, ip in gtp.SESSIONS)
        self.assertEqual(self.last.PERSONA_SESSIONS, want)
        self.assertEqual(self.last.PERSONA_USER, gtp.ADMIN_USER)
        self.assertEqual(self.last.PERSONA_KERNEL, gtp.KERNEL)

    def test_exec_last_is_the_persona_at_every_cowrie_age(self):
        for age in AGES:
            for now in SAMPLES:
                proto = HoneyPotExecProtocol(start=now - age)
                out, err, rc = run(self.last.Command_last, proto, now=now)
                res = harness("last", out + err, now, age, rc)
                if not res.ok:
                    self.fail(f"age {age}s at {datetime.fromtimestamp(now, timezone.utc)}:\n"
                              + "\n".join(res.diff + res.messages))

    def test_reference_rows_equal_gen_time_persona(self):
        # At a grid instant the rows are exactly the txtcmd gen-time-persona
        # writes for that instant, boot rows aside.
        now = self.last.persona_reference(T0)
        proto = HoneyPotExecProtocol(start=now)
        out, _, _ = run(self.last.Command_last, proto, now=now)
        txt = gtp.build(datetime.fromtimestamp(now, timezone.utc).replace(tzinfo=None))
        want = txt["share/cowrie/txtcmds/usr/bin/last"].split("\n")[:6]
        self.assertEqual(out.split("\n")[:6], want)

    def test_repeated_runs_agree_within_a_step(self):
        now = self.last.persona_reference(T0) + 60
        proto = HoneyPotExecProtocol(start=now)
        a, _, _ = run(self.last.Command_last, proto, now=now)
        b, _, _ = run(self.last.Command_last, proto, now=now + 1800)
        self.assertEqual(a, b)

    def test_exec_caller_has_no_row_pty_caller_does(self):
        now = T0
        out, _, _ = run(self.last.Command_last, HoneyPotExecProtocol(now - 60, "203.0.113.9"), now=now)
        self.assertNotIn("203.0.113.9", out)
        proto = HoneyPotInteractiveProtocol(now - 60, "203.0.113.9", login=now - 30)
        out, _, _ = run(self.last.Command_last, proto, now=now)
        first = out.split("\n")[0]
        self.assertEqual(first, "root     pts/1        203.0.113.9      "
                                f"{self.last.last_date(now - 30, seconds=False)}   still logged in")
        self.assertTrue(out.split("\n")[1].startswith("ubuntu   pts/0        10.0.0.8 "))

    def test_options(self):
        proto = HoneyPotExecProtocol(T0 - 60)
        out, _, rc = run(self.last.Command_last, proto, ["-n", "2"], now=T0)
        self.assertEqual(rc, 0)
        self.assertEqual(len(out.split("\n")), 2 + 3)  # 2 rows, blank, wtmp, ""
        out2, _, _ = run(self.last.Command_last, proto, ["-2"], now=T0)
        self.assertEqual(out, out2)
        out, _, _ = run(self.last.Command_last, proto, ["reboot"], now=T0)
        self.assertTrue(out.startswith("reboot   system boot  5.15.0-94-generi "))
        self.assertEqual(out.count("\n"), 3)
        out, _, _ = run(self.last.Command_last, proto, ["root"], now=T0)
        self.assertTrue(out.startswith("\nwtmp begins "))
        out, _, _ = run(self.last.Command_last, proto, ["-x", "-F"], now=T0)
        self.assertEqual(out.count("\n"), 7 + 2)
        out, err, rc = run(self.last.Command_last, proto, ["-z"], now=T0)
        self.assertEqual((out, rc), ("", 1))
        self.assertEqual(err, "last: invalid option -- 'z'\nTry 'last --help' for more information.\n")


if __name__ == "__main__":
    COWRIE_HOME = Path(sys.argv.pop(1))
    os.environ["TZ"] = "UTC"
    time.tzset()
    _install_stubs()
    unittest.main()
