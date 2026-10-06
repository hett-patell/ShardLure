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
    protocol.boot_offset = lambda: float(BOOT_OFFSET)
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
        self.assertEqual(self.last.PERSONA_ACTIVE_FOR, int(gtp.ACTIVE_FOR.total_seconds()))

    def test_exec_last_is_the_persona_at_every_cowrie_age(self):
        for age in AGES:
            for now in SAMPLES:
                proto = HoneyPotExecProtocol(start=now - age)
                out, err, rc = run(self.last.Command_last, proto, now=now)
                res = harness("last", out + err, now, age, rc)
                if not res.ok:
                    self.fail(f"age {age}s at {datetime.fromtimestamp(now, timezone.utc)}:\n"
                              + "\n".join(res.diff + res.messages))

    def test_rows_and_motd_equal_gen_time_persona_run_at_the_start(self):
        # gen-time-persona runs at deploy, just before Cowrie starts: its last
        # txtcmd rows and its motd "Last login" name the sessions Cowrie's
        # last lays out from the process start, at any later age.
        start = T0
        proto = HoneyPotExecProtocol(start=start)
        out, _, _ = run(self.last.Command_last, proto, now=start + 9 * 86400 + 5)
        txt = gtp.build(datetime.fromtimestamp(start, timezone.utc).replace(tzinfo=None))
        want = txt["share/cowrie/txtcmds/usr/bin/last"].split("\n")[:6]
        self.assertEqual(out.split("\n")[:6], want)
        second = datetime.strptime(out.split("\n")[1][39:55] + " 2026", "%a %b %d %H:%M %Y")
        self.assertIn(f"Last login: {second:%a %b %e %H:%M}", txt["honeyfs/etc/motd"])

    def test_history_never_moves_for_a_process(self):
        # Review I-1: wtmp is append-only. For one Cowrie start, last prints
        # the same bytes at every instant from 0 to 30 days of process age,
        # with no 4 h (or any) jumps.
        start = T0
        proto = HoneyPotExecProtocol(start=start)
        first, _, _ = run(self.last.Command_last, proto, now=start)
        instants = [start + k * 13 * 60 + 7 for k in range(0, 30 * 24 * 60 // 13, 7)]
        for now in instants + [start + age for age in AGES]:
            out, _, _ = run(self.last.Command_last, proto, now=now)
            self.assertEqual(out, first, f"history moved at age {now - start:.0f}s")

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
        out, err, rc = run(self.last.Command_last, proto, ["-n", "x"], now=T0)
        self.assertEqual((out, err, rc), ("", "last: failed to parse number: 'x'\n", 1))
        out, err, rc = run(self.last.Command_last, proto, ["-z"], now=T0)
        self.assertEqual((out, rc), ("", 1))
        self.assertEqual(err, "last: invalid option -- 'z'\nTry 'last --help' for more information.\n")


def load_w():
    """Command_w alone: base.py imports Twisted, so exec just its class."""
    import ast  # noqa: PLC0415

    source = (COWRIE_HOME / "src/cowrie/commands/base.py").read_text()
    node = next(n for n in ast.parse(source).body
                if isinstance(n, ast.ClassDef) and n.name == "Command_w")
    ns = {"time": time, "HoneyPotCommand": HoneyPotCommand}
    exec(compile(ast.Module(body=[node], type_ignores=[]), "base.py", "exec"), ns)
    return ns["Command_w"]


def proc_uptime(proto):
    """v3.1.1 HoneyPotBaseProtocol.proc_uptime over the persona's 4 CPUs."""
    up = proto.uptime()
    return f"{up:.2f} {up * 4 * 0.97:.2f}\n"


class UptimeWTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.last = load_module("src/cowrie/commands/last.py", "cowrie.commands.last")
        cls.uptime = load_module("src/cowrie/commands/uptime.py", "cowrie.commands.uptime")
        cls.w = load_w()

    def test_uptime_and_w_are_the_persona_at_every_cowrie_age(self):
        for age in AGES:
            for now in SAMPLES[::3]:
                proto = HoneyPotExecProtocol(start=now - age)
                for case, cls in (("uptime", self.uptime.Command_uptime), ("w", self.w)):
                    out, err, rc = run(cls, proto, now=now)
                    res = harness(case, out + err, now, age, rc)
                    if not res.ok:
                        self.fail(f"{case} age {age}s at "
                                  f"{datetime.fromtimestamp(now, timezone.utc)}:\n"
                                  + "\n".join(res.diff + res.messages))

    def test_every_time_source_agrees_on_one_channel(self):
        # time-persona-consistent: cat /proc/uptime; uptime; w; last.
        for age in AGES:
            for now in SAMPLES[::5]:
                proto = HoneyPotExecProtocol(start=now - age)
                with mock.patch("time.time", return_value=now):
                    out = proc_uptime(proto)
                out += run(self.uptime.Command_uptime, proto, now=now)[0]
                out += run(self.w, proto, now=now)[0]
                out += run(self.last.Command_last, proto, now=now)[0]
                res = harness("time-persona-consistent", out, now, age)
                if not res.ok:
                    self.fail(f"age {age}s at {datetime.fromtimestamp(now, timezone.utc)}:\n"
                              + "\n".join(res.diff + res.messages))

    def test_w_at_the_start_is_gen_time_personas_txtcmd(self):
        # Cowrie's w shadows txtcmds/usr/bin/w; at the process start, with the
        # persona's anchor uptime, the two are byte-identical.
        now = T0
        out, _, _ = run(self.w, HoneyPotExecProtocol(start=now), now=now)
        txt = gtp.build(datetime.fromtimestamp(now, timezone.utc).replace(tzinfo=None))
        self.assertEqual(out, txt["share/cowrie/txtcmds/usr/bin/w"])
        out, _, _ = run(self.uptime.Command_uptime, HoneyPotExecProtocol(start=now), now=now)
        self.assertEqual(out, txt["share/cowrie/txtcmds/usr/bin/uptime"])

    def test_load_average_is_the_fake_proc_loadavg(self):
        proto = HoneyPotExecProtocol(T0 - 60)
        out, _, _ = run(self.uptime.Command_uptime, proto, now=T0, loadavg=b"1.5 0.25 2 3/9 1\n")
        self.assertTrue(out.endswith("load average: 1.50, 0.25, 2.00\n"), out)
        out, _, _ = run(self.w, proto, now=T0, loadavg=None)
        self.assertIn("load average: 0.00, 0.00, 0.00\n", out)

    def test_procps_uptime_forms(self):
        line = self.uptime.procps_uptime_line
        fs = types.SimpleNamespace(file_contents=lambda p: b"0.38 0.42 0.45 1/287 18234\n")
        self.assertEqual(line(fs, T0, BOOT_OFFSET + 5, 1),
                         " 06:15:52 up 42 days,  3:17,  1 user,  load average: 0.38, 0.42, 0.45\n")
        self.assertEqual(line(fs, T0, 42 * 86400 + 300, 2),
                         " 06:15:52 up 42 days, 5 min,  2 users,  load average: 0.38, 0.42, 0.45\n")
        self.assertEqual(line(fs, T0, 86400 + 11 * 3600, 1)[10:28], "up 1 day, 11:00,  ")
        self.assertEqual(line(fs, T0, 3 * 3600 + 60, 1)[10:22], "up  3:01,  1")
        self.assertEqual(self.uptime.procps_pretty(BOOT_OFFSET),
                         "up 6 weeks, 3 hours, 17 minutes\n")
        self.assertEqual(self.uptime.procps_pretty(8 * 86400 + 60), "up 1 week, 1 day, 1 minute\n")

    def test_uptime_options(self):
        proto = HoneyPotExecProtocol(T0 - 60)
        out, _, rc = run(self.uptime.Command_uptime, proto, ["-s"], now=T0)
        boot = datetime.fromtimestamp(T0 - 60 - BOOT_OFFSET, timezone.utc)
        self.assertEqual((out, rc), (f"{boot:%Y-%m-%d %H:%M:%S}\n", 0))
        out, _, _ = run(self.uptime.Command_uptime, proto, ["-p"], now=T0)
        self.assertEqual(out, "up 6 weeks, 3 hours, 18 minutes\n")
        out, _, _ = run(self.uptime.Command_uptime, proto, ["-V"], now=T0)
        self.assertEqual(out, "uptime from procps-ng 3.3.17\n")
        out, err, rc = run(self.uptime.Command_uptime, proto, ["-z"], now=T0)
        self.assertEqual((out, rc), ("", 1))
        self.assertTrue(err.startswith("uptime: invalid option -- 'z'\n\nUsage:\n uptime [options]\n"))
        out, err, rc = run(self.uptime.Command_uptime, proto, ["now"], now=T0)
        self.assertEqual((out, rc), ("", 1))

    def test_pty_caller_is_a_second_user(self):
        proto = HoneyPotInteractiveProtocol(T0 - 60, "203.0.113.9", login=T0 - 30)
        out, _, _ = run(self.uptime.Command_uptime, proto, now=T0)
        self.assertIn(",  2 users,  load average", out)
        out, _, _ = run(self.w, proto, now=T0)
        rows = out.split("\n")
        self.assertIn(",  2 users,  load average", rows[0])
        self.assertTrue(rows[2].startswith("ubuntu   pts/0    10.0.0.8         "))
        self.assertEqual(rows[3], "root     pts/1    203.0.113.9      06:15    0.00s  0.00s  0.00s w")

    def test_w_options(self):
        proto = HoneyPotExecProtocol(T0 - 60)
        full, _, _ = run(self.w, proto, now=T0)
        out, _, _ = run(self.w, proto, ["-h"], now=T0)
        self.assertEqual(out, full.split("\n", 2)[2])
        out, _, _ = run(self.w, proto, ["-s"], now=T0)
        head, row = out.split("\n")[1:3]
        self.assertEqual(head, "USER     TTY      FROM              IDLE WHAT")
        self.assertRegex(row, r"^ubuntu   pts/0    10\.0\.0\.8         [ \d]\d:\d\dm -bash$")
        out, _, _ = run(self.w, proto, ["-f"], now=T0)
        self.assertEqual(out.split("\n")[1], "USER     TTY        LOGIN@   IDLE   JCPU   PCPU WHAT")
        out, _, _ = run(self.w, proto, ["root"], now=T0)
        self.assertEqual(len(out.split("\n")), 3)
        out, err, rc = run(self.w, proto, ["-z"], now=T0)
        self.assertEqual((out, rc), ("", 1))
        self.assertTrue(err.startswith("w: invalid option -- 'z'\n\nUsage:\n w [options]\n\n"))

    def test_w_login_ages_through_procps_forms(self):
        # Review m-3: the admin's login is fixed at the start, so it reaches
        # procps' "still today" HH:MM past 12 h, then DddHH, then DDMonYY.
        def row(start, now):
            out, _, _ = run(self.w, HoneyPotExecProtocol(start=start), now=now)
            return out.split("\n")[2]
        day = datetime(2026, 10, 3, 6, 47, tzinfo=timezone.utc).timestamp()
        self.assertEqual(row(day + 6 * 3600 + 47 * 60, day + 16 * 3600 + 13 * 60)[35:56],
                         "06:47   15:32m  0.04s")   # login 06:47, now 23:00 same day
        self.assertEqual(row(day + 6 * 3600 + 47 * 60, day + 3 * 86400)[35:56],
                         "Sat06    2days  0.04s")
        self.assertEqual(row(day + 6 * 3600 + 47 * 60, day + 8 * 86400)[35:56],
                         "03Oct26  7days  0.04s")
        self.assertEqual(self.last.last_date(day, seconds=False), "Sat Oct  3 06:47")


if __name__ == "__main__":
    COWRIE_HOME = Path(sys.argv.pop(1))
    os.environ["TZ"] = "UTC"
    time.tzset()
    _install_stubs()
    unittest.main()
