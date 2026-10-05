"""Unit tests for the Cowrie behavioural harness's own comparison logic.

These need no network and no Cowrie: the harness's transport is replaced by a
fake runner. They pin the normaliser (which fields are volatile and how each is
accepted), the diff/exit-code contract every later Phase B task relies on, and
the consistency of the shipped case files.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "cowrie_behaviour_test", HERE / "cowrie-behaviour-test.py"
)
cbt = importlib.util.module_from_spec(_spec)
# dataclasses resolve annotations through sys.modules, so register first.
sys.modules[_spec.name] = cbt
_spec.loader.exec_module(cbt)

CASES_DIR = HERE / "behaviour"

PERSONA_LAST = (
    "ubuntu   pts/0        10.0.0.8         Mon Oct  5 02:22   still logged in\n"
    "ubuntu   pts/0        10.0.0.8         Sun Oct  4 00:43   - 03:26  (02:43)\n"
    "reboot   system boot  5.15.0-94-generi Mon Aug 24 05:52   still running\n"
    "\n"
    "wtmp begins Mon Aug 24 05:52:26 2026\n"
)
LAST_TEMPLATE = (
    "ubuntu   pts/0        10.0.0.8         {{WDATE}} {{HH:MM}}   still logged in\n"
    "ubuntu   pts/0        10.0.0.8         {{WDATE}} {{HH:MM}}   - {{HH:MM}}  (02:43)\n"
    "reboot   system boot  5.15.0-94-generi {{WDATE}} {{HH:MM}}   still running\n"
    "\n"
    "wtmp begins {{WDATE}} {{HH:MM:SS}} {{YEAR}}\n"
)


def check(template: str, actual: str, rc: int = 0, timed_out: bool = False):
    return cbt.compare("case", cbt.parse_expected(template), actual, rc, timed_out)


class UptimeNormaliserTest(unittest.TestCase):
    TEMPLATE = "UPTIME:{{UPTIME_SECS}} {{IDLE_SECS}}\n"

    def test_anchor_itself_is_accepted(self):
        self.assertTrue(check(self.TEMPLATE, "UPTIME:3640620.00 13979980.80\n").ok)

    def test_value_past_the_anchor_is_accepted(self):
        # v3.1.1 with boot_offset = 3640620, a few seconds after start.
        self.assertTrue(check(self.TEMPLATE, "UPTIME:3640632.78 14125655.18\n").ok)

    def test_zero_is_rejected(self):
        res = check(self.TEMPLATE, "UPTIME:0.00 0.00\n")
        self.assertFalse(res.ok)
        self.assertTrue(any("anchor" in m for m in res.messages), res.messages)

    def test_below_anchor_is_rejected(self):
        # v3.1.1's random boot_offset (23 days) - disagrees with the persona.
        self.assertFalse(check(self.TEMPLATE, "UPTIME:2031659.57 7882839.14\n").ok)

    def test_empty_field_is_rejected(self):
        # The pin's headline failure: every field after UNAME is empty.
        res = check(self.TEMPLATE, "UPTIME:\n")
        self.assertFalse(res.ok)
        self.assertTrue(res.diff)

    def test_human_uptime_at_or_past_anchor(self):
        tpl = " {{HH:MM:SS}} {{UPTIME_HUMAN}},  1 user,  load average: 0.38, 0.42, 0.45\n"
        ok = " 07:16:27 up 42 days,  3:17,  1 user,  load average: 0.38, 0.42, 0.45\n"
        later = " 07:16:27 up 43 days, 11:02,  1 user,  load average: 0.38, 0.42, 0.45\n"
        self.assertTrue(check(tpl, ok).ok)
        self.assertTrue(check(tpl, later).ok)

    def test_human_uptime_below_anchor_or_wrong_shape_is_rejected(self):
        tpl = " {{HH:MM:SS}} {{UPTIME_HUMAN}},  1 user,  load average: 0.38, 0.42, 0.45\n"
        for bad in (
            " 07:16:27 up 41 days, 23:59,  1 user,  load average: 0.38, 0.42, 0.45\n",
            # The pin: Cowrie's own process uptime.
            " 07:16:27 up 11 min,  1 user,  load average: 0.38, 0.42, 0.45\n",
            # v3.1.1: double space before "up".
            " 07:16:27  up 42 days,  3:17,  1 user,  load average: 0.38, 0.42, 0.45\n",
        ):
            with self.subTest(bad=bad):
                self.assertFalse(check(tpl, bad).ok)

    def test_advances_requires_strict_increase(self):
        tpl = "#harness: advances\n{{UPTIME_SECS}} {{IDLE_SECS}}\n{{UPTIME_SECS}} {{IDLE_SECS}}\n"
        moving = "3640620.00 13979980.80\n3640622.01 13979988.10\n"
        static = "3640620.00 13979980.80\n3640620.00 13979980.80\n"
        self.assertTrue(check(tpl, moving).ok)
        res = check(tpl, static)
        self.assertFalse(res.ok)
        self.assertTrue(any("advance" in m for m in res.messages), res.messages)


class LastShapeTest(unittest.TestCase):
    def test_persona_history_matches_by_shape(self):
        self.assertTrue(check(LAST_TEMPLATE, PERSONA_LAST).ok)

    def test_other_dates_match_too(self):
        shifted = PERSONA_LAST.replace("Mon Oct  5 02:22", "Sat Dec 19 23:59")
        self.assertTrue(check(LAST_TEMPLATE, shifted).ok)

    def test_the_callers_own_session_is_rejected(self):
        # v3.1.1 lists the attacker's own exec session.
        own = (
            "root     pts/0        127.0.0.1        Mon Oct  5 07:11   still logged in\n"
            "\n"
            "wtmp begins Mon Aug 24 05:52:26 2026\n"
        )
        self.assertFalse(check(LAST_TEMPLATE, own).ok)

    def test_wrong_date_shape_is_rejected(self):
        bad = PERSONA_LAST.replace("Mon Oct  5 02:22", "2026-10-05 02:22")
        self.assertFalse(check(LAST_TEMPLATE, bad).ok)

    def test_fixed_session_lengths_are_not_volatile(self):
        bad = PERSONA_LAST.replace("(02:43)", "(02:44)")
        self.assertFalse(check(LAST_TEMPLATE, bad).ok)


class ExactComparisonTest(unittest.TestCase):
    def test_regex_metacharacters_are_literal(self):
        tpl = "CPU_MODEL:Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n"
        self.assertTrue(check(tpl, tpl).ok)
        self.assertFalse(check(tpl, "CPU_MODEL:IntelR XeonR CPU E5-2676 v3 @ 2.40GHz\n").ok)

    def test_mismatch_produces_unified_diff(self):
        res = check("ARCH:x86_64\nCPUS:4\n", "ARCH:\nCPUS:4\n")
        self.assertFalse(res.ok)
        text = "\n".join(res.diff)
        self.assertIn("-ARCH:x86_64", text)
        self.assertIn("+ARCH:", text)
        self.assertIn("@@", text)

    def test_matched_volatile_lines_do_not_clutter_the_diff(self):
        tpl = "UPTIME:{{UPTIME_SECS}} {{IDLE_SECS}}\nGPU:00:02.0 VGA\n"
        res = check(tpl, "UPTIME:3640650.00 1.00\nGPU:\n")
        text = "\n".join(res.diff)
        self.assertIn(" UPTIME:{{UPTIME_SECS}} {{IDLE_SECS}}", text)
        self.assertNotIn("+UPTIME", text)
        self.assertIn("+GPU:", text)

    def test_trailing_newline_is_significant(self):
        self.assertFalse(check("root\n", "root").ok)

    def test_carriage_returns_are_a_mismatch_and_shown_escaped(self):
        res = check("root\n", "root\r\n")
        self.assertFalse(res.ok)
        self.assertIn("+root\\r", "\n".join(res.diff))

    def test_rc_directive(self):
        tpl = "#harness: rc=1\nno crontab for root\n"
        self.assertTrue(check(tpl, "no crontab for root\n", rc=1).ok)
        res = check(tpl, "no crontab for root\n", rc=0)
        self.assertFalse(res.ok)
        self.assertTrue(any("exit status" in m for m in res.messages), res.messages)

    def test_rc_is_ignored_without_directive(self):
        self.assertTrue(check("x\n", "x\n", rc=7).ok)

    def test_timeout_fails(self):
        res = check("x\n", "x\n", timed_out=True)
        self.assertFalse(res.ok)
        self.assertTrue(any("timed out" in m for m in res.messages), res.messages)

    def test_empty_expected_output(self):
        tpl = "#harness: rc=1\n"
        self.assertTrue(check(tpl, "", rc=1).ok)
        self.assertFalse(check(tpl, "Miner\n", rc=1).ok)

    def test_unknown_token_is_an_error(self):
        with self.assertRaises(ValueError):
            cbt.parse_expected("{{NOPE}}\n")

    def test_unknown_directive_is_an_error(self):
        with self.assertRaises(ValueError):
            cbt.parse_expected("#harness: frobnicate\nx\n")

    def test_skip_directive(self):
        exp = cbt.parse_expected("#harness: skip=deferred (factsheet 5 #17)\nwhatever\n")
        self.assertEqual(exp.skip, "deferred (factsheet 5 #17)")


class MainExitCodeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        (root / "expected").mkdir()
        (root / "profiler.sh").write_text("echo hi")
        (root / "expected" / "profiler.out").write_text("hi\n")
        (root / "probes.txt").write_text(
            "# comment\n\nwho-am-i\twhoami\ncron\tcrontab -l\ngone\tifconfig\n"
        )
        (root / "expected" / "who-am-i.out").write_text("root\n")
        (root / "expected" / "cron.out").write_text("#harness: rc=1\nno crontab for root\n")
        (root / "expected" / "gone.out").write_text("#harness: skip=not planned\n")
        userdb = root / "userdb.txt"
        userdb.write_text("root:x:pw\n")
        self.root = root
        self.argv = [
            "--host", "127.0.0.1", "--port", "2299",
            "--password-from", str(userdb), "--cases-dir", str(root),
        ]

    def run_main(self, answers, extra=()):
        calls = []

        def runner(command, timeout):
            calls.append(command)
            return answers[command]

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cbt.main(self.argv + list(extra), runner=runner)
        return rc, out.getvalue(), calls

    def good(self):
        return {
            "echo hi": cbt.RunResult("hi\n", 0, False),
            "whoami": cbt.RunResult("root\n", 0, False),
            "crontab -l": cbt.RunResult("no crontab for root\n", 1, False),
        }

    def test_all_match_exits_zero_and_skips_are_not_run(self):
        rc, out, calls = self.run_main(self.good())
        self.assertEqual(rc, 0, out)
        self.assertNotIn("ifconfig", calls)
        self.assertIn("SKIP", out)

    def test_exact_mismatch_prints_diff_and_exits_one(self):
        answers = self.good()
        answers["whoami"] = cbt.RunResult("phil\n", 0, False)
        rc, out, _ = self.run_main(answers)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL who-am-i", out)
        self.assertIn("-root", out)
        self.assertIn("+phil", out)

    def test_only_profiler(self):
        rc, out, calls = self.run_main(self.good(), ["--only", "profiler"])
        self.assertEqual(rc, 0, out)
        self.assertEqual(calls, ["echo hi"])

    def test_only_probes(self):
        rc, _, calls = self.run_main(self.good(), ["--only", "probes"])
        self.assertEqual(rc, 0)
        self.assertNotIn("echo hi", calls)

    def test_missing_expected_file_fails(self):
        (self.root / "expected" / "who-am-i.out").unlink()
        rc, out, _ = self.run_main(self.good())
        self.assertEqual(rc, 1)
        self.assertIn("who-am-i", out)


class FakeChannel:
    """Just enough of paramiko.Channel for exec_on_channel."""

    def __init__(self, chunks, rc, raise_on_exec=False, never_close=False):
        self.chunks = list(chunks)
        self.rc = rc
        self.raise_on_exec = raise_on_exec
        self.never_close = never_close
        self.eof_received = False
        self.closed = False

    def exec_command(self, command):
        if self.raise_on_exec:
            raise ClosedError("Channel closed.")

    def recv_ready(self):
        return bool(self.chunks)

    def recv(self, n):
        data = self.chunks.pop(0)
        if not self.chunks and not self.never_close:
            self.eof_received = self.closed = True
        return data

    def recv_stderr_ready(self):
        return False

    def exit_status_ready(self):
        return self.closed

    def recv_exit_status(self):
        return self.rc


class ClosedError(Exception):
    pass


class ExecOnChannelTest(unittest.TestCase):
    def test_closed_before_exec_ack_still_returns_buffered_output(self):
        # Cowrie on the pin: data + exit status arrive, exec_command raises.
        chan = FakeChannel([b"root\n"], 0, raise_on_exec=True)
        res = cbt.exec_on_channel(chan, "whoami", time.monotonic() + 5, ClosedError)
        self.assertEqual(res, cbt.RunResult("root\n", 0, False))

    def test_hung_session_times_out(self):
        chan = FakeChannel([b"Enter new UNIX password: "], None, never_close=True)
        res = cbt.exec_on_channel(chan, "passwd", time.monotonic() + 0.2, ClosedError)
        self.assertTrue(res.timed_out)
        self.assertEqual(res.output, "Enter new UNIX password: ")


class InputParsingTest(unittest.TestCase):
    def test_parse_probes(self):
        probes = cbt.parse_probes("# c\n\na\techo 'x' | cat\nb\tuname -a ; echo 'vT'\n")
        self.assertEqual(probes, [("a", "echo 'x' | cat"), ("b", "uname -a ; echo 'vT'")])

    def test_parse_probes_rejects_bad_lines_and_duplicates(self):
        with self.assertRaises(ValueError):
            cbt.parse_probes("no-tab-here\n")
        with self.assertRaises(ValueError):
            cbt.parse_probes("a\tx\na\ty\n")
        with self.assertRaises(ValueError):
            cbt.parse_probes("profiler\tx\n")

    def test_password_from_userdb_takes_first_literal(self):
        db = (
            "# comment\n"
            "*:x:!/honeypot|cowrie/i\n"
            "root:x:!root\n"
            "root:x:/^r.*$/\n"
            "root:x:*\n"
            "root:x:3245gs5662d34\n"
            "root:x:123456\n"
            "admin:x:admin\n"
        )
        self.assertEqual(cbt.password_from_userdb(db, "root"), "3245gs5662d34")
        self.assertEqual(cbt.password_from_userdb(db, "admin"), "admin")
        with self.assertRaises(ValueError):
            cbt.password_from_userdb(db, "nobody")

    def test_shipped_userdb_gives_a_root_password(self):
        db = (HERE.parent / "install" / "persona" / "userdb.txt").read_text()
        self.assertEqual(cbt.password_from_userdb(db, "root"), "3245gs5662d34")


class ShippedCasesTest(unittest.TestCase):
    """The case files every later task appends to must stay well-formed."""

    def test_profiler_is_the_verbatim_3273_byte_variant(self):
        data = (CASES_DIR / "profiler.sh").read_bytes()
        self.assertEqual(len(data), 3273)
        self.assertTrue(data.startswith(b"export PATH=/usr/local/sbin"))
        self.assertTrue(data.endswith(b'echo "FILTER:$filter_output"'))

    def test_every_case_has_a_parseable_expected_file_and_no_orphans(self):
        probes = cbt.parse_probes((CASES_DIR / "probes.txt").read_text())
        names = {"profiler"} | {name for name, _ in probes}
        files = {p.stem for p in (CASES_DIR / "expected").glob("*.out")}
        self.assertEqual(names, files)
        for name in names:
            with self.subTest(case=name):
                cbt.parse_expected((CASES_DIR / "expected" / f"{name}.out").read_text())

    def test_profiler_expected_is_the_real_column(self):
        exp = cbt.parse_expected((CASES_DIR / "expected" / "profiler.out").read_text())
        self.assertIsNone(exp.skip)
        real = (
            "UNAME:Linux prod-app-server-01 #104-Ubuntu SMP Tue Jan 9 15:25:40 UTC 2024 x86_64\n"
            "ARCH:x86_64\n"
            "UPTIME:3640620.00 13979980.80\n"
            "CPUS:4\n"
            "CPU_MODEL:Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n"
            "GPU:00:02.0 VGA compatible controller: Cirrus Logic GD 5446\n"
            "LAST:ubuntu   pts/0        10.0.0.8         Mon Oct  5 02:22   still logged in\n"
            "ubuntu   pts/0        10.0.0.8         Sun Oct  4 00:43   - 03:26  (02:43)\n"
            "ubuntu   pts/1        10.0.0.12        Sat Oct  3 19:12   - 19:55  (00:43)\n"
            "ubuntu   pts/0        10.0.0.8         Sat Oct  3 00:14   - 02:02  (01:48)\n"
            "ubuntu   pts/0        10.0.0.8         Thu Oct  1 13:08   - 14:34  (01:26)\n"
            "ubuntu   pts/0        10.0.0.8         Wed Sep 30 10:26   - 11:49  (01:23)\n"
            "reboot   system boot  5.15.0-94-generi Mon Aug 24 05:52   still running\n"
            "\n"
            "wtmp begins Mon Aug 24 05:52:26 2026\n"
            "FILTER:===SHELL_BEHAVIOR===\n"
            "path_err=bash: line 9: ./xxxxxx: No such file or directory\n"
            "cmd_err=bash: line 9: xxxxxx: command not found\n"
            "execute_err=xxxxxx\n"
            "===DONE===\n"
        )
        # Captured from ubuntu:22.04 bash 5.1.16 with the persona's uname,
        # nproc, lscpu, lspci, last and /proc files substituted (factsheet 0).
        res = cbt.compare("profiler", exp, real, 0, False)
        self.assertTrue(res.ok, "\n".join(res.diff + res.messages))


if __name__ == "__main__":
    unittest.main()
