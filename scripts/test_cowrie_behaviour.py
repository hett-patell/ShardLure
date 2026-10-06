"""Unit tests for the Cowrie behavioural harness's own comparison logic.

These need no network and no Cowrie: the harness's transport is replaced by a
fake runner and the clock is fixed. They pin the normaliser (which fields are
volatile and how each is tied to the persona clock), the diff/exit-code
contract every later Phase B task relies on, and the consistency of the
shipped case files.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import time
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "cowrie_behaviour_test", HERE / "cowrie-behaviour-test.py"
)
cbt = importlib.util.module_from_spec(_spec)
# dataclasses resolve annotations through sys.modules, so register first.
sys.modules[_spec.name] = cbt
_spec.loader.exec_module(cbt)

_gspec = importlib.util.spec_from_file_location(
    "gen_time_persona", HERE.parent / "install" / "persona" / "gen-time-persona.py"
)
gtp = importlib.util.module_from_spec(_gspec)
_gspec.loader.exec_module(gtp)

CASES_DIR = HERE / "behaviour"
ANCHOR = 3640620
# The instant the ubuntu:22.04 reference run in ShippedCasesTest was taken.
REF_NOW = datetime(2026, 10, 5, 9, 9, 26, tzinfo=timezone.utc)
NOW = datetime(2026, 10, 5, 9, 0, 0, tzinfo=timezone.utc)


def clock(now=NOW, run_seconds=0.0, slack=cbt.DEFAULT_UPTIME_SLACK, age=None):
    return cbt.Clock(start=now, end=now + timedelta(seconds=run_seconds),
                     uptime_slack=slack, cowrie_age=age)


def check(template: str, actual: str, rc: int = 0, timed_out: bool = False, clk=None):
    return cbt.compare("case", cbt.parse_expected(template), actual, rc, timed_out,
                       clk or clock())


def persona(now=NOW) -> dict:
    """The persona's own time files, generated for `now` (naive UTC)."""
    return gtp.build(now.replace(tzinfo=None))


def persona_last(now=NOW, uptime=ANCHOR) -> str:
    """last(1) as a correct honeypot prints it: sessions anchored to now (the
    persona's offsets), the reboot row and "wtmp begins" at now - uptime."""
    rows = persona(now)["share/cowrie/txtcmds/usr/bin/last"].split("\n")
    boot = now - timedelta(seconds=uptime)
    out = []
    for row in rows:
        if row.startswith("reboot"):
            row = row[:39] + f"{boot:%a %b %e %H:%M}" + row[55:]
        elif row.startswith("wtmp begins"):
            row = f"wtmp begins {boot:%a %b %e %H:%M:%S %Y}"
        out.append(row)
    return "\n".join(out)


def profiler_output(now=NOW, uptime=ANCHOR + 12.34, last=None) -> str:
    idle = uptime * 3.88
    if last is None:
        last = persona_last(now, uptime)
    return (
        "UNAME:Linux prod-app-server-01 #104-Ubuntu SMP Tue Jan 9 15:25:40 UTC 2024 x86_64\n"
        "ARCH:x86_64\n"
        f"UPTIME:{uptime:.2f} {idle:.2f}\n"
        "CPUS:4\n"
        "CPU_MODEL:Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n"
        "GPU:00:02.0 VGA compatible controller: Cirrus Logic GD 5446\n"
        f"LAST:{last.rstrip(chr(10))}\n"
        "FILTER:===SHELL_BEHAVIOR===\n"
        "path_err=bash: line 9: ./xxxxxx: No such file or directory\n"
        "cmd_err=bash: line 9: xxxxxx: command not found\n"
        "execute_err=xxxxxx\n"
        "===DONE===\n"
    )


def profiler_check(output, clk=None):
    exp = cbt.parse_expected((CASES_DIR / "expected" / "profiler.out").read_text())
    return cbt.compare("profiler", exp, output, 0, False, clk or clock())


UPTIME_TPL = "UPTIME:{{UPTIME_SECS}} {{IDLE_SECS}}\n"
HUMAN_TPL = " {{NOW_HMS}} {{UPTIME_HUMAN}},  1 user,  load average: 0.38, 0.42, 0.45\n"


def uptime_line(now=NOW, human="up 42 days,  3:17", sep=" "):
    return f" {now:%H:%M:%S}{sep}{human},  1 user,  load average: 0.38, 0.42, 0.45\n"


class UptimeBoundsTest(unittest.TestCase):
    def test_anchor_itself_is_accepted(self):
        self.assertTrue(check(UPTIME_TPL, "UPTIME:3640620.00 13979980.80\n").ok)

    def test_value_just_past_the_anchor_is_accepted(self):
        # v3.1.1 with boot_offset = 3640620, a few seconds after start.
        self.assertTrue(check(UPTIME_TPL, "UPTIME:3640632.78 14125655.18\n").ok)

    def test_zero_and_below_anchor_are_rejected(self):
        for val in ("0.00", "3640619.99"):
            with self.subTest(val=val):
                res = check(UPTIME_TPL, f"UPTIME:{val} 1.00\n")
                self.assertFalse(res.ok)
                self.assertTrue(any("anchor" in m for m in res.messages), res.messages)

    def test_far_past_the_anchor_is_rejected(self):
        # I-2: 1000 days, or any v3.1.1 random boot_offset draw above 42d,
        # disagrees with the persona's "up 42 days" motd/last.
        for val in ("86400000.00", "999999999999.00", "5000000.00"):
            with self.subTest(val=val):
                self.assertFalse(check(UPTIME_TPL, f"UPTIME:{val} 1.00\n").ok)

    def test_slack_is_the_upper_bound(self):
        inside = ANCHOR + cbt.DEFAULT_UPTIME_SLACK
        self.assertTrue(check(UPTIME_TPL, f"UPTIME:{inside:.2f} 1.00\n").ok)
        self.assertFalse(check(UPTIME_TPL, f"UPTIME:{inside + 1:.2f} 1.00\n").ok)
        # An operator checking a long-running prod Cowrie widens it explicitly.
        wide = clock(slack=30 * 86400)
        self.assertTrue(check(UPTIME_TPL, f"UPTIME:{ANCHOR + 20 * 86400:.2f} 1.00\n", clk=wide).ok)

    def test_empty_field_is_rejected(self):
        # The pin's headline failure: every field after UNAME is empty.
        res = check(UPTIME_TPL, "UPTIME:\n")
        self.assertFalse(res.ok)
        self.assertTrue(res.diff)

    def test_advances_requires_a_plausible_step(self):
        tpl = ("#harness: advances=1.5..6\n"
               "{{UPTIME_SECS}} {{IDLE_SECS}}\n{{UPTIME_SECS}} {{IDLE_SECS}}\n")
        clk = clock(run_seconds=2.3)
        self.assertTrue(check(tpl, "3640620.00 1.00\n3640622.01 9.00\n", clk=clk).ok)
        for second in ("3640620.00", "3640619.00", "3640720.00", "3640621.00"):
            with self.subTest(second=second):
                res = check(tpl, f"3640620.00 1.00\n{second} 9.00\n", clk=clk)
                self.assertFalse(res.ok)
                self.assertTrue(any("advance" in m for m in res.messages), res.messages)

    def test_bad_advances_directive(self):
        with self.assertRaises(ValueError):
            cbt.parse_expected("#harness: advances=6..1\nx\n")


class CowrieAgeWindowTest(unittest.TestCase):
    """--cowrie-age: production uptime = boot_offset + process age, two-sided."""
    AGE = 30 * 86400

    def test_correct_age_passes(self):
        clk = clock(age=self.AGE)
        for u in (ANCHOR + self.AGE, ANCHOR + self.AGE + 600, ANCHOR + self.AGE - 600):
            with self.subTest(u=u):
                self.assertTrue(check(UPTIME_TPL, f"UPTIME:{u:.2f} 1.00\n", clk=clk).ok)

    def test_random_boot_offset_fails(self):
        # Review re-round: a forgotten boot_offset (random 1-90 d) plus a 30 d
        # process age used to fit [anchor, anchor + age] about 34% of the time.
        clk = clock(age=self.AGE)
        for offset_days in (12, 20, 41, 42.2, 60, 89):
            u = offset_days * 86400 + self.AGE
            with self.subTest(offset_days=offset_days):
                res = check(UPTIME_TPL, f"UPTIME:{u:.2f} 1.00\n", clk=clk)
                self.assertFalse(res.ok)
                self.assertTrue(any("anchor" in m for m in res.messages), res.messages)

    def test_margin_is_900_seconds_each_side(self):
        clk = clock(age=self.AGE)
        base = ANCHOR + self.AGE
        self.assertTrue(check(UPTIME_TPL, f"UPTIME:{base + 900:.2f} 1.00\n", clk=clk).ok)
        self.assertFalse(check(UPTIME_TPL, f"UPTIME:{base + 901:.2f} 1.00\n", clk=clk).ok)
        self.assertFalse(check(UPTIME_TPL, f"UPTIME:{base - 901:.2f} 1.00\n", clk=clk).ok)

    def test_human_uptime_uses_the_same_window(self):
        clk = clock(age=self.AGE)
        good = cbt._format_human(ANCHOR + self.AGE)
        self.assertTrue(check(HUMAN_TPL, uptime_line(human=good), clk=clk).ok)
        self.assertFalse(check(HUMAN_TPL, uptime_line(), clk=clk).ok)

    def test_profiler_with_age_passes(self):
        u = ANCHOR + self.AGE + 12.34
        res = profiler_check(profiler_output(uptime=u), clock(age=self.AGE))
        self.assertTrue(res.ok, "\n".join(res.diff + res.messages))


class HumanUptimeTest(unittest.TestCase):
    def test_anchor_and_later_hours_pass(self):
        self.assertTrue(check(HUMAN_TPL, uptime_line()).ok)
        self.assertTrue(check(HUMAN_TPL, uptime_line(human="up 42 days,  8:59")).ok)

    def test_minute_only_form_passes(self):
        # M-1: procps prints "up 42 days, 17 min" when the hour field is 0.
        # With a 6 h slack that form is reachable only under a wider slack.
        wide = clock(slack=86400)
        self.assertTrue(check(HUMAN_TPL, uptime_line(human="up 43 days, 17 min"), clk=wide).ok)

    def test_double_digit_hours_pass(self):
        wide = clock(slack=86400)
        self.assertTrue(check(HUMAN_TPL, uptime_line(human="up 42 days, 13:05"), clk=wide).ok)

    def test_wrong_spacing_is_rejected(self):
        # M-1: procps pads the hour with %2d.
        self.assertFalse(check(HUMAN_TPL, uptime_line(human="up 42 days, 3:17")).ok)
        self.assertFalse(check(HUMAN_TPL, uptime_line(human="up 42 days,   3:17")).ok)

    def test_below_or_far_past_anchor_is_rejected(self):
        for human in ("up 41 days, 23:59", "up 11 min", "up 1000 days,  3:17",
                      "up 43 days,  3:17"):
            with self.subTest(human=human):
                self.assertFalse(check(HUMAN_TPL, uptime_line(human=human)).ok)

    def test_v311_double_space_before_up_is_rejected(self):
        self.assertFalse(check(HUMAN_TPL, uptime_line(sep="  ")).ok)

    def test_clock_must_be_now(self):
        # I-1: the HH:MM:SS of uptime/w is the current time, within 2 min.
        self.assertTrue(check(HUMAN_TPL, uptime_line(now=NOW + timedelta(seconds=90))).ok)
        res = check(HUMAN_TPL, uptime_line(now=NOW - timedelta(hours=3)))
        self.assertFalse(res.ok)
        self.assertTrue(any("clock" in m for m in res.messages), res.messages)

    def test_clock_just_before_a_midnight_start(self):
        clk = clock(now=datetime(2026, 10, 6, 0, 0, 30, tzinfo=timezone.utc))
        line = uptime_line(now=datetime(2026, 10, 5, 23, 59, 50, tzinfo=timezone.utc))
        self.assertTrue(check(HUMAN_TPL, line, clk=clk).ok)

    def test_clock_wraps_midnight(self):
        clk = clock(now=datetime(2026, 10, 5, 23, 59, 30, tzinfo=timezone.utc), run_seconds=60)
        line = uptime_line(now=datetime(2026, 10, 6, 0, 0, 10, tzinfo=timezone.utc))
        self.assertTrue(check(HUMAN_TPL, line, clk=clk).ok)


# Column offsets of last(1) rows as gen-time-persona writes them:
# "%-8s %-12s %-16s " then the 16-char "%a %b %e %H:%M", 3 spaces, "- HH:MM".
WHEN = 8 + 1 + 12 + 1 + 16 + 1
LOGOUT = WHEN + 16 + 3 + 2


class LastAgainstPersonaClockTest(unittest.TestCase):
    def test_session_before_boot_is_rejected_without_a_reboot_row(self):
        # With no reboot row to order against, boot comes from the anchor.
        tpl = "{{LAST_LOGIN}}\n"
        ok = NOW - timedelta(days=3)
        old = NOW - timedelta(days=50)
        self.assertTrue(check(tpl, f"{ok:%a %b %e %H:%M}\n").ok)
        res = check(tpl, f"{old:%a %b %e %H:%M}\n")
        self.assertFalse(res.ok)
        self.assertTrue(any("between boot and now" in m for m in res.messages), res.messages)

    def test_reference_output_passes(self):
        res = profiler_check(profiler_output())
        self.assertTrue(res.ok, "\n".join(res.diff + res.messages))

    def test_reference_passes_on_another_day(self):
        now = datetime(2027, 3, 1, 0, 30, tzinfo=timezone.utc)
        res = profiler_check(profiler_output(now=now), clock(now=now))
        self.assertTrue(res.ok, "\n".join(res.diff + res.messages))

    def test_cowrie_pin_wtmp_begins_today_is_rejected(self):
        # I-1: the pin's last.py prints logintime//86400*86400+63.
        last = persona()["share/cowrie/txtcmds/usr/bin/last"]
        head, _, _ = last.rpartition("wtmp begins ")
        bad = head + "wtmp begins Mon Oct  5 00:01:03 2026\n"
        res = profiler_check(profiler_output(last=bad))
        self.assertFalse(res.ok)
        self.assertTrue(any("wtmp" in m for m in res.messages), res.messages)

    def test_all_today_history_is_rejected(self):
        # I-1: every session stamped today (a patch that drops the caller but
        # keeps today-relative dates) must not pass.
        rows = [
            "ubuntu   pts/0        10.0.0.8         Mon Oct  5 02:22   still logged in",
            "ubuntu   pts/0        10.0.0.8         Mon Oct  5 01:43   - 04:26  (02:43)",
            "ubuntu   pts/1        10.0.0.12        Mon Oct  5 01:12   - 01:55  (00:43)",
            "ubuntu   pts/0        10.0.0.8         Mon Oct  5 01:00   - 02:48  (01:48)",
            "ubuntu   pts/0        10.0.0.8         Mon Oct  5 00:40   - 02:06  (01:26)",
            "ubuntu   pts/0        10.0.0.8         Mon Oct  5 00:20   - 01:43  (01:23)",
        ]
        boot = NOW - timedelta(seconds=ANCHOR + 12.34)
        last = ("\n".join(rows)
                + f"\nreboot   system boot  5.15.0-94-generi {boot:%a %b %e %H:%M}   still running\n"
                + f"\nwtmp begins {boot:%a %b %e %H:%M:%S %Y}\n")
        res = profiler_check(profiler_output(last=last))
        self.assertFalse(res.ok)

    def test_malformed_feb_29_fails_the_case_without_crashing(self):
        # Review m-1: "Feb 29" in a non-leap year raised from dt.replace().
        last = persona()["share/cowrie/txtcmds/usr/bin/last"]
        head, _, _ = last.rpartition("wtmp begins ")
        bad = head + "wtmp begins Tue Feb 29 05:43:00 2027\n"
        res = profiler_check(profiler_output(last=bad))
        self.assertFalse(res.ok)
        self.assertTrue(any("invalid date" in m for m in res.messages), res.messages)

    def test_reboot_not_at_now_minus_uptime_is_rejected(self):
        last = persona(NOW - timedelta(days=3))["share/cowrie/txtcmds/usr/bin/last"]
        res = profiler_check(profiler_output(last=last))
        self.assertFalse(res.ok)
        self.assertTrue(any("boot" in m for m in res.messages), res.messages)

    def test_history_out_of_order_is_rejected(self):
        rows = persona()["share/cowrie/txtcmds/usr/bin/last"].split("\n")
        # Swap only the login dates of two completed rows (same tty/ip text).
        a, b = rows[3], rows[4]
        rows[3] = a[:WHEN] + b[WHEN:WHEN + 16] + a[WHEN + 16:]
        rows[4] = b[:WHEN] + a[WHEN:WHEN + 16] + b[WHEN + 16:]
        res = profiler_check(profiler_output(last="\n".join(rows)))
        self.assertFalse(res.ok)
        self.assertTrue(any("order" in m for m in res.messages), res.messages)

    def test_weekday_must_match_date(self):
        last = persona()["share/cowrie/txtcmds/usr/bin/last"]
        first = last.split("\n")[0]
        day = first[WHEN:WHEN + 3]
        wrong = first[:WHEN] + ("Sun" if day != "Sun" else "Mon") + first[WHEN + 3:]
        res = profiler_check(profiler_output(last=last.replace(first, wrong)))
        self.assertFalse(res.ok)
        self.assertTrue(any("weekday" in m for m in res.messages), res.messages)

    def test_logout_must_equal_login_plus_duration(self):
        last = persona()["share/cowrie/txtcmds/usr/bin/last"]
        row = last.split("\n")[1]
        hhmm = row[LOGOUT:LOGOUT + 5]
        h, m = int(hhmm[:2]), int(hhmm[3:])
        wrong = row[:LOGOUT] + f"{(h + 1) % 24:02d}:{m:02d}" + row[LOGOUT + 5:]
        res = profiler_check(profiler_output(last=last.replace(row, wrong)))
        self.assertFalse(res.ok)
        self.assertTrue(any("logout" in m for m in res.messages), res.messages)

    def test_current_session_must_be_recent(self):
        last = persona()["share/cowrie/txtcmds/usr/bin/last"]
        first = last.split("\n")[0]
        old = NOW - timedelta(hours=20)
        wrong = first[:WHEN] + f"{old:%a %b %e %H:%M}" + first[WHEN + 16:]
        res = profiler_check(profiler_output(last=last.replace(first, wrong)))
        self.assertFalse(res.ok)
        self.assertTrue(any("12 h" in m for m in res.messages), res.messages)

    def test_the_callers_own_session_is_rejected(self):
        # v3.1.1 lists the attacker's own exec session.
        last = persona()["share/cowrie/txtcmds/usr/bin/last"]
        own = "root     pts/0        127.0.0.1        Mon Oct  5 08:59   still logged in\n" + last
        self.assertFalse(profiler_check(profiler_output(last=own)).ok)

    def test_fixed_session_lengths_are_not_volatile(self):
        last = persona()["share/cowrie/txtcmds/usr/bin/last"].replace("(02:43)", "(02:44)")
        self.assertFalse(profiler_check(profiler_output(last=last)).ok)


W_TPL_PATH = CASES_DIR / "expected" / "w.out"


def w_output(now=NOW, login=None, idle="  6:47m", what="-bash", uptime_human="up 42 days,  3:17"):
    login = login or (now - timedelta(hours=6, minutes=47))
    return (
        uptime_line(now=now, human=uptime_human)
        + "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
        + f"ubuntu   pts/0    10.0.0.8         {login:%H:%M}  {idle}  0.04s  0.01s {what}\n"
    )


def w_check(output, clk=None):
    return cbt.compare("w", cbt.parse_expected(W_TPL_PATH.read_text()), output, 0, False,
                       clk or clock())


class WRowTest(unittest.TestCase):
    def test_login_shell_row_passes_with_any_procps_idle(self):
        for idle in ("  6:47m", "  0.00s", " 12:05 ", "  1:02m", " 59.99s"):
            with self.subTest(idle=idle):
                res = w_check(w_output(idle=idle))
                self.assertTrue(res.ok, "\n".join(res.diff + res.messages))

    def test_persona_quirk_of_ubuntu_running_w_is_rejected(self):
        self.assertFalse(w_check(w_output(idle="  0.00s", what="w")).ok)

    def test_idle_longer_than_the_session_is_rejected(self):
        res = w_check(w_output(idle="  9:00m"))
        self.assertFalse(res.ok)
        self.assertTrue(any("idle" in m for m in res.messages), res.messages)

    def test_login_more_than_12h_ago_is_rejected(self):
        res = w_check(w_output(login=NOW - timedelta(hours=13), idle="  0.00s"))
        self.assertFalse(res.ok)
        self.assertTrue(any("12 h" in m for m in res.messages), res.messages)

    def test_login_in_the_future_is_rejected(self):
        # HH:MM later today than now reads as yesterday: >12 h ago.
        res = w_check(w_output(login=NOW + timedelta(minutes=30), idle="  0.00s"))
        self.assertFalse(res.ok)
        self.assertTrue(any("12 h" in m for m in res.messages), res.messages)

    def test_the_pins_own_w_is_rejected(self):
        pin = (" 09:00:00 up 6 min,  1 user,  load average: 0.00, 0.00, 0.00\n"
               "USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT\n"
               "root     pts/0    127.0.0.1         09:00    0.00s  0.00s  0.00s w\n")
        self.assertFalse(w_check(pin).ok)


LS_TPL = "-rwxr-xr-x 1 root root 135K {{LSDATE}} /usr/bin/ls\n"


class LsDateTest(unittest.TestCase):
    def test_old_package_date_passes(self):
        self.assertTrue(check(LS_TPL, "-rwxr-xr-x 1 root root 135K Feb  7  2022 /usr/bin/ls\n").ok)

    def test_todays_date_is_rejected(self):
        # M-2: a node stamped with Cowrie's start time.
        self.assertFalse(check(LS_TPL, f"-rwxr-xr-x 1 root root 135K {NOW:%b %e %H:%M} /usr/bin/ls\n").ok)

    def test_recent_year_form_is_rejected(self):
        self.assertFalse(check(LS_TPL, f"-rwxr-xr-x 1 root root 135K {NOW:%b %e  %Y} /usr/bin/ls\n").ok)


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

    def test_rc_defaults_to_zero(self):
        # M-3: every case has a known real exit status; 0 unless declared.
        self.assertTrue(check("x\n", "x\n", rc=0).ok)
        for rc in (7, None):
            with self.subTest(rc=rc):
                res = check("x\n", "x\n", rc=rc)
                self.assertFalse(res.ok)
                self.assertTrue(any("exit status" in m for m in res.messages), res.messages)

    def test_unacknowledged_exec_is_explained(self):
        # M-4: a refused exec request must not read as plain empty output.
        exp = cbt.parse_expected("x\n")
        run = cbt.RunResult("", None, False, note="exec request not acknowledged")
        res = cbt.compare("case", exp, run.output, run.rc, run.timed_out, clock(), run.note)
        self.assertTrue(any("not acknowledged" in m for m in res.messages), res.messages)

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


class HostMemtotalTest(unittest.TestCase):
    """free must never render the Cowrie host's own memory (factsheet 3 #11)."""

    ARM = "MemTotal:       24548180 kB\nMemFree:  1 kB\n"

    def tokens(self):
        return cbt.host_memtotal_tokens(self.ARM)

    def test_v311_leak_shapes_are_caught(self):
        # What stock v3.1.1 printed on arm: free -m (/1000) and free (kB).
        for leak in ("Mem:          24548   2645", "Mem:       24548180     1",
                     "Mem: 23972 1", "Mem: 23Gi 1", "Mem: 23.4Gi", "Mem: 24G"):
            with self.subTest(leak=leak):
                self.assertTrue(cbt.leaked_host_tokens(leak, self.tokens()))

    def test_persona_output_is_clean(self):
        persona_free = (
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:         8039340     1564336     4192784         528     2282220     6258412\n"
            "Swap:              0           0           0\n"
            "Mem:           7.7Gi       1.5Gi       4.0Gi       0.0Ki       2.2Gi       6.0Gi\n"
            "7850 1527 4094 0 2228 6111\n"
        )
        self.assertEqual(cbt.leaked_host_tokens(persona_free, self.tokens()), [])

    def test_tokens_are_whole_words(self):
        self.assertEqual(cbt.leaked_host_tokens("x245481800 1245480", self.tokens()), [])

    def test_missing_memtotal_is_an_error(self):
        with self.assertRaises(ValueError):
            cbt.host_memtotal_tokens("MemFree: 1 kB\n")

    def test_directive_parses(self):
        exp = cbt.parse_expected("#harness: no-host-memtotal\nx\n")
        self.assertTrue(exp.no_host_memtotal)
        self.assertEqual(exp.content, "x\n")

    def run_free(self, output, meminfo):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "expected").mkdir()
            (root / "profiler.sh").write_text("echo hi")
            (root / "expected" / "profiler.out").write_text("#harness: skip=x\n")
            (root / "probes.txt").write_text("free\tfree\n")
            (root / "expected" / "free.out").write_text(
                "#harness: no-host-memtotal\n" + output)
            (root / "userdb.txt").write_text("root:x:pw\n")
            argv = ["--host", "127.0.0.1", "--port", "2299", "--cases-dir", str(root),
                    "--password-from", str(root / "userdb.txt"),
                    "--host-meminfo", str(root / "meminfo")]
            if meminfo is not None:
                (root / "meminfo").write_text(meminfo)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = cbt.main(argv, runner=lambda c, t: cbt.RunResult(output, 0, False))
            return rc, out.getvalue()

    def test_main_fails_a_leak_even_when_the_text_matches(self):
        # The expected text is the output itself; only the directive objects.
        rc, out = self.run_free("Mem: 24548180\n", self.ARM)
        self.assertEqual(rc, 1, out)
        self.assertIn("host memory leaked", out)

    def test_main_passes_clean_output(self):
        rc, out = self.run_free("Mem: 8039340\n", self.ARM)
        self.assertEqual(rc, 0, out)

    def test_unreadable_host_meminfo_fails_closed(self):
        rc, out = self.run_free("Mem: 8039340\n", None)
        self.assertEqual(rc, 1, out)
        self.assertIn("cannot read host MemTotal", out)


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

    def test_uptime_slack_flag_reaches_the_comparison(self):
        (self.root / "probes.txt").write_text("up\tcat /proc/uptime\n")
        (self.root / "expected" / "up.out").write_text("{{UPTIME_SECS}} {{IDLE_SECS}}\n")
        answers = {"cat /proc/uptime": cbt.RunResult(f"{ANCHOR + 86400:.2f} 1.00\n", 0, False)}
        rc, out, _ = self.run_main(answers, ["--only", "probes"])
        self.assertEqual(rc, 1, out)
        rc, out, _ = self.run_main(answers, ["--only", "probes", "--uptime-slack", "100000"])
        self.assertEqual(rc, 0, out)

    def test_cowrie_age_flag_reaches_the_comparison(self):
        (self.root / "probes.txt").write_text("up\tcat /proc/uptime\n")
        (self.root / "expected" / "up.out").write_text("{{UPTIME_SECS}} {{IDLE_SECS}}\n")
        answers = {"cat /proc/uptime": cbt.RunResult(f"{ANCHOR + 86400:.2f} 1.00\n", 0, False)}
        rc, out, _ = self.run_main(answers, ["--only", "probes", "--cowrie-age", "86400"])
        self.assertEqual(rc, 0, out)
        rc, out, _ = self.run_main(answers, ["--only", "probes", "--cowrie-age", "3600"])
        self.assertEqual(rc, 1, out)

    def test_missing_expected_file_fails(self):
        (self.root / "expected" / "who-am-i.out").unlink()
        rc, out, _ = self.run_main(self.good())
        self.assertEqual(rc, 1)
        self.assertIn("who-am-i", out)


    def test_scp_stdin_case_feeds_the_elf_as_one_c_record(self):
        (self.root / "probes.txt").write_text("run-own\tscp -t /root/x >/dev/null; ./x\n")
        (self.root / "expected" / "run-own.out").write_text("#harness: scp-stdin=x\n")
        elf = self.root / "elf"
        elf.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 57)
        seen = []

        def runner(command, timeout, stdin=None):
            seen.append((command, stdin))
            return cbt.RunResult("", 0, False)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cbt.main(self.argv + ["--only", "probes", "--upload-source", str(elf)],
                          runner=runner)
        self.assertEqual(rc, 0, out.getvalue())
        data = elf.read_bytes()
        self.assertEqual(seen, [("scp -t /root/x >/dev/null; ./x",
                                 f"C0755 {len(data)} x\n".encode() + data + b"\x00")])

    def test_upload_source_must_be_an_elf(self):
        (self.root / "probes.txt").write_text("run-own\tscp -t /root/x >/dev/null; ./x\n")
        (self.root / "expected" / "run-own.out").write_text("#harness: scp-stdin=x\n")
        script = self.root / "not-elf"
        script.write_text("#!/bin/sh\n")
        rc, out, calls = self.run_main({}, ["--only", "probes", "--upload-source", str(script)])
        self.assertEqual(rc, 1)
        self.assertIn("not an ELF", out)
        self.assertEqual(calls, [])

    def test_failed_run_fails_the_case(self):
        (self.root / "probes.txt").write_text("run-own\tscp -t /root/x >/dev/null; ./x\n")
        (self.root / "expected" / "run-own.out").write_text("#harness: scp-stdin=x\n")
        elf = self.root / "elf"
        elf.write_bytes(b"\x7fELF")

        def runner(command, timeout, stdin=None):
            return cbt.RunResult("bash: line 1: ./x: cannot execute binary file: "
                                 "Exec format error\n", 126, False)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cbt.main(self.argv + ["--only", "probes", "--upload-source", str(elf)],
                          runner=runner)
        self.assertEqual(rc, 1)
        self.assertIn("exit status 126, expected 0", out.getvalue())


    def test_upload_channel_case_uploads_on_an_earlier_channel(self):
        (self.root / "probes.txt").write_text("cross\tls -l /tmp/x; /tmp/x; echo rc=$?\n")
        (self.root / "expected" / "cross.out").write_text(
            "#harness: upload-channel=/tmp/x hw\n"
            "-rwxr-xr-x 1 root root {{UPLOAD_SIZE}} {{LSDATE_RECENT}} /tmp/x\nrc=0\n")
        elf = self.root / "elf"
        elf.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 57)
        data = elf.read_bytes()
        seen = []

        def runner(command, timeout, stdin=None, before=None):
            seen.append((command, stdin, before))
            stamp = datetime.now(timezone.utc)
            return cbt.RunResult(f"-rwxr-xr-x 1 root root {len(data)} {stamp:%b %e %H:%M}"
                                 " /tmp/x\nrc=0\n", 0, False)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cbt.main(self.argv + ["--only", "probes", "--upload-source", str(elf)],
                          runner=runner)
        self.assertEqual(rc, 0, out.getvalue())
        self.assertEqual(seen, [(
            "ls -l /tmp/x; /tmp/x; echo rc=$?", None,
            [("scp -t /tmp/x", f"C0755 {len(data)} hw\n".encode() + data + b"\x00")],
        )])

    def test_before_channels_follow_the_upload_channel(self):
        (self.root / "probes.txt").write_text("redir\tcat /tmp/m\n")
        (self.root / "expected" / "redir.out").write_text(
            "#harness: upload-channel=/tmp/x hw\n#harness: before=echo m > /tmp/m\nm\n")
        elf = self.root / "elf"
        elf.write_bytes(b"\x7fELF")
        seen = []

        def runner(command, timeout, stdin=None, before=None):
            seen.append(before)
            return cbt.RunResult("m\n", 0, False)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cbt.main(self.argv + ["--only", "probes", "--upload-source", str(elf)],
                          runner=runner)
        self.assertEqual(rc, 0, out.getvalue())
        self.assertEqual(seen, [[("scp -t /tmp/x", b"C0755 4 hw\n\x7fELF\x00"),
                                 ("echo m > /tmp/m", None)]])

    def test_sftp_during_case_checks_the_capture(self):
        (self.root / "probes.txt").write_text("inflight\techo X > /tmp/up; echo rc=$?\n")
        (self.root / "expected" / "inflight.out").write_text(
            "#harness: sftp-during=/tmp/up\nrc=0\n")
        elf = self.root / "elf"
        elf.write_bytes(b"\x7fELF")
        dl = self.root / "dl"
        dl.mkdir()

        def runner(command, timeout, stdin=None, before=None, sftp_during=None, overlap=None):
            path, data = sftp_during
            self.assertEqual(path, "/tmp/up")
            self.assertTrue(data.startswith(b"\x7fELF") and len(data) == 20)
            if capture:
                (dl / cbt.hashlib.sha256(data).hexdigest()).write_bytes(data)
            return cbt.RunResult("rc=0\n", 0, False)

        for capture, want in ((True, 0), (False, 1)):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = cbt.main(self.argv + ["--only", "probes", "--upload-source", str(elf),
                                           "--downloads-dir", str(dl)], runner=runner)
            self.assertEqual(rc, want, out.getvalue())
        self.assertIn("upload not captured", out.getvalue())

    def test_upload_size_is_the_exact_source_size(self):
        (self.root / "probes.txt").write_text("cross\tls -l /tmp/x\n")
        (self.root / "expected" / "cross.out").write_text(
            "#harness: upload-channel=/tmp/x hw\n"
            "-rwxr-xr-x 1 root root {{UPLOAD_SIZE}} {{LSDATE_RECENT}} /tmp/x\n")
        elf = self.root / "elf"
        elf.write_bytes(b"\x7fELF" + b"\x00" * 60)

        def runner(command, timeout, stdin=None, before=None):
            stamp = datetime.now(timezone.utc)
            return cbt.RunResult(f"-rwxr-xr-x 1 root root 63 {stamp:%b %e %H:%M} /tmp/x\n",
                                 0, False)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cbt.main(self.argv + ["--only", "probes", "--upload-source", str(elf)],
                          runner=runner)
        self.assertEqual(rc, 1, out.getvalue())
        self.assertIn("+-rwxr-xr-x 1 root root 63", out.getvalue())


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

    def test_unacknowledged_exec_with_no_output_is_noted(self):
        # M-4: a refused exec request reads as empty output; say why.
        chan = FakeChannel([], None, raise_on_exec=True)
        chan.closed = chan.eof_received = True
        res = cbt.exec_on_channel(chan, "x", time.monotonic() + 5, ClosedError)
        self.assertIn("not acknowledged", res.note)

    def test_acknowledged_race_with_output_has_no_note(self):
        chan = FakeChannel([b"root\n"], 0, raise_on_exec=True)
        res = cbt.exec_on_channel(chan, "whoami", time.monotonic() + 5, ClosedError)
        self.assertEqual(res.note, "")

    def test_hung_session_times_out(self):
        chan = FakeChannel([b"Enter new UNIX password: "], None, never_close=True)
        res = cbt.exec_on_channel(chan, "passwd", time.monotonic() + 0.2, ClosedError)
        self.assertTrue(res.timed_out)
        self.assertEqual(res.output, "Enter new UNIX password: ")


class ScpStdinTest(unittest.TestCase):
    def test_record_is_the_legacy_c_record(self):
        self.assertEqual(cbt.scp_record("x", b"\x7fELFab"), b"C0755 6 x\n\x7fELFab\x00")

    def test_stdin_is_sent_then_closed_on_the_exec_channel(self):
        chan = FakeChannel([b""], 0)
        chan.sent, chan.write_shut = b"", False
        chan.sendall = lambda data: setattr(chan, "sent", chan.sent + data)
        chan.shutdown_write = lambda: setattr(chan, "write_shut", True)
        res = cbt.exec_on_channel(chan, "scp -t /root/x", time.monotonic() + 5,
                                  ClosedError, b"C0755 1 x\nA\x00")
        self.assertEqual(chan.sent, b"C0755 1 x\nA\x00")
        self.assertTrue(chan.write_shut)
        self.assertEqual(res.rc, 0)

    def test_scp_stdin_directive(self):
        self.assertEqual(cbt.parse_expected("#harness: scp-stdin=x\n").scp_stdin, "x")
        for bad in ("", "a/b", "a b", "..", "/root/x"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                cbt.parse_expected(f"#harness: scp-stdin={bad}\n")



class UploadChannelTest(unittest.TestCase):
    def test_directive(self):
        exp = cbt.parse_expected("#harness: upload-channel=/tmp/x hw\n")
        self.assertEqual(exp.upload_channel, ("/tmp/x", "hw"))
        self.assertEqual(cbt.parse_expected("#harness: upload-channel=/tmp/ hw\n")
                         .upload_channel, ("/tmp/", "hw"))
        for bad in ("", "/tmp/x", "tmp/x hw", "/tmp/x a/b", "/tmp/x ..", "/tmp/x hw z",
                    "/tmp/$(id) hw"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                cbt.parse_expected(f"#harness: upload-channel={bad}\n")

    def test_upload_size_needs_an_upload_directive(self):
        with self.assertRaises(ValueError):
            cbt.parse_expected("size {{UPLOAD_SIZE}}\n")
        cbt.parse_expected("#harness: scp-stdin=x\nsize {{UPLOAD_SIZE}}\n")

    def test_directives_are_exclusive(self):
        with self.assertRaises(ValueError):
            cbt.parse_expected("#harness: scp-stdin=x\n#harness: upload-channel=/tmp/x hw\n")

    def test_sequence_runs_each_step_on_its_own_channel(self):
        chans = [FakeChannel([b"\x00\x00"], 0), FakeChannel([b"rc=0\n"], 0)]
        for c in chans:
            c.sent, c.commands = b"", []
            c.sendall = lambda data, c=c: setattr(c, "sent", c.sent + data)
            c.shutdown_write = lambda: None
        opened = iter(chans)
        res = cbt.exec_sequence(lambda: next(opened),
                                [("scp -t /tmp/x", b"C0755 1 hw\nA\x00"), ("/tmp/x", None)],
                                time.monotonic() + 5, ClosedError)
        self.assertEqual(res, cbt.RunResult("rc=0\n", 0, False))
        self.assertEqual(chans[0].sent, b"C0755 1 hw\nA\x00")
        self.assertEqual(chans[1].sent, b"")

    def test_failed_earlier_step_fails_the_case_with_a_note(self):
        chans = iter([FakeChannel([b"\x00-scp: /nope/x: No such file or directory\n"], 1)])
        res = cbt.exec_sequence(lambda: next(chans),
                                [("scp -t /nope/x", None), ("/nope/x", None)],
                                time.monotonic() + 5, ClosedError)
        self.assertIsNone(res.rc)
        self.assertIn("channel 1 (`scp -t /nope/x`) failed: exit status 1", res.note)
        self.assertEqual(res.output, "-scp: /nope/x: No such file or directory\n")

    def test_before_directive_is_repeatable_and_ordered(self):
        exp = cbt.parse_expected("#harness: before=echo a > /tmp/m\n"
                                 "#harness: before=echo b >> /tmp/m\n")
        self.assertEqual(exp.before, ["echo a > /tmp/m", "echo b >> /tmp/m"])
        with self.assertRaises(ValueError):
            cbt.parse_expected("#harness: before=\n")

    def test_ssh_transport_refuses_rather_than_running_one_connection_per_step(self):
        with mock.patch.object(cbt.shutil, "which", return_value="/usr/bin/x"):
            run = cbt.ssh_runner("127.0.0.1", 2299, "root", "pw")
        with mock.patch.object(cbt.subprocess, "run") as sp:
            res = run("/tmp/x", 5, before=[("scp -t /tmp/x", b"")])
        sp.assert_not_called()
        self.assertIsNone(res.rc)
        self.assertIn("--transport paramiko", res.note)



class ConcurrentChannelTest(unittest.TestCase):
    def test_directives(self):
        exp = cbt.parse_expected("#harness: sftp-during=/tmp/up\nrc=0\n")
        self.assertEqual(exp.sftp_during, "/tmp/up")
        self.assertEqual(cbt.parse_expected("#harness: overlap=true\n").overlap, "true")
        for bad in ("#harness: sftp-during=tmp/up\n", "#harness: overlap=\n",
                    "#harness: sftp-during=/tmp/up\n#harness: overlap=true\n",
                    "#harness: overlap=true\n#harness: before=true\n",
                    "#harness: sftp-during=/tmp/up\n#harness: scp-stdin=x\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                cbt.parse_expected(bad)

    def test_overlap_runs_b_to_completion_inside_a(self):
        order = []

        class Chan(FakeChannel):
            def __init__(self, name, chunks, rc):
                super().__init__(chunks, rc)
                self.name = name

            def exec_command(self, command):
                order.append(f"exec {self.name}")

            def recv(self, n):
                order.append(f"read {self.name}")
                return super().recv(n)

        chans = iter([Chan("A", [b"2\n"], 0), Chan("B", [b""], 0)])
        res = cbt.exec_overlapped(lambda: next(chans), "sleep 2; cat /proc/uptime | wc -w",
                                  "true", time.monotonic() + 5, ClosedError)
        self.assertEqual(res, cbt.RunResult("2\n", 0, False))
        self.assertEqual(order, ["exec A", "exec B", "read B", "read A"])

    def test_sftp_upload_is_split_around_the_case_and_failure_fails(self):
        events = []

        class Handle:
            def __init__(self, fail):
                self.fail = fail

            def write(self, data):
                events.append(("write", data))

            def flush(self):
                events.append(("flush",))

            def close(self):
                if self.fail:
                    raise OSError("Failure")
                events.append(("close",))

        for fail in (False, True):
            events.clear()
            sftp = mock.Mock()
            sftp.open.return_value = Handle(fail)
            res = cbt.exec_during_sftp(lambda: sftp, "/tmp/up", b"abcd",
                                       lambda: (events.append(("case",)),
                                                cbt.RunResult("rc=0\n", 0, False))[1])
            self.assertEqual(events[:4], [("write", b"ab"), ("flush",), ("case",),
                                          ("write", b"cd")])
            if fail:
                self.assertIsNone(res.rc)
                self.assertIn("SFTP upload to /tmp/up failed", res.note)
            else:
                self.assertEqual(res.rc, 0)
            sftp.close.assert_called_once()

    def test_capture_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            data = b"\x7fELF payload"
            self.assertIn("needs --downloads-dir", cbt.check_capture(None, data))
            self.assertIn("not captured", cbt.check_capture(d, data))
            sha = cbt.hashlib.sha256(data).hexdigest()
            (d / sha).write_bytes(b"X\n")
            self.assertIn("does not hash to its name", cbt.check_capture(d, data))
            (d / sha).write_bytes(data)
            self.assertEqual(cbt.check_capture(d, data), "")

class LsDateRecentTest(unittest.TestCase):
    TPL = "-rwxr-xr-x 1 root root 7 {{LSDATE_RECENT}} /tmp/x\n"

    def test_written_during_the_run_passes(self):
        res = check(self.TPL, f"-rwxr-xr-x 1 root root 7 {NOW:%b %e %H:%M} /tmp/x\n",
                    clk=clock(run_seconds=30))
        self.assertTrue(res.ok, res.diff + res.messages)

    def test_old_or_future_stamp_is_rejected(self):
        for when in (NOW - timedelta(hours=1), NOW + timedelta(hours=1)):
            with self.subTest(when=when):
                res = check(self.TPL, f"-rwxr-xr-x 1 root root 7 {when:%b %e %H:%M} /tmp/x\n")
                self.assertFalse(res.ok)

    def test_cowrie_iso_date_is_rejected(self):
        res = check(self.TPL, f"-rwxr-xr-x 1 root root 7 {NOW:%Y-%m-%d %H:%M} x\n")
        self.assertFalse(res.ok)

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

    def test_expected_file_rulings(self):
        exp = lambda n: (CASES_DIR / "expected" / f"{n}.out").read_text()  # noqa: E731
        # Review I-3: persona df blocks 99014048 K -> 94.43 GiB -> df -h "95G".
        self.assertEqual(exp("df-h-awk"), "95G\n")
        # procps 3.3.17 on the persona meminfo (truncates, does not round),
        # and no free case may render the Cowrie host's own memory.
        free_m = cbt.parse_expected(exp("free-m-awk"))
        self.assertEqual(free_m.content, "7850 1527 4094 0 2228 6111\n")
        for name in ("free-m-awk", "free", "free-h"):
            with self.subTest(case=name):
                self.assertTrue(cbt.parse_expected(exp(name)).no_host_memtotal)
        # free-meminfo.py falls back to MemFree when MemAvailable is missing,
        # where procps would estimate from the zone watermarks; the persona
        # meminfo must keep the field so that fallback stays unreachable.
        meminfo = (HERE.parent / "install" / "persona" / "honeyfs" / "proc" / "meminfo").read_text()
        self.assertRegex(meminfo, r"(?m)^MemAvailable:\s+\d+ kB$")
        # The shadowed free txtcmd is procps' own output for the persona.
        self.assertEqual(
            cbt.parse_expected(exp("free")).content,
            (HERE.parent / "install" / "persona" / "txtcmds" / "usr" / "bin" / "free").read_text())
        # lspci answers with the persona's own Xen list, the txtcmd it shadows.
        self.assertEqual(
            exp("lspci"),
            (HERE.parent / "install" / "persona" / "txtcmds" / "usr" / "bin" / "lspci").read_text())
        # Review I-4: the ubuntu row runs its login shell, idle is volatile.
        self.assertTrue(exp("w").rstrip("\n").endswith("{{W_IDLE}}  0.04s  0.01s -bash"))
        self.assertIn("{{LSDATE}}", exp("ls-which-ls"))

    def test_motd_disk_size_agrees_with_df(self):
        # landscape-sysinfo's "GB" is KiB/1024/1024 of the root fs: 94.43.
        motd = persona()["honeyfs/etc/motd"]
        self.assertIn("61.2% of 94.43GB", motd)
        self.assertIn("61.2% of 94.43GB",
                      (HERE.parent / "install" / "persona" / "honeyfs" / "etc" / "motd").read_text())

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
        res = cbt.compare("profiler", exp, real, 0, False, clock(now=REF_NOW))
        self.assertTrue(res.ok, "\n".join(res.diff + res.messages))


if __name__ == "__main__":
    unittest.main()
