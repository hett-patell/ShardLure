#!/usr/bin/env python3
"""Behavioural harness: drive a loopback Cowrie and diff what its shell answers.

Why this exists: `check-cowrie-patches.sh` only proves a persona patch applies
as text. `command-type-builtins` passed that check on Cowrie v3.1.1 and then
crashed every session that used it (a TypeError on the new `getCommand`
signature; factsheet-phaseB 4). The only test that catches that class of
fault is to talk to a running Cowrie the way an attacker does and compare the
answers with what a real Ubuntu 22.04 box matching the persona would print.

Cases (all under --cases-dir, default scripts/behaviour/):
  profiler.sh          the recurring SHELL_BEHAVIOR profiler, verbatim (case
                       name "profiler"; 1,452 sessions in 30 days on prod).
  probes.txt           "<name><TAB><command>" per line; '#' comments.
  expected/<name>.out  the expected stdout+stderr, byte for byte, apart from
                       the declared volatile tokens below.

Each case is one SSH **exec** channel on a fresh connection, because that is
how the profiler arrives (one `cowrie.command.input` with embedded newlines).
stdout is followed by stderr; Cowrie writes both to the channel's stdout
anyway (factsheet 2, FILTER "exec-channel stderr").

Expected files may start with directive lines, consumed until the first other
line:
  #harness: rc=N            exit status must be N (default 0: real bash's
                            status is known for every case, and a session
                            closing without one is a failure)
  #harness: advances=LO..HI successive {{UPTIME_SECS}} must rise by LO..HI s
  #harness: skip=WHY        do not run; reported as SKIP (deferred probes)
  #harness: scp-stdin=NAME  feed the case's stdin one legacy scp C-record
                            ("C0755 <size> NAME", --upload-source, NUL), then
                            EOF, so a `scp -t ...` in the command receives an
                            upload. --upload-source defaults to /bin/true, a
                            harmless ELF; Cowrie only stores it. Upload and run
                            share ONE exec channel because Cowrie v3.1.1 builds
                            a fresh fake filesystem for every session channel
                            (shell/session.py initFileSystem), so a file
                            uploaded on one channel is gone on the next.

Volatile tokens. Only these fields vary between a real box and a correct
honeypot, and each is checked against the persona clock, not just its shape.
"now" is the case's run window in --tz (Cowrie's persona cfg sets UTC); boot
is now minus {{UPTIME_SECS}} when the case prints it, else now minus the
anchor (+ slack).
  {{UPTIME_SECS}}   /proc/uptime seconds, anchor <= v <= anchor + slack, or
                    anchor + age +- 900 s with --cowrie-age
  {{IDLE_SECS}}     /proc/uptime idle seconds (shape only)
  {{UPTIME_HUMAN}}  procps "up N days,  H:MM" / "up N days, M min", same bound
  {{NOW_HMS}}       uptime/w clock, within 2 min of now
  {{LAST_LOGIN_CURRENT}}  last's "still logged in" row: after boot, <= 12 h old
  {{LAST_LOGIN}}    a completed session: after boot, before today (the
                    persona's completed sessions are all >= 1d8h old)
  {{LOGOUT_HM}}     its "- HH:MM", equal to login + the row's "(HH:MM)"
  {{BOOT_HM}}       last's reboot row, boot to the minute (+-1 min)
  {{BOOT_FULL}}     "wtmp begins", boot to the second (+-60 s), never today
  {{LOGIN_HM}}      w's LOGIN@, <= 12 h before now (procps prints HH:MM
                    only then)
  {{W_IDLE}}        w's 7-char IDLE cell, no longer than the session
  {{LSDATE}}        ls -l's date of a packaged binary: the year form, older
                    than six months (never a node stamped "now")
All last rows (logins, then reboot) must be in non-increasing time order, and
every weekday must match its date.

Transport: paramiko when importable (exec_command, no pty - like the
profiler's Go client), otherwise `sshpass -e ssh`. Each case gets a 10 s
deadline; a hang (e.g. `passwd` waiting on stdin forever) is a FAIL, not a
stuck run. CI runs only the unit tests (scripts/test_cowrie_behaviour.py):
this CLI needs a live Cowrie.

Usage:
  cowrie-behaviour-test.py --host 127.0.0.1 --port 2299 \\
      --password-from etc/userdb.txt [--only profiler|probes]

A freshly started rehearsal uses the default one-sided window (anchor + 6 h).
Against a long-running Cowrie (production, loopback only) pass its process age,
read timezone-free from ps (systemd timestamps print in the host's local zone):
  pid=$(systemctl show -P MainPID cowrie)    # confirm it is twistd, not authbind
  age=$(ps -o etimes= -p "$pid" | tr -d ' ')
  cowrie-behaviour-test.py --host 127.0.0.1 --port 22 \\
      --password-from /var/lib/shardlure/cowrie/etc/userdb.txt \\
      --cowrie-age "$age" --tz UTC
Exit 0 when every case matches, else 1 with a unified diff per failing case.
"""
from __future__ import annotations

import argparse
import difflib
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

# The persona advertises 42d 3h17m of uptime (install/persona/gen-time-persona.py
# UPTIME; Phase B sets Cowrie's boot_offset to the same value). Anything below
# it disagrees with the persona's own `uptime`, `last` and motd.
UPTIME_ANCHOR = 42 * 86400 + 3 * 3600 + 17 * 60  # 3640620

# Upper bound on uptime past the anchor. With a fixed boot_offset, Cowrie's
# uptime is the anchor plus its own process age, so a rehearsal started for a
# harness run reads anchor + minutes. 6 h covers a rehearsal left running for
# an afternoon and still rejects v3.1.1's default random 1-90 day boot_offset
# (review I-2: without a bound, ~54% of random draws passed). Checking a
# long-running production Cowrie needs an explicit --uptime-slack.
DEFAULT_UPTIME_SLACK = 6 * 3600

# Production: uptime = boot_offset + the Cowrie process age, so with
# --cowrie-age the window is two-sided, anchor + age +- this margin. A one-sided
# [anchor, anchor + age] let a forgotten (random 1-90 d) boot_offset pass ~34%
# of the time at a 30 d process age. 900 s covers the run itself (35 cases at
# up to 10-20 s each) plus the delay between reading the age and connecting.
COWRIE_AGE_MARGIN = 900

NOW_TOLERANCE = 120        # uptime/w HH:MM:SS vs the run window
BOOT_TOLERANCE = 60        # last's boot stamps vs now - uptime
CURRENT_SESSION_MAX = 12 * 3600
LS_MIN_AGE = 183 * 86400   # ls prints the year form only for files > ~6 months

DEFAULT_TIMEOUT = 10.0
DEFAULT_CASES_DIR = Path(__file__).resolve().parent / "behaviour"

_WDAY = r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)"
_MON = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
_HM = r"(?:[01]\d|2[0-3]):[0-5]\d"
_WDATE_HM = _WDAY + " " + _MON + r" [ 123]\d " + _HM

# token -> regex. The checks in _check_values give each its meaning.
TOKENS = {
    "UPTIME_SECS": r"\d+\.\d{2}",
    "IDLE_SECS": r"\d+\.\d{2}",
    # procps 3.3.17 sprint_uptime: "%d days, " then "%2d:%02d" or "%d min".
    "UPTIME_HUMAN": r"up \d+ days?, (?:(?: \d|[1-9]\d):[0-5]\d|\d+ min)",
    "NOW_HMS": _HM + r":[0-5]\d",
    "LAST_LOGIN_CURRENT": _WDATE_HM,
    "LAST_LOGIN": _WDATE_HM,
    "LOGOUT_HM": _HM,
    "BOOT_HM": _WDATE_HM,
    "BOOT_FULL": _WDATE_HM + r":[0-5]\d \d{4}",
    "LOGIN_HM": _HM,
    # procps print_time_ival7: " %2ludays", " %2lu:%02um", " %2lu:%02u ", " %2lu.%02us"
    "W_IDLE": r" (?:[ \d]\ddays|[ \d]\d:[0-5]\dm|[ \d]\d:[0-5]\d |[ \d]\d\.\d\ds)",
    "LSDATE": _MON + r" [ 123]\d  \d{4}",
}
_TOKEN_RE = re.compile(r"\{\{([A-Z_:]+)\}\}")
_DIRECTIVE = "#harness:"


@dataclass
class Expected:
    content: str
    rc: int | None = 0
    skip: str | None = None
    advances: tuple[float, float] | None = None
    scp_stdin: str | None = None


@dataclass
class RunResult:
    output: str
    rc: int | None
    timed_out: bool
    note: str = ""


@dataclass
class Clock:
    """When a case ran (aware datetimes) and how its times are judged."""
    start: datetime
    end: datetime
    uptime_slack: float = DEFAULT_UPTIME_SLACK
    tz: tzinfo = timezone.utc
    cowrie_age: float | None = None

    def uptime_window(self) -> tuple[float, float]:
        """Allowed /proc/uptime seconds: rehearsal one-sided, production two-sided."""
        if self.cowrie_age is None:
            return UPTIME_ANCHOR, UPTIME_ANCHOR + self.uptime_slack
        mid = UPTIME_ANCHOR + self.cowrie_age
        return mid - COWRIE_AGE_MARGIN, mid + COWRIE_AGE_MARGIN

    def describe_window(self) -> str:
        lo, hi = self.uptime_window()
        if self.cowrie_age is None:
            return f"{lo:.0f}..{hi:.0f}s (42d 3h17m + {self.uptime_slack:.0f}s slack)"
        return (f"{lo:.0f}..{hi:.0f}s (42d 3h17m + cowrie age {self.cowrie_age:.0f}s"
                f" +-{COWRIE_AGE_MARGIN}s)")

    def local(self, dt: datetime) -> datetime:
        return dt.astimezone(self.tz).replace(tzinfo=None)


@dataclass
class CaseResult:
    name: str
    ok: bool
    diff: list[str] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)


def parse_expected(text: str) -> Expected:
    exp = Expected(content="")
    lines = text.split("\n")
    i = 0
    while i < len(lines) and lines[i].startswith(_DIRECTIVE):
        body = lines[i][len(_DIRECTIVE):].strip()
        if body.startswith("rc="):
            exp.rc = int(body[3:])
        elif body.startswith("advances="):
            m = re.fullmatch(r"advances=(\d+(?:\.\d+)?)\.\.(\d+(?:\.\d+)?)", body)
            if not m or float(m.group(1)) >= float(m.group(2)):
                raise ValueError(f"bad advances directive (want LO..HI): {lines[i]!r}")
            exp.advances = (float(m.group(1)), float(m.group(2)))
        elif body.startswith("skip="):
            exp.skip = body[5:].strip() or "skipped"
        elif body.startswith("scp-stdin="):
            name = body[10:].strip()
            if not re.fullmatch(r"[A-Za-z0-9._-]+", name) or name in (".", ".."):
                raise ValueError(f"bad scp-stdin directive (want a plain file name): {lines[i]!r}")
            exp.scp_stdin = name
        else:
            raise ValueError(f"unknown harness directive: {lines[i]!r}")
        i += 1
    exp.content = "\n".join(lines[i:])
    for tok in _TOKEN_RE.findall(exp.content):
        if tok not in TOKENS:
            raise ValueError(f"unknown volatile token {{{{{tok}}}}}")
    return exp


def _line_regex(template: str) -> tuple[re.Pattern, list[str]]:
    parts, names, pos = [], [], 0
    for m in _TOKEN_RE.finditer(template):
        parts.append(re.escape(template[pos:m.start()]))
        names.append(m.group(1))
        parts.append(f"(?P<t{len(names) - 1}>{TOKENS[m.group(1)]})")
        pos = m.end()
    parts.append(re.escape(template[pos:]))
    return re.compile("".join(parts)), names


def _match_line(template: str, actual: str) -> list[tuple[str, str]] | None:
    """(token, value) pairs if `actual` has the template's shape, else None."""
    if "{{" not in template:
        return [] if template == actual else None
    rx, names = _line_regex(template)
    m = rx.fullmatch(actual)
    if not m:
        return None
    return [(name, m.group(f"t{idx}")) for idx, name in enumerate(names)]


# --- value checks against the persona clock ---------------------------------

def _human_seconds(text: str) -> int:
    m = re.fullmatch(r"up (\d+) days?, (?:\s*(\d+):(\d\d)|(\d+) min)", text)
    days = int(m.group(1)) * 86400
    if m.group(4) is not None:
        return days + int(m.group(4)) * 60
    return days + int(m.group(2)) * 3600 + int(m.group(3)) * 60


def _format_human(seconds: float) -> str:
    """procps 3.3.17's "up ..." for an uptime (days > 0)."""
    s = int(seconds)
    days, hours, mins = s // 86400, s % 86400 // 3600, s % 3600 // 60
    tail = f"{hours:2d}:{mins:02d}" if hours else f"{mins} min"
    return f"up {days} day{'s' if days != 1 else ''}, {tail}"


def _resolve_date(text: str, fmt: str, now: datetime) -> tuple[datetime | None, str | None]:
    """Parse a yearless last(1) stamp as its latest occurrence not after now.

    Returns (datetime, problem). The weekday is checked against the date, which
    a yearless stamp cannot otherwise prove.
    """
    for year in (now.year, now.year - 1):
        try:
            dt = datetime.strptime(f"{text} {year}", fmt + " %Y")
        except ValueError:  # Feb 29 in a non-leap year
            continue
        if dt <= now + timedelta(days=1):
            if dt.strftime("%a") != text[:3]:
                return dt, f"weekday in '{text}' does not match its date ({dt:%a})"
            return dt, None
    return None, f"'{text}' is not a date before now"


def _idle_seconds(cell: str) -> int:
    c = cell.strip()
    if c.endswith("days"):
        return int(c[:-4]) * 86400
    if c.endswith("m"):
        h, m = c[:-1].split(":")
        return int(h) * 3600 + int(m) * 60
    if c.endswith("s"):
        return int(float(c[:-1]))
    m, s = c.split(":")
    return int(m) * 60 + int(s)


def _tod_distance(a: datetime, b: datetime) -> float:
    """Seconds between two times of day, wrapping at midnight."""
    d = abs((a.hour * 3600 + a.minute * 60 + a.second)
            - (b.hour * 3600 + b.minute * 60 + b.second))
    return min(d, 86400 - d)


def _check_values(lines: list[tuple[int, str, list[tuple[str, str]]]],
                  exp: Expected, clock: Clock) -> dict[int, list[str]]:
    """Relational checks over every matched token. Returns {line: problems}."""
    start, end = clock.local(clock.start), clock.local(clock.end)
    up_lo, up_hi = clock.uptime_window()
    bad: dict[int, list[str]] = {}

    def flag(i: int, msg: str) -> None:
        bad.setdefault(i, []).append(msg)

    uptimes = [(i, float(v)) for i, _, vals in lines for t, v in vals if t == "UPTIME_SECS"]
    for i, u in uptimes:
        if not up_lo <= u <= up_hi:
            flag(i, f"uptime {u:.2f}s is not on the persona anchor: want"
                    f" {clock.describe_window()}")
    if exp.advances and len(uptimes) > 1:
        lo, hi = exp.advances
        for (_, a), (i, b) in zip(uptimes, uptimes[1:]):
            if not lo <= b - a <= hi:
                flag(i, f"uptime did not advance by {lo:g}..{hi:g}s between reads"
                        f" ({a:.2f} -> {b:.2f})")
    # Boot as an interval: the stamps were produced somewhere in the run.
    if uptimes and uptimes[0][1] < 100 * 365 * 86400:  # timedelta overflows past ~2.7e9 days
        u = uptimes[0][1]
        boot_lo, boot_hi = start - timedelta(seconds=u), end - timedelta(seconds=u)
    else:
        boot_lo = start - timedelta(seconds=up_hi)
        boot_hi = end - timedelta(seconds=up_lo)

    order: list[tuple[int, datetime]] = []
    for i, text, vals in lines:
        login = login_hm = None
        for tok, val in vals:
            if tok == "UPTIME_HUMAN":
                h = _human_seconds(val)
                # procps truncates to the minute.
                if not up_lo - 60 < h <= up_hi:
                    flag(i, f"'{val}' is not on the persona anchor: want"
                            f" {clock.describe_window()}")
            elif tok == "NOW_HMS":
                t = datetime.strptime(val, "%H:%M:%S")
                d = min(_tod_distance(t, start), _tod_distance(t, end))
                if d > NOW_TOLERANCE and not _tod_between(t, start, end):
                    flag(i, f"clock {val} is not now ({start:%H:%M:%S}..{end:%H:%M:%S}"
                            f" +-{NOW_TOLERANCE}s)")
            elif tok in ("LAST_LOGIN", "LAST_LOGIN_CURRENT", "BOOT_HM"):
                dt, problem = _resolve_date(val, "%a %b %d %H:%M", end)
                if problem:
                    flag(i, problem)
                if dt is None:
                    continue
                order.append((i, dt))
                if tok == "BOOT_HM":
                    if not boot_lo - timedelta(seconds=2 * BOOT_TOLERANCE) <= dt <= \
                            boot_hi + timedelta(seconds=BOOT_TOLERANCE):
                        flag(i, f"reboot '{val}' is not boot (now - uptime ="
                                f" {boot_hi:%a %b %e %H:%M})")
                    continue
                login = dt
                if dt < boot_lo - timedelta(seconds=2 * BOOT_TOLERANCE) or dt > end:
                    flag(i, f"session '{val}' is not between boot and now")
                if tok == "LAST_LOGIN_CURRENT":
                    if (end - dt).total_seconds() > CURRENT_SESSION_MAX:
                        flag(i, f"still-logged-in session '{val}' is more than 12 h old")
                elif dt.date() >= end.date():
                    flag(i, f"completed session '{val}' is today; the persona's"
                            " history is in the past")
            elif tok == "LOGOUT_HM":
                dur = re.search(r"\((\d\d):(\d\d)\)", text)
                if login is None or dur is None:
                    flag(i, "logout time without a login and (duration) on its row")
                    continue
                out = login + timedelta(hours=int(dur.group(1)), minutes=int(dur.group(2)))
                if val != f"{out:%H:%M}":
                    flag(i, f"logout {val} is not login + duration ({out:%H:%M})")
                if out > end:
                    flag(i, f"logout {out:%H:%M} is after now")
            elif tok == "BOOT_FULL":
                # The stamp carries its year: parse it whole. A malformed one
                # (Feb 29 of a non-leap year) fails this case, not the run.
                try:
                    dt = datetime.strptime(val, "%a %b %d %H:%M:%S %Y")
                except ValueError:
                    flag(i, f"wtmp begins '{val}' is an invalid date")
                    continue
                if dt.strftime("%a") != val[:3]:
                    flag(i, f"weekday in '{val}' does not match its date ({dt:%a})")
                if not boot_lo - timedelta(seconds=BOOT_TOLERANCE) <= dt <= \
                        boot_hi + timedelta(seconds=BOOT_TOLERANCE):
                    flag(i, f"wtmp begins '{val}' is not boot (now - uptime ="
                            f" {boot_hi:%a %b %e %H:%M:%S %Y})")
                # Implied by the boot check while uptime >= the 42 d anchor; kept
                # so the message names Cowrie's own tell (pin last.py prints
                # wtmp begins <today> 00:01:03) if the bounds ever loosen.
                if dt.date() == end.date():
                    flag(i, f"wtmp begins '{val}' is today (Cowrie's own last.py tell)")
            elif tok == "LOGIN_HM":
                t = datetime.strptime(val, "%H:%M")
                login_hm = end.replace(hour=t.hour, minute=t.minute, second=0, microsecond=0)
                if login_hm > end:
                    login_hm -= timedelta(days=1)
                if (end - login_hm).total_seconds() > CURRENT_SESSION_MAX:
                    flag(i, f"LOGIN@ {val} is more than 12 h before now (procps would"
                            " print a weekday)")
            elif tok == "W_IDLE":
                idle = _idle_seconds(val)
                if login_hm is not None and idle > (end - login_hm).total_seconds() + 60:
                    flag(i, f"idle '{val.strip()}' is longer than the session")
            elif tok == "LSDATE":
                dt = datetime.strptime(val, "%b %d  %Y")
                if (end - dt).total_seconds() < LS_MIN_AGE:
                    flag(i, f"ls date '{val}' is not an old package build date")
    for (_, a), (i, b) in zip(order, order[1:]):
        if b > a:
            flag(i, "last rows are out of order (each must be no later than the one above)")
    return bad


def _tod_between(t: datetime, start: datetime, end: datetime) -> bool:
    if (end - start).total_seconds() >= 86400:
        return True
    s = start.hour * 3600 + start.minute * 60 + start.second
    e = end.hour * 3600 + end.minute * 60 + end.second
    x = t.hour * 3600 + t.minute * 60 + t.second
    return s <= x <= e if s <= e else (x >= s or x <= e)


def _visible(line: str) -> str:
    # Control characters (a stray \r from a pty-style write, say) would garble
    # the terminal and hide the very difference being reported.
    return "".join(
        ch if ch == "\t" or (ch >= " " and ch != "\x7f") else repr(ch)[1:-1]
        for ch in line
    )


def compare(name: str, exp: Expected, output: str, rc: int | None,
            timed_out: bool, clock: Clock | None = None, note: str = "") -> CaseResult:
    if clock is None:
        now = datetime.now(timezone.utc)
        clock = Clock(start=now, end=now)
    res = CaseResult(name=name, ok=True)
    want = exp.content.split("\n")
    got = output.split("\n")

    # Pass 1: shape. A line matching its template is rendered as the template
    # so the diff only carries real differences; a line matching another
    # template (an inserted or dropped row) is rendered as that template.
    rendered: list[str] = []
    matched: list[tuple[int, str, list[tuple[str, str]]]] = []
    for i, line in enumerate(got):
        order = ([i] if i < len(want) else []) + [j for j in range(len(want)) if j != i]
        chosen = None
        for j in order:
            vals = _match_line(want[j], line)
            if vals is not None:
                chosen = want[j]
                if j == i:
                    matched.append((i, line, vals))
                break
        rendered.append(chosen if chosen is not None else _visible(line))

    # Pass 2: values against the persona clock. Only meaningful once every
    # line sits on its own template; an offending line is shown as itself.
    if rendered == want:
        bad = _check_values(matched, exp, clock)
        for i in sorted(bad):
            rendered[i] = _visible(got[i])
            res.messages.extend(f"line {i + 1}: {m}" for m in bad[i])

    if rendered != want:
        res.ok = False
        res.diff = list(difflib.unified_diff(
            want, rendered, fromfile=f"expected/{name}.out", tofile="actual", lineterm=""
        ))
    if note:
        res.messages.append(note)
    if timed_out:
        res.ok = False
        res.messages.append("timed out (session hung or never closed)")
    elif exp.rc is not None and rc != exp.rc:
        res.ok = False
        res.messages.append(f"exit status {rc}, expected {exp.rc}")
    return res


def parse_probes(text: str) -> list[tuple[str, str]]:
    probes, seen = [], {"profiler"}
    for n, raw in enumerate(text.split("\n"), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if "\t" not in raw:
            raise ValueError(f"probes.txt:{n}: expected '<name><TAB><command>'")
        name, command = raw.split("\t", 1)
        name = name.strip()
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
            raise ValueError(f"probes.txt:{n}: bad case name {name!r}")
        if name in seen:
            raise ValueError(f"probes.txt:{n}: duplicate case name {name!r}")
        seen.add(name)
        probes.append((name, command))
    return probes


def password_from_userdb(text: str, user: str = "root") -> str:
    """First literal password for `user` in a Cowrie userdb.txt.

    Skips deny rules ('!'), wildcards ('*') and regexes ('/.../'), which do not
    name a password a client can type.
    """
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 2)
        if len(parts) != 3 or parts[0] != user:
            continue
        pw = parts[2]
        if not pw or pw.startswith("!") or pw == "*" or (pw.startswith("/") and len(pw) > 1):
            continue
        return pw
    raise ValueError(f"no literal password for {user!r} in userdb")


# --- transports -------------------------------------------------------------

def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def exec_on_channel(chan, command: str, deadline: float, closed_exc=Exception,
                    stdin: bytes | None = None) -> RunResult:
    """Run `command` on an open paramiko-style channel and drain it.

    Cowrie answers a short exec command and closes the channel before
    paramiko sees the reply to its exec request, so `exec_command` raises
    "Channel closed" although the output and the exit status have already
    arrived (measured on the pin: `whoami` -> b'root\\n', status 0). That
    exception is therefore not a failure; whatever the channel buffered is
    the result.
    """
    unacked = False
    try:
        chan.exec_command(command)
    except closed_exc:
        unacked = True
    if stdin is not None and not unacked:
        chan.sendall(stdin)
        chan.shutdown_write()
    out, err = bytearray(), bytearray()
    while True:
        while chan.recv_ready():
            out += chan.recv(65536)
        while chan.recv_stderr_ready():
            err += chan.recv_stderr(65536)
        drained = not chan.recv_ready() and not chan.recv_stderr_ready()
        if drained and (chan.closed or (chan.exit_status_ready() and chan.eof_received)):
            break
        if time.monotonic() > deadline:
            return RunResult(_decode(bytes(out + err)), None, True)
        time.sleep(0.05)
    rc = chan.recv_exit_status() if chan.exit_status_ready() else None
    # The race above delivers output or an exit status; a refused exec request
    # delivers neither and would otherwise read as plain empty output.
    note = "exec request not acknowledged (no output, no exit status)" \
        if unacked and not out and not err and rc is None else ""
    return RunResult(_decode(bytes(out + err)), rc, False, note)


def scp_record(name: str, data: bytes) -> bytes:
    """One legacy scp upload as the client sends it to `scp -t`: a C-record
    header, the bytes, and the NUL that ends them."""
    return f"C0755 {len(data)} {name}\n".encode() + data + b"\x00"


def paramiko_runner(host: str, port: int, user: str, password: str):
    import paramiko  # noqa: PLC0415 - optional dependency

    def run(command: str, timeout: float, stdin: bytes | None = None) -> RunResult:
        deadline = time.monotonic() + timeout
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port=port, username=user, password=password,
                           look_for_keys=False, allow_agent=False, timeout=timeout,
                           banner_timeout=timeout, auth_timeout=timeout)
            chan = client.get_transport().open_session(timeout=timeout)
            return exec_on_channel(chan, command, deadline, paramiko.SSHException, stdin)
        except Exception as exc:  # noqa: BLE001 - a broken session is a result
            timed = time.monotonic() > deadline
            return RunResult(f"<transport error: {type(exc).__name__}: {exc}>\n", None, timed)
        finally:
            client.close()

    return run


def ssh_runner(host: str, port: int, user: str, password: str):
    if not shutil.which("sshpass") or not shutil.which("ssh"):
        raise SystemExit("neither paramiko nor ssh+sshpass is available")
    base = [
        "sshpass", "-e", "ssh", "-p", str(port),
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password",
        "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10",
        "-T", f"{user}@{host}",
    ]
    env = dict(os.environ, SSHPASS=password)

    def run(command: str, timeout: float, stdin: bytes | None = None) -> RunResult:
        stdio = {"input": stdin} if stdin is not None else {"stdin": subprocess.DEVNULL}
        try:
            p = subprocess.run(base + [command], env=env, capture_output=True,
                               timeout=timeout, **stdio)
        except subprocess.TimeoutExpired as exc:
            return RunResult(_decode((exc.stdout or b"") + (exc.stderr or b"")), None, True)
        return RunResult(_decode(p.stdout + p.stderr), p.returncode, False)

    return run


def make_runner(kind: str, host: str, port: int, user: str, password: str):
    if kind in ("auto", "paramiko"):
        try:
            import paramiko  # noqa: F401, PLC0415
            return "paramiko", paramiko_runner(host, port, user, password)
        except ImportError:
            if kind == "paramiko":
                raise SystemExit("paramiko is not installed")
    return "ssh+sshpass", ssh_runner(host, port, user, password)


# --- CLI --------------------------------------------------------------------

def load_cases(cases_dir: Path, only: str | None) -> list[tuple[str, str]]:
    cases: list[tuple[str, str]] = []
    if only in (None, "profiler"):
        cases.append(("profiler", (cases_dir / "profiler.sh").read_text()))
    if only in (None, "probes"):
        cases.extend(parse_probes((cases_dir / "probes.txt").read_text()))
    return cases


def main(argv: list[str] | None = None, runner=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--password-from", required=True, metavar="USERDB",
                    help="Cowrie userdb.txt; the first literal password for --user is used")
    ap.add_argument("--user", default="root")
    ap.add_argument("--only", choices=("profiler", "probes"))
    ap.add_argument("--case", action="append", default=[], metavar="NAME",
                    help="run only these case names (repeatable)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help="per-case deadline in seconds (default 10)")
    ap.add_argument("--transport", choices=("auto", "paramiko", "ssh"), default="auto")
    ap.add_argument("--uptime-slack", type=float, default=DEFAULT_UPTIME_SLACK,
                    metavar="SECONDS",
                    help="allowed uptime past the 42d 3h17m anchor (default 6 h, for a"
                         " freshly started rehearsal; a long-running Cowrie needs more)")
    ap.add_argument("--cowrie-age", type=float, metavar="SECONDS",
                    help="the Cowrie process age; makes the uptime window two-sided"
                         f" (anchor + age +-{COWRIE_AGE_MARGIN}s). Use it against a"
                         " long-running Cowrie, e.g. production (see the docstring)")
    ap.add_argument("--tz", default="UTC",
                    help="timezone Cowrie renders times in (persona cfg: UTC)")
    ap.add_argument("--cases-dir", type=Path, default=DEFAULT_CASES_DIR)
    ap.add_argument("--upload-source", type=Path, default=Path("/bin/true"),
                    help="ELF fed to '#harness: scp-stdin=' cases (default /bin/true;"
                         " Cowrie never runs it, it only has to be a binary)")
    args = ap.parse_args(argv)

    if runner is None:
        password = password_from_userdb(Path(args.password_from).read_text(), args.user)
        kind, runner = make_runner(args.transport, args.host, args.port, args.user, password)
        print(f"transport: {kind}; target {args.user}@{args.host}:{args.port}")

    if args.uptime_slack < 0:
        raise SystemExit("--uptime-slack must be >= 0")
    if args.cowrie_age is not None and args.cowrie_age < 0:
        raise SystemExit("--cowrie-age must be >= 0")
    try:
        tz = timezone.utc if args.tz == "UTC" else ZoneInfo(args.tz)
    except (ZoneInfoNotFoundError, ValueError):
        raise SystemExit(f"unknown --tz {args.tz!r}")

    cases = load_cases(args.cases_dir, args.only)
    if args.case:
        unknown = set(args.case) - {n for n, _ in cases}
        if unknown:
            raise SystemExit(f"unknown case(s): {', '.join(sorted(unknown))}")
        cases = [c for c in cases if c[0] in args.case]

    passed = failed = skipped = 0
    for name, command in cases:
        exp_path = args.cases_dir / "expected" / f"{name}.out"
        try:
            exp = parse_expected(exp_path.read_text())
        except (OSError, ValueError) as exc:
            failed += 1
            print(f"FAIL {name}: bad or missing expected file: {exc}")
            continue
        if exp.skip:
            skipped += 1
            print(f"SKIP {name}: {exp.skip}")
            continue
        started = datetime.now(timezone.utc)
        if exp.scp_stdin:
            try:
                payload = args.upload_source.read_bytes()
            except OSError as exc:
                failed += 1
                print(f"FAIL {name}: cannot read --upload-source: {exc}")
                continue
            if not payload.startswith(b"\x7fELF"):
                failed += 1
                print(f"FAIL {name}: --upload-source {args.upload_source} is not an ELF")
                continue
            run = runner(command, args.timeout, stdin=scp_record(exp.scp_stdin, payload))
        else:
            run = runner(command, args.timeout)
        clock = Clock(start=started, end=datetime.now(timezone.utc),
                      uptime_slack=args.uptime_slack, tz=tz,
                      cowrie_age=args.cowrie_age)
        res = compare(name, exp, run.output, run.rc, run.timed_out, clock, run.note)
        if res.ok:
            passed += 1
            print(f"PASS {name}")
            continue
        failed += 1
        print(f"FAIL {name}")
        for msg in res.messages:
            print(f"  ! {msg}")
        for line in res.diff:
            print(line)
    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
