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
  #harness: rc=N        the exit status must be N (otherwise it is not checked)
  #harness: advances    successive {{UPTIME_SECS}} values must strictly rise
  #harness: skip=WHY    do not run; reported as SKIP (deferred probes)

Volatile tokens. Only these fields vary between a real box and a correct
honeypot, so nothing else is normalised:
  {{UPTIME_SECS}}   /proc/uptime seconds, must be >= the persona's 42d 3h17m
  {{IDLE_SECS}}     /proc/uptime idle seconds (shape only)
  {{UPTIME_HUMAN}}  "up N days, H:MM" (uptime/w), must be >= the same anchor
  {{WDATE}}         last's weekday-date, e.g. "Mon Oct  5"
  {{HH:MM}} {{HH:MM:SS}} {{YEAR}}   clock fields in last/w/uptime
  {{LSDATE}}        ls -l's date column ("Aug 25 15:12" or "Aug 25  2025")

Transport: paramiko when importable (exec_command, no pty - like the
profiler's Go client), otherwise `sshpass -e ssh`. Each case gets a 10 s
deadline; a hang (e.g. `passwd` waiting on stdin forever) is a FAIL, not a
stuck run. CI runs only the unit tests (scripts/test_cowrie_behaviour.py):
this CLI needs a live Cowrie.

Usage:
  cowrie-behaviour-test.py --host 127.0.0.1 --port 2299 \\
      --password-from etc/userdb.txt [--only profiler|probes]
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
from pathlib import Path

# The persona advertises 42d 3h17m of uptime (install/persona/gen-time-persona.py
# UPTIME; Phase B sets Cowrie's boot_offset to the same value). Anything below
# it disagrees with the persona's own `uptime`, `last` and motd.
UPTIME_ANCHOR = 42 * 86400 + 3 * 3600 + 17 * 60  # 3640620

DEFAULT_TIMEOUT = 10.0
DEFAULT_CASES_DIR = Path(__file__).resolve().parent / "behaviour"

_WDAY = r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)"
_MON = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
_HM = r"(?:[01]\d|2[0-3]):[0-5]\d"

# token -> regex. Group names are generated per occurrence; the checks below
# key on the token name.
TOKENS = {
    "UPTIME_SECS": r"\d+\.\d{2}",
    "IDLE_SECS": r"\d+\.\d{2}",
    "UPTIME_HUMAN": r"up \d+ days?, +\d{1,2}:[0-5]\d",
    "WDATE": _WDAY + " " + _MON + r" [ 123]\d",
    "HH:MM": _HM,
    "HH:MM:SS": _HM + r":[0-5]\d",
    "YEAR": r"\d{4}",
    "LSDATE": _MON + r" [ 123]\d (?: \d{4}|" + _HM + ")",
}
_TOKEN_RE = re.compile(r"\{\{([A-Z_:]+)\}\}")
_DIRECTIVE = "#harness:"


@dataclass
class Expected:
    content: str
    rc: int | None = None
    skip: str | None = None
    advances: bool = False


@dataclass
class RunResult:
    output: str
    rc: int | None
    timed_out: bool


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
        elif body == "advances":
            exp.advances = True
        elif body.startswith("skip="):
            exp.skip = body[5:].strip() or "skipped"
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


def _human_seconds(text: str) -> int:
    m = re.match(r"up (\d+) days?, +(\d{1,2}):(\d\d)", text)
    return int(m.group(1)) * 86400 + int(m.group(2)) * 3600 + int(m.group(3)) * 60


def _match_line(template: str, actual: str) -> tuple[bool, list[float], list[str]]:
    """Does `actual` fit `template`? Returns (ok, uptime values, problems)."""
    if "{{" not in template:
        return template == actual, [], []
    rx, names = _line_regex(template)
    m = rx.fullmatch(actual)
    if not m:
        return False, [], []
    uptimes, problems = [], []
    for idx, name in enumerate(names):
        val = m.group(f"t{idx}")
        if name == "UPTIME_SECS":
            secs = float(val)
            uptimes.append(secs)
            if secs < UPTIME_ANCHOR:
                problems.append(
                    f"uptime {val}s is below the persona anchor {UPTIME_ANCHOR}s (42d 3h17m)"
                )
        elif name == "UPTIME_HUMAN" and _human_seconds(val) < UPTIME_ANCHOR:
            problems.append(f"'{val}' is below the persona anchor (up 42 days,  3:17)")
    return not problems, uptimes, problems


def _visible(line: str) -> str:
    # Control characters (a stray \r from a pty-style write, say) would garble
    # the terminal and hide the very difference being reported.
    return "".join(
        ch if ch == "\t" or (ch >= " " and ch != "\x7f") else repr(ch)[1:-1]
        for ch in line
    )


def compare(name: str, exp: Expected, output: str, rc: int | None,
            timed_out: bool) -> CaseResult:
    res = CaseResult(name=name, ok=True)
    want = exp.content.split("\n")
    got = output.split("\n")

    rendered: list[str] = []
    uptimes: list[float] = []
    for i, line in enumerate(got):
        # Prefer the template at the same index, then any other: a matched
        # volatile line is shown as its template so the diff only carries
        # real differences.
        order = ([i] if i < len(want) else []) + [j for j in range(len(want)) if j != i]
        chosen = None
        for j in order:
            ok, ups, problems = _match_line(want[j], line)
            if ok:
                chosen = want[j]
                if j == i:
                    uptimes.extend(ups)
                break
            if j == i and problems:
                res.messages.extend(problems)
        rendered.append(chosen if chosen is not None else _visible(line))

    if rendered != want:
        res.ok = False
        res.diff = list(difflib.unified_diff(
            want, rendered, fromfile=f"expected/{name}.out", tofile="actual", lineterm=""
        ))
    elif exp.advances and any(b <= a for a, b in zip(uptimes, uptimes[1:])):
        res.ok = False
        res.messages.append(
            "uptime did not advance between reads: "
            + ", ".join(f"{u:.2f}" for u in uptimes)
        )
    if timed_out:
        res.ok = False
        res.messages.append("timed out (session hung or never closed)")
    elif exp.rc is not None and rc != exp.rc:
        res.ok = False
        res.messages.append(f"exit status {rc}, expected {exp.rc}")
    if res.messages and not res.diff:
        res.ok = False
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


def exec_on_channel(chan, command: str, deadline: float, closed_exc=Exception) -> RunResult:
    """Run `command` on an open paramiko-style channel and drain it.

    Cowrie answers a short exec command and closes the channel before
    paramiko sees the reply to its exec request, so `exec_command` raises
    "Channel closed" although the output and the exit status have already
    arrived (measured on the pin: `whoami` -> b'root\\n', status 0). That
    exception is therefore not a failure; whatever the channel buffered is
    the result.
    """
    try:
        chan.exec_command(command)
    except closed_exc:
        pass
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
    return RunResult(_decode(bytes(out + err)), rc, False)


def paramiko_runner(host: str, port: int, user: str, password: str):
    import paramiko  # noqa: PLC0415 - optional dependency

    def run(command: str, timeout: float) -> RunResult:
        deadline = time.monotonic() + timeout
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port=port, username=user, password=password,
                           look_for_keys=False, allow_agent=False, timeout=timeout,
                           banner_timeout=timeout, auth_timeout=timeout)
            chan = client.get_transport().open_session(timeout=timeout)
            return exec_on_channel(chan, command, deadline, paramiko.SSHException)
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

    def run(command: str, timeout: float) -> RunResult:
        try:
            p = subprocess.run(base + [command], env=env, capture_output=True,
                               timeout=timeout, stdin=subprocess.DEVNULL)
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
    ap.add_argument("--cases-dir", type=Path, default=DEFAULT_CASES_DIR)
    args = ap.parse_args(argv)

    if runner is None:
        password = password_from_userdb(Path(args.password_from).read_text(), args.user)
        kind, runner = make_runner(args.transport, args.host, args.port, args.user, password)
        print(f"transport: {kind}; target {args.user}@{args.host}:{args.port}")

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
        run = runner(command, args.timeout)
        res = compare(name, exp, run.output, run.rc, run.timed_out)
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
