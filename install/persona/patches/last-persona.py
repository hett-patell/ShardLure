#!/usr/bin/env python3
"""Patch cowrie/commands/last.py: last prints the persona's wtmp.

WHY (payload-yield Phase B Task 5; factsheet-phaseB 2 LAST, 5 #4): the
recurring profiler (1,452 sessions in 30 days) ends with `last`. v3.1.1's
last prints exactly one row, the caller's own session (as `pts/0` even on an
exec channel, which has no pty), then `wtmp begins <boot>`. A real 22.04 box
answering an exec channel shows its admins' history and the boot, and no row
for the caller at all: sshd writes wtmp only for pty sessions. The persona's
history is the one gen-time-persona.py writes into the txtcmd this command
shadows (six `ubuntu` logins from 10.0.0.8/.12, the reboot row, wtmp begins).

Where the times come from (Task 5 review I-1, option (b)):
- The reboot row and `wtmp begins` come from protocol.boot_time(), the same
  boot Cowrie's /proc/uptime, uptime and w report ([honeypot] boot_offset).
- The admin history is laid out once from the Cowrie process start
  (persona_start = boot_time() + boot_offset() = factory.starttime) and never
  moves while the process runs: wtmp is append-only, so a history anchored to
  now (every row shifts minute by minute) or to a 4 h grid (every completed
  row moves forward a day per day, the live session "re-logs-in" every 4 h)
  is visible to any bot that stores its LAST field (the profiler, 1,452
  sessions in 30 days). gen-time-persona writes the motd at deploy, just
  before the Cowrie (re)start, so its "Last login" names the same session.
  A restart regenerates the history together with the boot, which reads as a
  reboot. The "still logged in" ubuntu session stays logged in for the
  process's life (w shows its LOGIN@ ageing into procps' DddHH/DDMonYY forms
  and its IDLE growing), as a forgotten tmux or jump-host session does.

An interactive (pty) caller gets its own "still logged in" row on pts/1, as
sshd would write it; an exec caller gets none. The helpers below are shared
with w (uptime-loadavg.py), so `w` and `last` always name the same login.
Options: -n N / -N / --limit[=]N, and user or tty names (`last reboot`,
`last ubuntu`); the display options util-linux has beyond those are accepted
and ignored; an unknown option fails as util-linux does.
"""

import sys
from pathlib import Path

OLD = r'''class Command_last(HoneyPotCommand):
    def call(self) -> None:
        line = list(self.args)
        while len(line):
            arg = line.pop(0)
            if not arg.startswith("-"):
                continue
            elif arg == "-n" and len(line) and line[0].isdigit():
                line.pop(0)

        self.write(
            "{:8s} {:12s} {:16s} {}   still logged in\n".format(
                self.user["username"],
                "pts/0",
                self.protocol.clientIP,
                last_date(self.protocol.logintime, seconds=False),
            )
        )

        # wtmp starts at the emulated boot, the same clock uptime reports.
        boot = self.protocol.boot_time()
        self.write("\n")
        self.write(f"wtmp begins {last_date(boot, seconds=True)}\n")
'''

NEW = r'''# ShardLure persona (last-persona.py): the box's own wtmp. The admin history
# is gen-time-persona.py's SESSIONS, in seconds (a contract test keeps the two
# equal): (login before the reference instant, session length or None for
# "still logged in", tty, source).
PERSONA_USER = "ubuntu"
PERSONA_KERNEL = "5.15.0-94-generic"
PERSONA_SESSIONS = (
    (24420, None, "pts/0", "10.0.0.8"),
    (116760, 9780, "pts/0", "10.0.0.8"),
    (136620, 2580, "pts/1", "10.0.0.12"),
    (204900, 6480, "pts/0", "10.0.0.8"),
    (331260, 5160, "pts/0", "10.0.0.8"),
    (427380, 4980, "pts/0", "10.0.0.8"),
)
# The still-logged-in admin's last keystroke, after login (w's IDLE).
PERSONA_ACTIVE_FOR = 41 * 60
CALLER_TTY = "pts/1"


def persona_start(protocol) -> float:
    """The instant the persona's history is laid out from: the Cowrie process
    start, fixed for the process's life (boot_time() is start - boot_offset)."""
    from cowrie.shell.protocol import boot_offset

    return protocol.boot_time() + boot_offset()


def admin_session(protocol) -> tuple[float, float, str, str]:
    """(login, last activity, tty, source) of the still-logged-in admin."""
    offset, _, tty, source = PERSONA_SESSIONS[0]
    login = persona_start(protocol) - offset
    return login, login + PERSONA_ACTIVE_FOR, tty, source


def caller_has_utmp(protocol) -> bool:
    """sshd writes utmp/wtmp only for a pty session, never for exec."""
    from cowrie.shell.protocol import HoneyPotExecProtocol

    return not isinstance(protocol, HoneyPotExecProtocol)


def _last_row(user: str, tty: str, host: str, login: float, length) -> str:
    when = last_date(login, seconds=False)
    if length is None:
        status = "still logged in"
    else:
        total = int(length)
        logout = time.strftime("%H:%M", time.localtime(login + total))
        status = f"- {logout}  ({total // 3600:02d}:{total % 3600 // 60:02d})"
    return f"{user[:8]:<8} {tty[:12]:<12} {host[:16]:<16} {when}   {status}"


def persona_last_rows(start: float, boot: float, caller=None) -> list[tuple[str, str, str]]:
    """last(1)'s rows, newest first, as (user, tty, text), for a history laid
    out from `start`. `caller` is (user, source, login) for a pty session."""
    rows = []
    if caller is not None:
        user, source, login = caller
        rows.append((user, CALLER_TTY,
                     _last_row(user, CALLER_TTY, source, login, None)))
    for offset, length, tty, source in PERSONA_SESSIONS:
        rows.append((PERSONA_USER, tty,
                     _last_row(PERSONA_USER, tty, source, start - offset, length)))
    rows.append(("reboot", "system boot",
                 f"{'reboot':<8} {'system boot':<12} {PERSONA_KERNEL[:16]:<16} "
                 f"{last_date(boot, seconds=False)}   still running"))
    return rows


class Command_last(HoneyPotCommand):
    def call(self) -> None:
        limit = None
        names = []
        args = list(self.args)
        while args:
            arg = args.pop(0)
            if arg == "--":
                names.extend(args)
                break
            if arg in ("-n", "--limit") or arg.startswith("--limit="):
                value = arg.split("=", 1)[1] if "=" in arg else (args.pop(0) if args else "")
                if not value.isdigit():
                    self.errorWrite(f"last: failed to parse number: '{value}'\n")
                    self.exit(1)
                    return
                limit = int(value)
            elif arg.startswith("-n") and arg[2:].isdigit():
                limit = int(arg[2:])
            elif len(arg) > 1 and arg[0] == "-" and arg[1:].isdigit():
                limit = int(arg[1:])
            elif arg in ("-f", "--file", "-s", "--since", "-t", "--until",
                         "-p", "--present", "--time-format"):
                if args:
                    args.pop(0)
            elif arg.startswith("--"):
                if arg.split("=", 1)[0] not in (
                        "--hostlast", "--dns", "--fulltimes", "--ip", "--nohostname",
                        "--system", "--fullnames", "--file", "--since", "--until",
                        "--present", "--time-format"):
                    self.errorWrite(f"last: unrecognized option '{arg}'\n"
                                    "Try 'last --help' for more information.\n")
                    self.exit(1)
                    return
            elif arg.startswith("-") and len(arg) > 1:
                bad = next((c for c in arg[1:] if c not in "adFiwRx0123456789"), None)
                if bad is not None:
                    self.errorWrite(f"last: invalid option -- '{bad}'\n"
                                    "Try 'last --help' for more information.\n")
                    self.exit(1)
                    return
            else:
                names.append(arg)

        caller = None
        if caller_has_utmp(self.protocol):
            caller = (self.user["username"], self.protocol.clientIP,
                      self.protocol.logintime)
        rows = persona_last_rows(persona_start(self.protocol), self.protocol.boot_time(), caller)
        if names:
            rows = [r for r in rows if r[0] in names or r[1] in names]
        if limit is not None:
            rows = rows[:limit]
        for _, _, text in rows:
            self.write(text + "\n")

        # wtmp starts at the emulated boot, the same clock uptime reports.
        boot = self.protocol.boot_time()
        self.write("\n")
        self.write(f"wtmp begins {last_date(boot, seconds=True)}\n")
'''

BLOCKS = ((OLD, NEW),)


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/commands/last.py"
    content = path.read_text(encoding="utf-8")
    counts = [(content.count(old), content.count(new)) for old, new in BLOCKS]
    if all(c == (0, 1) for c in counts):
        print(f"  [skip] {path}: already patched")
        return 0
    if not all(c == (1, 0) for c in counts):
        print(
            f"  [FAIL] {path}: target is neither pristine nor fully patched "
            f"(old/new counts {counts}) - upstream last changed",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    for old, new in BLOCKS:
        content = content.replace(old, new, 1)
    path.write_text(content, encoding="utf-8")
    print(f"  [ok] {path}: patched (last prints the persona's wtmp)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
