#!/usr/bin/env python3
"""Patch cowrie/commands/uptime.py and base.py (Command_w): procps uptime and w.

WHY (payload-yield Phase B Task 5; factsheet-phaseB 3 #15, 5 #5): `w` and
`uptime` are 50 probe sessions in 30 days on prod, and v3.1.1 answers both
with three tells at once:
- the load average is hard-coded `0.00, 0.00, 0.00`, while the persona's
  /proc/loadavg (and its motd) say 0.38 0.42 0.45;
- uptime prints `HH:MM:SS  up` (two spaces, no leading one), where procps-ng
  3.3.17 prints ` HH:MM:SS up`; with a zero hour Cowrie prints ` 0:05` where
  procps prints `5 min`;
- w lists the caller's own exec session (`root pts/0 127.0.0.1 ... w`). sshd
  writes utmp only for a pty session, so a real box shows only who is
  logged in: the persona's admin, `ubuntu` on pts/0 from 10.0.0.8, idle in
  its login shell (`-bash`; Task 1 review ruling I-4).

Both now print procps-ng 3.3.17's format (sprint_uptime, print_logintime,
print_time_ival7) from the same clocks every other time source uses: the
uptime is protocol.uptime() (boot_time(), [honeypot] boot_offset, which
/proc/uptime and last also read), the load average is the fake filesystem's
/proc/loadavg, and the admin's login and last keystroke come from
cowrie.commands.last's admin_session(), so `w` and `last` always name the same
login (last-persona.py, which therefore comes first in PATCHES). That login is
fixed at the Cowrie process start; its LOGIN@ ages through procps' three
forms and its IDLE grows in real time, as on a real box. A pty caller gets
its own row and the user count includes it.

Options: uptime -p/-s/-h/-V; w -h/-s/-f, a user name, and -u/-i/-o accepted
(no effect on this output). Unknown options fail with procps' usage text.

Command_w lives in commands/base.py beside Command_passwd, which
passwd-stdin.py patches; the two blocks are disjoint and both patches check
their own anchor, so either order leaves the other's anchor intact.
"""

import sys
from pathlib import Path

OLD_UPTIME = r'''class Command_uptime(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            "{}  up {},  1 user,  load average: 0.00, 0.00, 0.00\n".format(
                time.strftime("%H:%M:%S"), utils.uptime(self.protocol.uptime())
            )
        )
'''

NEW_UPTIME = r'''# ShardLure persona (uptime-loadavg.py): procps-ng 3.3.17 uptime, shared with
# w (commands/base.py). The load average is the fake /proc/loadavg; the user
# count is the persona's admin plus a pty caller (cowrie.commands.last).
PROCPS_USAGE_TAIL = "\nFor more details see {}.\n"


def procps_loadavg(fs) -> str:
    """The three load figures of the fake /proc/loadavg, as procps prints them."""
    try:
        fields = fs.file_contents("/proc/loadavg").split()
        return ", ".join(f"{float(x):.2f}" for x in fields[:3])
    except Exception:
        return "0.00, 0.00, 0.00"


def procps_uptime_line(fs, now: float, uptime: float, users: int) -> str:
    """sprint_uptime(0): ` 07:16:27 up 42 days,  3:17,  1 user,  load ...`."""
    secs = int(uptime)
    days, hours, mins = secs // 86400, secs // 3600 % 24, secs // 60 % 60
    text = time.strftime(" %H:%M:%S up ", time.localtime(now))
    if days:
        text += f"{days} day{'s' if days != 1 else ''}, "
    text += f"{hours:2d}:{mins:02d}, " if hours else f"{mins} min, "
    text += f"{users:2d} user{'' if users == 1 else 's'}, "
    return text + f" load average: {procps_loadavg(fs)}\n"


def procps_pretty(uptime: float) -> str:
    """sprint_uptime(1), uptime -p: `up 6 weeks, 3 hours, 17 minutes`."""
    secs = int(uptime)
    parts = []
    for count, one, many in (
        (secs // (86400 * 365 * 10), "decade", "decades"),
        (secs // (86400 * 365) % 10, "year", "years"),
        (secs // (86400 * 7) % 52, "week", "weeks"),
        (secs // 86400 % 7, "day", "days"),
        (secs // 3600 % 24, "hour", "hours"),
    ):
        if count:
            parts.append(f"{count} {many if count > 1 else one}")
    mins = secs // 60 % 60
    if mins or secs < 60:
        parts.append(f"{mins} {'minutes' if mins > 1 else 'minute'}")
    return "up " + ", ".join(parts) + "\n"


def procps_users(protocol) -> int:
    from cowrie.commands.last import caller_has_utmp

    return 1 + (1 if caller_has_utmp(protocol) else 0)


class Command_uptime(HoneyPotCommand):
    USAGE = (
        "\nUsage:\n uptime [options]\n\nOptions:\n"
        " -p, --pretty   show uptime in pretty format\n"
        " -h, --help     display this help and exit\n"
        " -s, --since    system up since\n"
        " -V, --version  output version information and exit\n"
        + PROCPS_USAGE_TAIL.format("uptime(1)")
    )

    def call(self) -> None:
        # getopt order: -s, -h and -V act (and exit) as soon as they are read.
        pretty = False
        positional = []
        args = list(self.args)
        while args:
            arg = args.pop(0)
            if arg == "--":
                positional.extend(args)
                break
            if arg.startswith("--"):
                short = {"--pretty": "p", "--since": "s", "--help": "h",
                         "--version": "V"}.get(arg)
                if short is None:
                    self.errorWrite(f"uptime: unrecognized option '{arg}'\n" + self.USAGE)
                    self.exit(1)
                    return
                chars = short
            elif arg.startswith("-") and len(arg) > 1:
                chars = arg[1:]
            else:
                positional.append(arg)
                continue
            for c in chars:
                if c == "p":
                    pretty = True
                elif c == "s":
                    since = time.localtime(int(time.time() - self.protocol.uptime() + 0.5))
                    self.write(time.strftime("%Y-%m-%d %H:%M:%S\n", since))
                    return
                elif c == "h":
                    self.write(self.USAGE)
                    return
                elif c == "V":
                    self.write("uptime from procps-ng 3.3.17\n")
                    return
                else:
                    self.errorWrite(f"uptime: invalid option -- '{c}'\n" + self.USAGE)
                    self.exit(1)
                    return
        if positional:
            self.errorWrite(self.USAGE)
            self.exit(1)
            return
        now = time.time()
        uptime = self.protocol.uptime()
        if pretty:
            self.write(procps_pretty(uptime))
        else:
            self.write(procps_uptime_line(self.fs, now, uptime, procps_users(self.protocol)))
'''

# Command_w in commands/base.py (OLD/NEW: the names the contract test and
# check-cowrie-patches.sh's drift fixture read).
OLD = r'''class Command_w(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            f" {time.strftime('%H:%M:%S')} up {utils.uptime(self.protocol.uptime())},  1 user,  load average: 0.00, 0.00, 0.00\n"
        )
        self.write(
            "USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT\n"
        )
        self.write(
            f"{self.user['username']:8s} pts/0    {self.protocol.clientIP[:17].ljust(17)} {time.strftime('%H:%M', time.localtime(self.protocol.logintime))}    0.00s  0.00s  0.00s w\n"
        )
'''

NEW = r'''class Command_w(HoneyPotCommand):
    """procps-ng 3.3.17 w (ShardLure persona, uptime-loadavg.py): the
    persona's admin on pts/0 in its login shell, plus a pty caller; an exec
    caller has no utmp row. Header from commands/uptime.py, login and
    last keystroke from commands/last.py, so w agrees with uptime and last."""

    USAGE = (
        "\nUsage:\n w [options]\n\nOptions:\n"
        " -h, --no-header     do not print header\n"
        " -u, --no-current    ignore current process username\n"
        " -s, --short         short format\n"
        " -f, --from          show remote hostname field\n"
        " -o, --old-style     old style output\n"
        " -i, --ip-addr       display IP address instead of hostname (if possible)\n"
        "\n     --help     display this help and exit\n"
        " -V, --version  output version information and exit\n"
        "\nFor more details see w(1).\n"
    )
    LONG = {"--no-header": "h", "--no-current": "u", "--short": "s", "--from": "f",
            "--old-style": "o", "--ip-addr": "i", "--version": "V", "--help": "?"}

    @staticmethod
    def ival7(seconds: float, centi: int = 0) -> str:
        """print_time_ival7, the 7-column IDLE/JCPU/PCPU cell."""
        t = int(seconds)
        if t >= 48 * 3600:
            return f" {t // 86400:2d}days"
        if t >= 3600:
            return f" {t // 3600:2d}:{t // 60 % 60:02d}m"
        if t > 60:
            return f" {t // 60:2d}:{t % 60:02d} "
        return f" {t:2d}.{centi:02d}s"

    @staticmethod
    def logintime(login: float, now: float) -> str:
        """print_logintime: HH:MM within 12 h or on the same day, else DddHH,
        or DDMonYY past 6 days (the persona's session ages through all three
        over the Cowrie process's life)."""
        tm = time.localtime(login)
        if now - login > 12 * 3600 and tm.tm_yday != time.localtime(now).tm_yday:
            if now - login > 6 * 86400:
                return " " + time.strftime("%d%b%y", tm)
            return " " + time.strftime("%a", tm) + f"{tm.tm_hour:02d}  "
        return f" {tm.tm_hour:02d}:{tm.tm_min:02d}  "

    def call(self) -> None:
        from cowrie.commands.last import CALLER_TTY, PERSONA_USER, admin_session, caller_has_utmp
        from cowrie.commands.uptime import procps_uptime_line

        flags = set()
        names = []
        for arg in self.args:
            if arg.startswith("--"):
                opt = self.LONG.get(arg)
                if opt is None:
                    self.errorWrite(f"w: unrecognized option '{arg}'\n" + self.USAGE)
                    self.exit(1)
                    return
                flags.add(opt)
            elif arg.startswith("-") and len(arg) > 1:
                for c in arg[1:]:
                    if c not in "husfoiV":
                        self.errorWrite(f"w: invalid option -- '{c}'\n" + self.USAGE)
                        self.exit(1)
                        return
                    flags.add(c)
            else:
                names.append(arg)
        if "?" in flags:
            self.write(self.USAGE)
            return
        if "V" in flags:
            self.write("w from procps-ng 3.3.17\n")
            return

        now = time.time()
        login, active, tty, source = admin_session(self.protocol)
        # (user, tty, from, login, idle, jcpu, pcpu, what)
        rows = [(PERSONA_USER, tty, source, login, now - active, "  0.04s", "  0.01s", "-bash")]
        if caller_has_utmp(self.protocol):
            rows.append((self.user["username"], CALLER_TTY, self.protocol.clientIP,
                         self.protocol.logintime, 0, "  0.00s", "  0.00s", "w"))
        long_form = "s" not in flags
        show_from = "f" not in flags
        if "h" not in flags:
            self.write(procps_uptime_line(self.fs, now, self.protocol.uptime(), len(rows)))
            head = "USER     TTY      " + ("FROM           " if show_from else "")
            head += "  LOGIN@   IDLE   JCPU   PCPU WHAT\n" if long_form else "   IDLE WHAT\n"
            self.write(head)
        for user, line, host, since, idle, jcpu, pcpu, what in rows:
            if names and names[0] != user:
                continue
            text = f"{user[:8]:<9}{line[:8]:<9}"
            if show_from:
                text += f"{(host or '-')[:16]:<16}"
            if long_form:
                text += self.logintime(since, now) + self.ival7(idle) + jcpu + pcpu
            else:
                text += self.ival7(idle)
            self.write(f"{text} {what}\n")
'''

TARGETS = (
    ("src/cowrie/commands/uptime.py", OLD_UPTIME, NEW_UPTIME),
    ("src/cowrie/commands/base.py", OLD, NEW),
)


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    home = Path(args[0])
    contents = {rel: (home / rel).read_text(encoding="utf-8") for rel, _, _ in TARGETS}
    counts = [(contents[rel].count(old), contents[rel].count(new)) for rel, old, new in TARGETS]
    if all(c == (0, 1) for c in counts):
        print(f"  [skip] {home}: uptime.py, base.py already patched")
        return 0
    if not all(c == (1, 0) for c in counts):
        print(
            f"  [FAIL] {home}: uptime.py/base.py are neither pristine nor fully patched "
            f"(old/new counts {counts}) - upstream uptime or w changed",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {home}: uptime.py, base.py compatible")
        return 0
    for rel, old, new in TARGETS:
        (home / rel).write_text(contents[rel].replace(old, new, 1), encoding="utf-8")
    print(f"  [ok] {home}: patched uptime.py, base.py (procps uptime and w)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
