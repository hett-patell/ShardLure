#!/usr/bin/env python3
"""Patch cowrie/commands/base.py: who lists the persona's utmp, as w and last do.

WHY (payload-yield Phase B Task 7; Task 5 review I-2): v3.1.1's who printed
one row, the caller's own (`root pts/0 <now> (<client ip>)`), and that
command shadows the persona's txtcmds/usr/bin/who. After Task 5, w and last
name the persona's still-logged-in `ubuntu` session on pts/0 and give an exec
caller no row (sshd writes utmp only for a pty). So who contradicted them on
both channel types:
  exec: a real box lists `ubuntu pts/0 ... (10.0.0.8)` and nothing for the
        caller; Cowrie listed the caller.
  pty:  w and last put the caller on pts/1 beside ubuntu on pts/0; Cowrie's
        who put root on pts/0, two users on one tty.

Now who reads the same helpers as w (uptime-loadavg.py) and last
(last-persona.py): admin_session(), caller_has_utmp() and CALLER_TTY. The
format is coreutils 8.32's under 22.04's LANG=C.UTF-8 (a hard locale, so ISO
times; an explicit C or POSIX LC_ALL/LC_TIME/LANG gives `Oct  5 02:22`): "%-8s %-12s %Y-%m-%d %H:%M (host)". Options: -q/--count, -H, -b
(the reboot row at boot_time()), `am i`/-m (the caller's row, nothing on an
exec channel), and coreutils' error on an invalid option; the other valid
options print the plain list. Every form was compared with ubuntu:22.04 who
over a crafted utmp.
"""
import sys
from pathlib import Path

OLD = '''class Command_who(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            f"{self.user['username']:8s} pts/0        {time.strftime('%Y-%m-%d', time.localtime(self.protocol.logintime))} {time.strftime('%H:%M', time.localtime(self.protocol.logintime))} ({self.protocol.clientIP})\\n"
        )
'''

NEW = '''class Command_who(HoneyPotCommand):
    """coreutils who over the persona's utmp (ShardLure who-persona.py)."""

    LETTERS = "abdHlmpqrsTtuw"
    LONG = ("--all", "--boot", "--dead", "--heading", "--login", "--lookup", "--mesg",
            "--message", "--writable", "--process", "--count", "--runlevel", "--short",
            "--time", "--users", "--ips")

    def call(self) -> None:
        from cowrie.commands.last import CALLER_TTY, PERSONA_USER, admin_session, caller_has_utmp

        flags = set()
        operands = []
        for arg in self.args:
            if arg.startswith("--"):
                if arg not in self.LONG:
                    self.errorWrite(f"who: unrecognized option '{arg}'\\n"
                                    "Try 'who --help' for more information.\\n")
                    self.exit_code = 1
                    return
                flags.add({"--count": "q", "--heading": "H", "--boot": "b"}.get(arg, ""))
            elif arg.startswith("-") and len(arg) > 1:
                for ch in arg[1:]:
                    if ch not in self.LETTERS:
                        self.errorWrite(f"who: invalid option -- '{ch}'\\n"
                                        "Try 'who --help' for more information.\\n")
                        self.exit_code = 1
                        return
                    flags.add(ch)
            else:
                operands.append(arg)
        # `who am i` (two operands) is -m: the caller's own terminal only.
        only_me = "m" in flags or len(operands) == 2

        login, _, tty, source = admin_session(self.protocol)
        rows = [] if only_me else [(PERSONA_USER, tty, login, source)]
        if caller_has_utmp(self.protocol):
            rows.append((self.user["username"], CALLER_TTY, self.protocol.logintime,
                         self.protocol.clientIP))

        # coreutils prints ISO times under a "hard" locale and `%b %e %H:%M`
        # under C/POSIX. A real session gets LANG=C.UTF-8 from pam_env, so an
        # unset locale is the persona's C.UTF-8; `LC_ALL=C who` is not.
        locale = next((self.environ.get(k) for k in ("LC_ALL", "LC_TIME", "LANG")
                       if self.environ.get(k)), "C.UTF-8")
        fmt = "%b %e %H:%M" if locale in ("C", "POSIX") else "%Y-%m-%d %H:%M"

        def stamp(when: float) -> str:
            return time.strftime(fmt, time.localtime(when))

        if "q" in flags:
            self.write(" ".join(user for user, *_ in rows) + "\\n")
            self.write(f"# users={len(rows)}\\n")
            return
        if "H" in flags:
            self.write(f"NAME     LINE         {'TIME':<{len(stamp(0))}} COMMENT\\n")
        if "b" in flags:
            self.write(f"{'':<8} {'system boot':<12} {stamp(self.protocol.boot_time())}\\n")
            return
        for user, line, when, host in rows:
            self.write(f"{user[:8]:<8} {line:<12} {stamp(when)} ({host})\\n")
'''

BLOCKS = ((OLD, NEW),)


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/commands/base.py"
    content = path.read_text(encoding="utf-8")
    counts = [(content.count(old), content.count(new)) for old, new in BLOCKS]
    if all(c == (0, 1) for c in counts):
        print(f"  [skip] {path}: already patched")
        return 0
    if not all(c == (1, 0) for c in counts):
        print(
            f"  [FAIL] {path}: target is neither pristine nor fully patched "
            f"(old/new counts {counts}) - upstream who changed",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    for old, new in BLOCKS:
        content = content.replace(old, new, 1)
    path.write_text(content, encoding="utf-8")
    print(f"  [ok] {path}: patched (who lists the persona's utmp)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
