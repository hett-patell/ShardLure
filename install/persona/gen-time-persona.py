#!/usr/bin/env python3
"""Generate the TIME-SENSITIVE persona files against the live clock at deploy.

The static txtcmds/honeyfs files are frozen at a fixed moment, which is a
honeypot tell: Cowrie's `date` command renders dynamically from the real system
clock, so a visitor who compares `date` to `uptime`/`last`/`who` sees the box
insist it is months in the past. This script rewrites the handful of files that
encode absolute time so they are internally consistent AND anchored to "now" at
deploy time.

Anchoring model: uptime is held at a constant, plausible 42d 3h17m, and the boot
instant is derived as `now - uptime`. So the box always claims "up 42 days" while
its boot date, login history weekdays, and /proc/uptime seconds all track the
real clock and agree with each other.

Files rewritten (all under COWRIE_HOME):
  share/cowrie/txtcmds/usr/bin/uptime
  share/cowrie/txtcmds/usr/bin/w
  share/cowrie/txtcmds/usr/bin/who
  share/cowrie/txtcmds/usr/bin/last
  honeyfs/proc/uptime
  honeyfs/etc/motd

motd is the sharpest clock tell: it is the FIRST thing an attacker sees, before
typing anything, and it embeds an absolute "System information as of <date>" +
"Last login" line. Frozen at deploy it read 86 days stale on the reference box
while `date` tracked the real clock. It is regenerated here from the same
UPTIME / LOAD / SESSIONS constants so load, uptime, and the last-login line all
agree with who/w/last/uptime.

Usage: gen-time-persona.py COWRIE_HOME
"""
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Canonical uptime the persona advertises. Boot slides so this stays constant.
UPTIME = timedelta(days=42, hours=3, minutes=17)
NCPU = 4                      # must match persona nproc/lscpu/cpuinfo
LOAD = "0.38, 0.42, 0.45"     # must match honeyfs/proc/loadavg
KERNEL = "5.15.0-94-generic"
ADMIN_USER = "ubuntu"

# Interactive admin sessions, newest first. Each: (login offset before now,
# session length or None for "still logged in", tty, source IP). All offsets
# are < UPTIME so every session falls after boot.
SESSIONS = [
    (timedelta(hours=6, minutes=47), None, "pts/0", "10.0.0.8"),
    (timedelta(days=1, hours=8, minutes=26), timedelta(hours=2, minutes=43), "pts/0", "10.0.0.8"),
    (timedelta(days=1, hours=13, minutes=57), timedelta(minutes=43), "pts/1", "10.0.0.12"),
    (timedelta(days=2, hours=8, minutes=55), timedelta(hours=1, minutes=48), "pts/0", "10.0.0.8"),
    (timedelta(days=3, hours=20, minutes=1), timedelta(hours=1, minutes=26), "pts/0", "10.0.0.8"),
    (timedelta(days=4, hours=22, minutes=43), timedelta(hours=1, minutes=23), "pts/0", "10.0.0.8"),
]


def _hm(delta: timedelta) -> str:
    """H:MM for a duration under a day (last's parenthesised session length)."""
    total = int(delta.total_seconds())
    return f"{total // 3600:02d}:{total % 3600 // 60:02d}"


def _uptime_hm() -> str:
    """The 'H:MM' tail of the uptime string (hours:minutes past the day count)."""
    rem = UPTIME - timedelta(days=UPTIME.days)
    return f"{rem.seconds // 3600:2d}:{rem.seconds % 3600 // 60:02d}"


def build(now: datetime) -> dict[str, str]:
    boot = now - UPTIME
    days = UPTIME.days
    uptime_tail = _uptime_hm()
    uptime_line = (
        f" {now:%H:%M:%S} up {days} days, {uptime_tail},  1 user,"
        f"  load average: {LOAD}"
    )

    # Newest session drives who/w (the "still logged in" admin).
    cur_login = now - SESSIONS[0][0]

    # --- uptime ---
    uptime_txt = uptime_line + "\n"

    # --- w ---
    w_txt = (
        uptime_line + "\n"
        "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
        f"{ADMIN_USER:<8} {SESSIONS[0][2]:<8} {SESSIONS[0][3]:<16} "
        f"{cur_login:%H:%M}    0.00s  0.04s  0.00s w\n"
    )

    # --- who ---
    who_txt = (
        f"{ADMIN_USER:<8} {SESSIONS[0][2]:<12} {cur_login:%Y-%m-%d %H:%M} "
        f"({SESSIONS[0][3]})\n"
    )

    # --- last ---
    last_lines = []
    for offset, length, tty, ip in SESSIONS:
        login = now - offset
        when = f"{login:%a %b %e %H:%M}"
        if length is None:
            status = "still logged in"
        else:
            logout = login + length
            status = f"- {logout:%H:%M}  ({_hm(length)})"
        last_lines.append(f"{ADMIN_USER:<8} {tty:<12} {ip:<16} {when}   {status}")
    reboot_when = f"{boot:%a %b %e %H:%M}"
    last_lines.append(
        f"{'reboot':<8} {'system boot':<12} {KERNEL[:16]:<16} {reboot_when}   still running"
    )
    last_txt = "\n".join(last_lines) + f"\n\nwtmp begins {boot:%a %b %e %H:%M:%S %Y}\n"

    # --- /proc/uptime ---
    # First field = seconds since boot (must equal the uptime shown). Second =
    # cumulative idle across all CPUs; ~96% idle reads as a calm prod box and
    # keeps the idle/load story consistent (no phantom busy cores).
    up_secs = UPTIME.total_seconds()
    idle_secs = up_secs * NCPU * 0.96
    proc_uptime_txt = f"{up_secs:.2f} {idle_secs:.2f}\n"

    # --- /etc/motd ---
    # The Ubuntu login banner. "System information as of <now>" tracks the live
    # clock; the embedded load/uptime reuse the persona constants so the banner
    # agrees with uptime/w/last (load's first field, the "42 days" uptime). The
    # "Last login" line is the newest COMPLETED admin session, i.e. the one
    # before the current still-logged-in one (SESSIONS[1]), which is what a real
    # motd shows the operator on this login.
    load1 = LOAD.split(",")[0].strip()
    prev_login = now - SESSIONS[1][0]
    motd_txt = (
        f"\n"
        f"  System information as of {now:%a %b %e %H:%M:%S} UTC {now:%Y}\n"
        f"\n"
        f"  System load:    {load1}                Processes:           287\n"
        f"  Usage of /:     61.2% of 96.73GB    Users logged in:     0\n"
        f"  Memory usage:   22%                 IPv4 address for ens3: 10.0.0.14\n"
        f"  Swap usage:     0%                  Uptime:              {days} days\n"
        f"\n"
        f"  23 updates can be applied immediately.\n"
        f"  To see these additional updates run: apt list --upgradable\n"
        f"\n"
        f"Last login: {prev_login:%a %b %e %H:%M:%S %Y} from {SESSIONS[1][3]}\n"
    )

    return {
        "share/cowrie/txtcmds/usr/bin/uptime": uptime_txt,
        "share/cowrie/txtcmds/usr/bin/w": w_txt,
        "share/cowrie/txtcmds/usr/bin/who": who_txt,
        "share/cowrie/txtcmds/usr/bin/last": last_txt,
        "honeyfs/proc/uptime": proc_uptime_txt,
        "honeyfs/etc/motd": motd_txt,
    }


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: gen-time-persona.py COWRIE_HOME", file=sys.stderr)
        return 2
    cowrie_home = Path(sys.argv[1])
    if not cowrie_home.is_dir():
        print(f"  [FAIL] COWRIE_HOME not a directory: {cowrie_home}", file=sys.stderr)
        return 1
    files = build(datetime.now())
    written = 0
    for rel, text in files.items():
        dst = cowrie_home / rel
        if not dst.parent.is_dir():
            # Only write where the persona already placed the tree; a missing
            # parent means that command/proc file was never deployed here.
            continue
        dst.write_text(text)
        written += 1
    print(f"  [ok] time-persona: refreshed {written}/{len(files)} files against live clock")
    return 0


if __name__ == "__main__":
    sys.exit(main())
