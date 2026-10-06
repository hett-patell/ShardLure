#!/usr/bin/env python3
"""Patch cowrie/commands/free.py: procps free from the fake /proc/meminfo.

WHY (payload-yield Phase B Task 6; factsheet-phaseB 3 #11, 5 #6): v3.1.1's
free opens the HOST's real /proc/meminfo, so `free` on the honeypot discloses
the Cowrie machine's own memory: arm's 24 GB behind a persona whose
/proc/meminfo, lscpu and motd all say an 8 GB EC2 guest. That is both a host
information leak and an immediate honeypot tell, and the probe is on the
prod list verbatim (`free -m | grep Mem | awk '{print $2 ,$3, ...}'`, 36
sessions in 30 days). Its arithmetic was not procps' either: it divided by
1000 and left SReclaimable out of buff/cache.

The patch replaces the module body (imports to the end of Command_free) with
a port of procps-ng 3.3.17 (Ubuntu 22.04) free.c and proc/sysinfo.c meminfo():
  - the input is self.fs.file_contents("/proc/meminfo"), the per-connection
    fake filesystem (honeyfs). The host file is never opened; a missing node
    gives procps' "Error: /proc must be mounted" and exit 102;
  - used = total - free - buffers - (Cached + SReclaimable), procps' rule;
  - -b -k -m -g --kilo --mega --giga --tera --peta --tebi --pebi, -h, --si,
    -l, -t, -w, -s N, -c N, --help, -V, with getopt_long's abbreviations and
    glibc's error wording, exit 1 on a usage error;
  - scale_size()'s quirks kept: -m truncates (8039340 kB -> 7850) and -h
    integer-divides first (528 kB -> "0.0Ki"). Checked against the real
    binary on the persona meminfo for every option above and 23 sizes.
`free -s N` repeats on the reactor until Ctrl-C, as the real one does.
Shadowed txtcmds/usr/bin/free is regenerated from procps for the same file.
"""

import sys
from pathlib import Path

# v3.1.1's free.py from its imports to its first registration.
OLD = r'''import getopt
from math import floor

from cowrie.shell.command import HoneyPotCommand

commands = {}

FREE_OUTPUT = """              total        used        free      shared  buff/cache   available
Mem:{MemTotal:>15}{calc_total_used:>12}{MemFree:>12}{Shmem:>12}{calc_total_buffers_and_cache:>12}{MemAvailable:>12}
Swap:{SwapTotal:>14}{calc_swap_used:>12}{SwapFree:>12}
"""


class Command_free(HoneyPotCommand):
    """
    free
    """

    def call(self) -> None:
        # Parse options or display no files
        try:
            opts, _args = getopt.getopt(self.args, "mh")
        except getopt.GetoptError:
            self.do_free()
            return

        # Parse options
        for o, _a in opts:
            if o in ("-h"):
                self.do_free(fmt="human")
                return
            elif o in ("-m"):
                self.do_free(fmt="megabytes")
                return
        self.do_free()

    def do_free(self, fmt: str = "kilobytes") -> None:
        """
        print free statistics
        """

        # Get real host memstats and add the calculated fields
        raw_mem_stats = self.get_free_stats()

        if raw_mem_stats == {}:
            return

        raw_mem_stats["calc_total_buffers_and_cache"] = (
            raw_mem_stats["Buffers"] + raw_mem_stats["Cached"]
        )
        raw_mem_stats["calc_total_used"] = raw_mem_stats["MemTotal"] - (
            raw_mem_stats["MemFree"] + raw_mem_stats["calc_total_buffers_and_cache"]
        )
        raw_mem_stats["calc_swap_used"] = (
            raw_mem_stats["SwapTotal"] - raw_mem_stats["SwapFree"]
        )

        if fmt == "megabytes":
            # Transform KB to MB
            for key, value in raw_mem_stats.items():
                raw_mem_stats[key] = int(value / 1000)

        if fmt == "human":
            magnitude = ["B", "M", "G", "T", "Z"]
            human_mem_stats = {}
            for key, value in raw_mem_stats.items():
                current_magnitude = 0

                # Keep dividing until we get a sane magnitude
                while value >= 1000 and current_magnitude < len(magnitude):
                    value = floor(float(value / 1000))
                    current_magnitude += 1

                # Format to string and append value with new magnitude
                human_mem_stats[key] = str(f"{value:g}{magnitude[current_magnitude]}")

            self.write(FREE_OUTPUT.format(**human_mem_stats))
        else:
            self.write(FREE_OUTPUT.format(**raw_mem_stats))

    def get_free_stats(self) -> dict[str, int]:
        """
        Get the free stats from /proc
        """
        needed_keys = [
            "Buffers",
            "Cached",
            "MemTotal",
            "MemFree",
            "SwapTotal",
            "SwapFree",
            "Shmem",
            "MemAvailable",
        ]
        mem_info_map: dict[str, int] = {}
        try:
            with open("/proc/meminfo") as proc_file:
                for line in proc_file:
                    tokens = line.split(":")

                    # Later we are going to do some math on those numbers, better not include uneeded keys for performance
                    if tokens[0] in needed_keys:
                        mem_info_map[tokens[0]] = int(tokens[1].lstrip().split(" ")[0])
        except Exception:
            pass

        # Got a map with all tokens from /proc/meminfo and sizes in KBs
        return mem_info_map


commands["/usr/bin/free"] = Command_free
'''

NEW = r'''import getopt
import re
import struct

from twisted.internet import reactor

from cowrie.shell.command import HoneyPotCommand

commands = {}

# ShardLure persona (free-meminfo.py): procps-ng 3.3.17's free, the one
# Ubuntu 22.04 ships, computed from the FAKE filesystem's /proc/meminfo. Stock
# Cowrie opened the host's real /proc/meminfo, so every `free` disclosed the
# Cowrie machine's own memory (arm's 24 GB behind a persona claiming 8 GB)
# and used its own arithmetic (/1000, no SReclaimable in buff/cache).
# Ported from procps v3.3.17 free.c and proc/sysinfo.c meminfo(); the
# formatting quirks are procps', on purpose (`free -h` shows 528 kB as
# "0.0Ki", because scale_size integer-divides by 1024 first).

FREE_USAGE = """
Usage:
 free [options]

Options:
 -b, --bytes         show output in bytes
     --kilo          show output in kilobytes
     --mega          show output in megabytes
     --giga          show output in gigabytes
     --tera          show output in terabytes
     --peta          show output in petabytes
 -k, --kibi          show output in kibibytes
 -m, --mebi          show output in mebibytes
 -g, --gibi          show output in gibibytes
     --tebi          show output in tebibytes
     --pebi          show output in pebibytes
 -h, --human         show human-readable output
     --si            use powers of 1000 not 1024
 -l, --lohi          show detailed low and high memory statistics
 -t, --total         show total for RAM + swap
 -s N, --seconds N   repeat printing every N seconds
 -c N, --count N     repeat printing N times, then exit
 -w, --wide          wide output

     --help     display this help and exit
 -V, --version  output version information and exit

For more details see free(1).
"""

FREE_BAD_OPEN = (
    "Error: /proc must be mounted\n"
    "  To mount /proc at boot you need an /etc/fstab line like:\n"
    "      proc   /proc   proc    defaults\n"
    '  In the meantime, run "mount proc /proc -t proc"\n'
)

# getopt_long's table, in free.c's order (glibc lists ambiguous matches so).
FREE_LONGOPTS = (
    "bytes", "kilo", "mega", "giga", "tera", "peta", "kibi", "mebi", "gibi",
    "tebi", "pebi", "human", "si", "lohi", "total", "seconds=", "count=",
    "wide", "help", "version",
)

# option -> (exponent, SI); free.c's check_unit_set allows only one.
FREE_UNITS = {
    "-b": (1, False), "--bytes": (1, False),
    "-k": (2, False), "--kibi": (2, False),
    "-m": (3, False), "--mebi": (3, False),
    "-g": (4, False), "--gibi": (4, False),
    "--tebi": (5, False), "--pebi": (6, False),
    "--kilo": (2, True), "--mega": (3, True), "--giga": (4, True),
    "--tera": (5, True), "--peta": (6, True),
}

FREE_MEMINFO_KEYS = (
    "MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "SReclaimable",
    "Shmem", "SwapTotal", "SwapFree", "LowTotal", "LowFree", "HighTotal", "HighFree",
)


def _f32(value: float) -> float:
    """Round to a C float, as free.c's `(float)` casts and float base do."""
    return struct.unpack("f", struct.pack("f", value))[0]


def free_scale(size: int, exponent: int, si: bool, human: bool) -> str:
    """procps 3.3.17 scale_size(); `size` is in kB."""
    base = 1000.0 if si else 1024.0
    if exponent == 0 and not human:
        return str(size)
    if not human:
        if exponent == 1:
            return str(size * 1024)
        return str(int((size * 1024.0) / base ** (exponent - 1)))
    text = ""
    for i, unit in enumerate("BKMGTP", start=1):
        if i == 1:
            text = f"{size * 1024}{unit}"
            if len(text) <= 4:
                return text
            continue
        # (size / 1024) * base / power(base, i - 2): an unsigned long
        # division, then float * float, then a double division.
        value = _f32(_f32(size // 1024) * base) / base ** (i - 2)
        suffix, width = (unit, 4) if si else (unit + "i", 5)
        text = f"{_f32(value):.1f}{suffix}"
        if len(text) <= width:
            return text
        text = f"{int(value)}{suffix}"
        if len(text) <= width:
            return text
    return text


def free_meminfo(text: str) -> dict[str, int]:
    """proc/sysinfo.c meminfo(): the fields free prints, in kB."""
    raw = dict.fromkeys(FREE_MEMINFO_KEYS, 0)
    for line in text.splitlines():
        key, sep, rest = line.partition(":")
        if not sep or key not in raw:
            continue
        m = re.match(r"\s*(\d+)", rest)
        if m:
            raw[key] = int(m.group(1))
    mem = {
        "total": raw["MemTotal"],
        "free": raw["MemFree"],
        "shared": raw["Shmem"],
        "buffers": raw["Buffers"],
        "cached": raw["Cached"] + raw["SReclaimable"],
        "available": raw["MemAvailable"],
        "swap_total": raw["SwapTotal"],
        "swap_free": raw["SwapFree"],
        "low_total": raw["LowTotal"],
        "low_free": raw["LowFree"],
        "high_total": raw["HighTotal"],
        "high_free": raw["HighFree"],
    }
    if not mem["low_total"]:
        # low == main except with large-memory support
        mem["low_total"], mem["low_free"] = mem["total"], mem["free"]
    mem["swap_used"] = mem["swap_total"] - mem["swap_free"]
    if mem["available"] > mem["total"]:
        mem["available"] = mem["free"]
    used = mem["total"] - mem["free"] - mem["cached"] - mem["buffers"]
    if used < 0:
        used = mem["total"] - mem["free"]
    mem["used"] = used
    if not mem["available"]:
        # procps estimates from /proc/sys/vm/min_free_kbytes here; the
        # persona's meminfo always carries MemAvailable.
        mem["available"] = mem["free"]
    return mem


class Command_free(HoneyPotCommand):
    """
    free (procps-ng 3.3.17)
    """

    scheduled = None

    def start(self) -> None:
        self.exponent = 0
        self.si = self.human = self.lohi = self.total = self.wide = False
        self.repeat = False
        self.count: int | None = None
        self.interval = 1.0
        try:
            opts, operands = getopt.gnu_getopt(self.args, "bkmghltc:ws:V", list(FREE_LONGOPTS))
        except getopt.GetoptError as err:
            self.errorWrite(f"free: {self.getopt_message(err)}\n")
            self.usage_error()
            return
        unit_set = False
        for opt, arg in opts:
            if opt in FREE_UNITS:
                if unit_set:
                    self.fail("Multiple unit options doesn't make sense.")
                    return
                unit_set = True
                self.exponent, si = FREE_UNITS[opt]
                self.si = self.si or si
            elif opt in ("-h", "--human"):
                self.human = True
            elif opt == "--si":
                self.si = True
            elif opt in ("-l", "--lohi"):
                self.lohi = True
            elif opt in ("-t", "--total"):
                self.total = True
            elif opt in ("-w", "--wide"):
                self.wide = True
            elif opt in ("-s", "--seconds"):
                self.repeat = True
                if not re.fullmatch(r"\s*[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?", arg):
                    self.fail(f"seconds argument failed: '{arg}': Invalid argument")
                    return
                if 1000000 * float(arg) < 1:
                    self.fail(f"seconds argument `{arg}' is not positive number")
                    return
                self.interval = float(arg)
            elif opt in ("-c", "--count"):
                self.repeat = True
                if not re.fullmatch(r"\s*[+-]?\d+", arg):
                    self.fail(f"failed to parse count argument: '{arg}'")
                    return
                if int(arg) < 1:
                    self.fail(
                        f"failed to parse count argument: '{arg}': Numerical result out of range"
                    )
                    return
                self.count = int(arg)
            elif opt == "--help":
                self.write(FREE_USAGE)
                self.exit(0)
                return
            elif opt in ("-V", "--version"):
                self.write("free from procps-ng 3.3.17\n")
                self.exit(0)
                return
        if operands:
            self.usage_error()
            return
        self.show()

    @staticmethod
    def getopt_message(err: getopt.GetoptError) -> str:
        """glibc getopt_long's wording for Python getopt's errors."""
        msg, opt = err.msg, err.opt
        if msg.startswith("option --"):
            if "not a unique prefix" in msg:
                matches = " ".join(
                    f"'--{name.rstrip('=')}'" for name in FREE_LONGOPTS if name.startswith(opt)
                )
                return f"option '--{opt}' is ambiguous; possibilities: {matches}"
            if "requires argument" in msg:
                return f"option '--{opt}' requires an argument"
            if "must not have an argument" in msg:
                return f"option '--{opt}' doesn't allow an argument"
            return f"unrecognized option '--{opt}'"
        if "requires argument" in msg:
            return f"option requires an argument -- '{opt}'"
        return f"invalid option -- '{opt}'"

    def fail(self, message: str) -> None:
        self.errorWrite(f"free: {message}\n")
        self.exit(1)

    def usage_error(self) -> None:
        self.errorWrite(FREE_USAGE)
        self.exit(1)

    def show(self) -> None:
        self.scheduled = None
        if self.exited or self not in (getattr(self.protocol, "cmdstack", None) or ()):
            # The session ended under a repeating `free -s`; connectionLost
            # empties the cmdstack. Stop instead of rescheduling forever.
            return
        try:
            # The fake filesystem only: never the Cowrie host's /proc.
            text = self.fs.file_contents("/proc/meminfo").decode("latin-1")
        except Exception:
            self.errorWrite(FREE_BAD_OPEN)
            self.exit(102)
            return
        self.write(self.render(free_meminfo(text)))
        if self.count is not None:
            self.count -= 1
            if self.count < 1:
                self.exit(0)
                return
        if not self.repeat:
            self.exit(0)
            return
        self.write("\n")
        # procps accepts any positive interval; the honeypot floors it at
        # 0.1 s so `free -s 0.000001` cannot spin the shared reactor or flood
        # a transport the client never reads. Not observable as a tell.
        self.scheduled = reactor.callLater(max(self.interval, 0.1), self.show)

    def render(self, mem: dict[str, int]) -> str:
        def col(size: int) -> str:
            return free_scale(size, self.exponent, self.si, self.human)

        def row(label: str, *sizes: int) -> str:
            cells = [f"{col(sizes[0]):>11}"] + [f" {col(s):>11}" for s in sizes[1:]]
            return f"{label:<9}" + "".join(cells) + "\n"

        if self.wide:
            out = ("               total        used        free      shared"
                   "     buffers       cache   available\n")
            out += row("Mem:", mem["total"], mem["used"], mem["free"], mem["shared"],
                       mem["buffers"], mem["cached"], mem["available"])
        else:
            out = ("               total        used        free      shared"
                   "  buff/cache   available\n")
            out += row("Mem:", mem["total"], mem["used"], mem["free"], mem["shared"],
                       mem["buffers"] + mem["cached"], mem["available"])
        if self.lohi:
            out += row("Low:", mem["low_total"], mem["low_total"] - mem["low_free"],
                       mem["low_free"])
            out += row("High:", mem["high_total"], mem["high_total"] - mem["high_free"],
                       mem["high_free"])
        out += row("Swap:", mem["swap_total"], mem["swap_used"], mem["swap_free"])
        if self.total:
            out += row("Total:", mem["total"] + mem["swap_total"],
                       mem["used"] + mem["swap_used"], mem["free"] + mem["swap_free"])
        return out

    def handle_CTRL_C(self) -> None:
        if self.scheduled is not None and self.scheduled.active():
            self.scheduled.cancel()
        self.scheduled = None
        super().handle_CTRL_C()


commands["/usr/bin/free"] = Command_free
'''


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/commands/free.py"
    content = path.read_text(encoding="utf-8")
    old, new = content.count(OLD), content.count(NEW)
    if (old, new) == (0, 1):
        print(f"  [skip] {path}: already patched")
        return 0
    if (old, new) != (1, 0):
        print(
            f"  [FAIL] {path}: target is neither pristine nor fully patched "
            f"(old/new counts {(old, new)}) - upstream free changed",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    path.write_text(content.replace(OLD, NEW, 1), encoding="utf-8")
    print(f"  [ok] {path}: patched (procps free from the fake /proc/meminfo)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
