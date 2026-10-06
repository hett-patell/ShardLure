#!/usr/bin/env python3
"""Patch cowrie/commands/lspci.py: answer with the persona's Xen device list.

WHY (payload-yield Phase B Task 6; factsheet-phaseB 2 GPU, 5 #3): v3.1.1
registers `lspci` and `/usr/bin/lspci` as a Python command, and the command
registry is consulted before txtcmds (shell/protocol.py getCommand), so the
persona's txtcmds/usr/bin/lspci never answers. Stock Cowrie prints a desktop
board instead: AMD RS880 chipset, a GeForce GTX 650, Atheros Wi-Fi. That
contradicts every other persona fact (an AWS-style Xen guest with a Xeon
E5-2676 v3, `hypervisor` in /proc/cpuinfo flags), and the SHELL_BEHAVIOR
profiler (1,452 sessions in 30 days) reads its GPU field from exactly this:
`lspci | grep -i vga`. A real guest of that shape answers
`00:02.0 VGA compatible controller: Cirrus Logic GD 5446`.

The list is the txtcmd's, byte for byte (test_release_contracts pins the two
together), and every option prints it, as stock Cowrie does.

commands/busybox.py, second block: the profiler runs `busybox lspci | grep -i
vga` too, and Cowrie's busybox hands any registered command to it, so the
persona's GPU line came out twice. BusyBox 1.20.2, the version Cowrie's
busybox claims, has no lspci applet (it is not in that banner's "Currently
defined functions"), so `busybox lspci` now answers as busybox does for a
missing applet: "lspci: applet not found" on stderr, exit 1 (stock Cowrie's
own not-found branch, left alone for other names, writes stdout with exit 0).
Only lspci: refusing every unlisted applet would also refuse
`busybox curl`, and a download Cowrie answers is a payload ShardLure captures.
"""

import sys
from pathlib import Path

# v3.1.1's lspci_out(), with the comment above it.
OLD = r'''# output taken from https://opensource.com/article/21/9/lspci-linux-hardware
# avoiding any mention of VMware/virtual etc to ensure attempts to look for vm not found
def lspci_out():
    return """00:00.0 Host bridge: Advanced Micro Devices, Inc. [AMD] RS880 Host Bridge
00:02.0 PCI bridge: Advanced Micro Devices, Inc. [AMD] RS780 PCI to PCI bridge (ext gfx port 0)
00:04.0 PCI bridge: Advanced Micro Devices, Inc. [AMD] RS780/RS880 PCI to PCI bridge (PCIE port 0)
00:05.0 PCI bridge: Advanced Micro Devices, Inc. [AMD] RS780/RS880 PCI to PCI bridge (PCIE port 1)
00:11.0 SATA controller: Advanced Micro Devices, Inc. [AMD/ATI] SB7x0/SB8x0/SB9x0 SATA Controller [AHCI mode]
00:12.0 USB controller: Advanced Micro Devices, Inc. [AMD/ATI] SB7x0/SB8x0/SB9x0 USB OHCI0 Controller
00:12.1 USB controller: Advanced Micro Devices, Inc. [AMD/ATI] SB7x0 USB OHCI1 Controller
00:12.2 USB controller: Advanced Micro Devices, Inc. [AMD/ATI] SB7x0/SB8x0/SB9x0 USB EHCI Controller
00:13.0 USB controller: Advanced Micro Devices, Inc. [AMD/ATI] SB7x0/SB8x0/SB9x0 USB OHCI0 Controller
00:13.1 USB controller: Advanced Micro Devices, Inc. [AMD/ATI] SB7x0 USB OHCI1 Controller
00:13.2 USB controller: Advanced Micro Devices, Inc. [AMD/ATI] SB7x0/SB8x0/SB9x0 USB EHCI Controller
00:14.0 SMBus: Advanced Micro Devices, Inc. [AMD/ATI] SBx00 SMBus Controller (rev 3c)
00:14.1 IDE interface: Advanced Micro Devices, Inc. [AMD/ATI] SB7x0/SB8x0/SB9x0 IDE Controller
00:14.3 ISA bridge: Advanced Micro Devices, Inc. [AMD/ATI] SB7x0/SB8x0/SB9x0 LPC host controller
00:14.4 PCI bridge: Advanced Micro Devices, Inc. [AMD/ATI] SBx00 PCI to PCI Bridge
00:14.5 USB controller: Advanced Micro Devices, Inc. [AMD/ATI] SB7x0/SB8x0/SB9x0 USB OHCI2 Controller
00:18.0 Host bridge: Advanced Micro Devices, Inc. [AMD] Family 10h Processor HyperTransport Configuration
00:18.1 Host bridge: Advanced Micro Devices, Inc. [AMD] Family 10h Processor Address Map
00:18.2 Host bridge: Advanced Micro Devices, Inc. [AMD] Family 10h Processor DRAM Controller
00:18.3 Host bridge: Advanced Micro Devices, Inc. [AMD] Family 10h Processor Miscellaneous Control
00:18.4 Host bridge: Advanced Micro Devices, Inc. [AMD] Family 10h Processor Link Control
01:00.0 VGA compatible controller: NVIDIA Corporation GK107 [GeForce GTX 650] (rev a1)
01:00.1 Audio device: NVIDIA Corporation GK107 HDMI Audio Controller (rev a1)
02:00.0 Network controller: Qualcomm Atheros AR9287 Wireless Network Adapter (PCI-Express) (rev 01)\n"""
'''

NEW = r'''# ShardLure persona (lspci-persona.py): the persona's Xen HVM guest, the
# same list as install/persona/txtcmds/usr/bin/lspci, which this registered
# command shadows.
def lspci_out():
    return """00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)
00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]
00:01.1 IDE interface: Intel Corporation 82371SB PIIX3 IDE [Natoma/Triton II]
00:01.3 Bridge: Intel Corporation 82371AB/EB/MB PIIX4 ACPI (rev 01)
00:02.0 VGA compatible controller: Cirrus Logic GD 5446
00:03.0 Unassigned class [ff80]: XenSource, Inc. Xen Platform Device (rev 01)\n"""
'''


# commands/busybox.py: lspci is not an applet of the BusyBox Cowrie claims.
OLD_BUSYBOX = r'''            cmd, self.environ.get("PATH", "").split(":"), self.cwd
        )
        if not cmdclass:
            self.write(f"{cmd}: applet not found\n")
'''

NEW_BUSYBOX = r'''            cmd, self.environ.get("PATH", "").split(":"), self.cwd
        )
        # ShardLure persona (lspci-persona.py): BusyBox 1.20.2 has no lspci
        # applet; without this, `busybox lspci` repeated the persona's list.
        # Real busybox reports a missing applet on stderr and fails
        # (xfunc_die, exit 1), so `busybox lspci 2>/dev/null` prints nothing.
        if cmd == "lspci":
            self.errorWrite(f"{cmd}: applet not found\n")
            self.exit(1)
            return
        if not cmdclass:
            self.write(f"{cmd}: applet not found\n")
'''

TARGETS = (
    ("src/cowrie/commands/lspci.py", OLD, NEW),
    ("src/cowrie/commands/busybox.py", OLD_BUSYBOX, NEW_BUSYBOX),
)


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    home = Path(args[0])
    # Both files are checked before either is written.
    contents = {rel: (home / rel).read_text(encoding="utf-8") for rel, _, _ in TARGETS}
    counts = [(contents[rel].count(old), contents[rel].count(new)) for rel, old, new in TARGETS]
    if all(c == (0, 1) for c in counts):
        print(f"  [skip] {home}: lspci persona already patched")
        return 0
    if not all(c == (1, 0) for c in counts):
        print(
            f"  [FAIL] {home}: lspci.py/busybox.py neither pristine nor fully patched "
            f"(old/new counts {counts}) - upstream changed",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {home}: lspci.py, busybox.py compatible")
        return 0
    for rel, old, new in TARGETS:
        (home / rel).write_text(contents[rel].replace(old, new, 1), encoding="utf-8")
    print(f"  [ok] {home}: patched lspci.py, busybox.py (persona Xen device list)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
