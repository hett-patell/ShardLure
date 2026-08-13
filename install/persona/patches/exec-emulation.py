#!/usr/bin/env python3
"""Patch cowrie/shell/script.py: plausibly "run" an attacker's own binary.

WHY (measured on the arm deployment): a bot family uploads a real binary and
runs it as a liveness/execution test:
    scp -t /bin/<random>        # upload the ELF (captured by ShardLure here)
    /bin/<random>               # run it
    rm -f /bin/<random>         # clean up, or give up
Cowrie reaches run_script_file for the run, sees an ELF via
is_executable_binary(), and writes "cannot execute binary file: Exec format
error". On a real matching-arch box the binary would simply run — so the error
is the honeypot tell, and the bot disengages (13 sessions observed bailing here).

Fix (scoped, and NEVER real execution): when the binary being run is an
ATTACKER-SUPPLIED file — its fake-FS node has A_REALFILE pointing inside
Cowrie's download_path (where scp/wget/curl/tftp deposit captured uploads) — a
canned exit 0 with no output is returned instead of the error. That is the
plausible outcome for a dropper compiled for this arch, and the payload has
already been captured at the upload/download step, so nothing is gained by
actually executing it (and everything is risked). No process is ever spawned.

Scope is deliberately "attacker file under download_path", NOT "has +x":
the observed probe runs the binary immediately after scp without chmod, and
Cowrie's scp mode modelling is unreliable. Any binary WITHOUT download_path
provenance (a honeyfs system binary, contents-backed file) keeps the real bash
"Exec format error", so we do not blanket-fake every binary — which would be its
own tell.
"""
import sys
from pathlib import Path

args = sys.argv[1:]
if (
    len(args) not in (1, 2)
    or not args[0]
    or args[0] == "--check"
    or (len(args) == 2 and args[1] != "--check")
):
    print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
    sys.exit(2)
check_only = len(args) == 2
cowrie_home = Path(args[0])
path = str(cowrie_home / "src/cowrie/shell/script.py")
with open(path) as f:
    content = f.read()

OLD = '''    if is_executable_binary(contents):
        command.errorWrite(binary_message)
        return'''

NEW = '''    if is_executable_binary(contents):
        # ShardLure stealth: if this is the ATTACKER'S OWN uploaded/downloaded
        # binary (fake-FS node backed by a real file under download_path), a
        # matching-arch dropper would just run on a real box, so emit the
        # plausible "it ran" (exit 0, no output) instead of the Exec-format
        # tell. The payload was already captured at upload/download; nothing is
        # executed here. Any other binary keeps the real error.
        if _is_attacker_binary(command, path):
            command.exit_code = 0
            return
        command.errorWrite(binary_message)
        return'''

HELPER = '''

def _is_attacker_binary(command, path: str) -> bool:
    """True if `path` resolves to a fake-FS file backed by a real file under
    Cowrie's download_path — i.e. something the attacker uploaded/downloaded
    this session, not a honeyfs system binary. See exec-emulation.py."""
    try:
        from cowrie.core.config import CowrieConfig
        from cowrie.shell.fs import A_REALFILE

        node = command.fs.getfile(path)
        if not node or not node[A_REALFILE]:
            return False
        real = str(node[A_REALFILE])
        dl = CowrieConfig.get("honeypot", "download_path", fallback="")
        return bool(dl) and real.startswith(str(dl))
    except Exception:
        # Any uncertainty -> not an attacker binary -> real error path. Fail
        # toward the truthful bash message, never toward a spurious success.
        return False
'''

already = "_is_attacker_binary(command, path)" in content

if already:
    print(f"  [skip] {path}: already patched")
    sys.exit(0)

if content.count(OLD) != 1:
    print(
        f"  [FAIL] {path}: is_executable_binary branch not found exactly once "
        f"(count={content.count(OLD)}) — upstream script.py changed",
        file=sys.stderr,
    )
    sys.exit(1)

if check_only:
    print(f"  [check] {path}: compatible")
    sys.exit(0)

content = content.replace(OLD, NEW, 1)
# Append the helper at module end (after run_script_file); it is imported lazily
# inside so module load stays free of new top-level deps.
content = content.rstrip("\n") + "\n" + HELPER
with open(path, "w") as f:
    f.write(content)
print(f"  [ok] {path}: patched (scoped attacker-binary fake-success)")
