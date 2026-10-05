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

v3.1.1 port (payload-yield Phase B Task 3). v3.1.1 folds two refusals into one
branch (shell/script.py): a file past max_input_size() and a binary both get
binary_message and exit 126. Only the binary half is faked: an oversized TEXT
file is not something a matching-arch box would "run", so it keeps the real
error. Three tightenings over the pin-era patch:
  - direct execution only (`./x`, `/bin/x`: protocol.py's Command_scriptcmd).
    `sh x` / `bash x` on an ELF is "cannot execute binary file" on a real box
    too, so faking success there would be a new tell;
  - the backing file must sit directly in download_path (or
    download_path_uniq, where scp.py stores uploads), compared as resolved
    directories, not a string prefix that `downloads-old/` would also match;
  - the result is plain old/new text, so --check and reapply follow the same
    pristine / patched / partial contract as every other persona patch.
Note that Cowrie v3.1.1 gives every session channel a fresh fake filesystem,
so an upload on one channel and a run on the next (the observed bot pattern)
never reaches this branch; scripts/behaviour's scp-upload-run case uploads
and runs on one channel.
"""
import sys
from pathlib import Path


OLD = """\
    if len(contents) > max_input_size() or is_executable_binary(contents):
        command.errorWrite(binary_message)
        command.exit_code = 126
        return
"""

NEW = """\
    if len(contents) > max_input_size() or is_executable_binary(contents):
        # ShardLure stealth (install/persona/patches/exec-emulation.py): a
        # binary the attacker uploaded or downloaded this session, run
        # directly, would just run on a matching-arch box, so answer the
        # plausible "it ran" (exit 0, no output) instead of the Exec-format
        # tell. Nothing is executed: the payload was captured at upload. An
        # oversized text file, `sh x`, and any other binary keep the error.
        if (
            type(command).__name__ == "Command_scriptcmd"
            and is_executable_binary(contents)
            and _shardlure_attacker_binary(command, path)
        ):
            command.exit_code = 0
            return
        command.errorWrite(binary_message)
        command.exit_code = 126
        return
"""

# The helper goes between is_executable_binary and run_script_file; its
# imports are lazy so module load gains no new dependencies.
OLD_DEF = """\
    except UnicodeDecodeError:
        return True
    return False


def run_script_file(
"""

NEW_DEF = """\
    except UnicodeDecodeError:
        return True
    return False


def _shardlure_attacker_binary(command, path: str) -> bool:
    \"\"\"True if `path` is a fake-FS file backed by a real file directly in
    Cowrie's download_path or download_path_uniq: something the attacker
    uploaded or downloaded, not a honeyfs system binary. See exec-emulation.py.
    \"\"\"
    try:
        import os

        from cowrie.core.config import CowrieConfig
        from cowrie.shell.fs import A_REALFILE

        node = command.fs.getfile(path)
        if not node or not node[A_REALFILE]:
            return False
        roots = set()
        for key in ("download_path", "download_path_uniq"):
            value = CowrieConfig.get("honeypot", key, fallback="")
            if value:
                roots.add(os.path.realpath(value))
        real_dir = os.path.dirname(os.path.realpath(str(node[A_REALFILE])))
        return real_dir in roots
    except Exception:
        # Any uncertainty -> not an attacker binary -> the real error. Fail
        # toward the truthful bash message, never toward a spurious success.
        return False


def run_script_file(
"""

BLOCKS = ((OLD, NEW), (OLD_DEF, NEW_DEF))


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/shell/script.py"
    content = path.read_text(encoding="utf-8")
    counts = [(content.count(old), content.count(new)) for old, new in BLOCKS]
    if all(c == (0, 1) for c in counts):
        print(f"  [skip] {path}: already patched")
        return 0
    if not all(c == (1, 0) for c in counts):
        print(
            f"  [FAIL] {path}: target is neither pristine nor fully patched "
            f"(old/new counts {counts}) — upstream script.py changed",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    for old, new in BLOCKS:
        content = content.replace(old, new, 1)
    path.write_text(content, encoding="utf-8")
    print(f"  [ok] {path}: patched (scoped attacker-binary fake-success)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
