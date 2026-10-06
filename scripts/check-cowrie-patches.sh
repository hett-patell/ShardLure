#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Cowrie v3.1.1 (lightweight tag; `git ls-remote ... refs/tags/v3.1.1`).
EXPECTED_PIN="c17c9b73d6af0972334ea1e90b20d974cb24eeca"
PIN_FILE="$ROOT/install/cowrie.commit"
ORCHESTRATOR="$ROOT/install/persona/apply-patches.py"

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/shardlure-cowrie-patches.XXXXXX")"
trap 'rm -rf -- "$tmp_root"' EXIT

pin="$(PYTHONPATH="$ROOT" python3 - "$PIN_FILE" <<'PY'
import sys
from pathlib import Path

from scripts.shardlure import read_cowrie_pin

print(read_cowrie_pin(Path(sys.argv[1])))
PY
)"
if [[ "$pin" != "$EXPECTED_PIN" ]]; then
  echo "[cowrie-patches] pin mismatch: got $pin, want $EXPECTED_PIN" >&2
  exit 1
fi

cowrie="$tmp_root/cowrie"
drifted="$tmp_root/cowrie-drifted"
args_checkout="$tmp_root/cowrie-args"
partial_passwd="$tmp_root/cowrie-partial-passwd"
partial_builtins="$tmp_root/cowrie-partial-builtins"
partial_exec="$tmp_root/cowrie-partial-exec"
partial_capture="$tmp_root/cowrie-partial-capture"
partial_sharedfs="$tmp_root/cowrie-partial-sharedfs"
partial_scp="$tmp_root/cowrie-partial-scp"
partial_ls="$tmp_root/cowrie-partial-ls"
partial_grep="$tmp_root/cowrie-partial-grep"
partial_lspci="$tmp_root/cowrie-partial-lspci"
partial_free="$tmp_root/cowrie-partial-free"
partial_uname="$tmp_root/cowrie-partial-uname"
partial_last="$tmp_root/cowrie-partial-last"
partial_uptime="$tmp_root/cowrie-partial-uptime"
git init -q "$cowrie"
git -C "$cowrie" remote add origin https://github.com/cowrie/cowrie.git
git -C "$cowrie" fetch -q --depth 1 origin "$EXPECTED_PIN"
git -C "$cowrie" checkout -q --detach "$EXPECTED_PIN"
if [[ "$(git -C "$cowrie" rev-parse HEAD)" != "$EXPECTED_PIN" ]]; then
  echo "[cowrie-patches] fetched checkout is not the tested pin" >&2
  exit 1
fi
cp -a "$cowrie" "$drifted"
cp -a "$cowrie" "$args_checkout"
cp -a "$cowrie" "$partial_passwd"
cp -a "$cowrie" "$partial_builtins"
cp -a "$cowrie" "$partial_exec"
cp -a "$cowrie" "$partial_capture"
cp -a "$cowrie" "$partial_sharedfs"
cp -a "$cowrie" "$partial_scp"
cp -a "$cowrie" "$partial_ls"
cp -a "$cowrie" "$partial_grep"
cp -a "$cowrie" "$partial_lspci"
cp -a "$cowrie" "$partial_free"
cp -a "$cowrie" "$partial_uname"
cp -a "$cowrie" "$partial_last"
cp -a "$cowrie" "$partial_uptime"

# Build exact incomplete states from the patch scripts' literal blocks:
# passwd has the piped-stdin branch without its early return, and builtins
# registers `command` but not `type`, so neither OLD nor NEW is present in
# either; exec has its new branch but not the helper it calls (NEW + OLD_DEF);
# capture has a chmod at the right location but the wrong permissions;
# sharedfs has its session.py half but not its filetransfer.py half; scp
# remembers the -t target but still names the file after the C-record; ls
# has the GNU recent form but keeps the ISO form for old files; grep has the
# new class but still ignores -i; lspci lists the persona with one device
# misnamed and leaves busybox.py pristine; free leaves SReclaimable out of
# buff/cache, as stock Cowrie did; uname has its new flags dict (platform
# preset to True) beside the old flag row and output; last puts a pty caller
# on the admin's own pts/0; uptime has its uptime.py half but not its
# base.py (w) half. The bashparse and honeypot fixtures went
# with the patches upstream made redundant.
python3 - \
  "$ROOT" \
  "$partial_passwd/src/cowrie/commands/base.py" \
  "$partial_builtins/src/cowrie/commands/which.py" \
  "$partial_exec/src/cowrie/shell/script.py" \
  "$partial_capture/src/cowrie/shell/fs.py" \
  "$partial_sharedfs/src/cowrie/shell/session.py" \
  "$partial_scp/src/cowrie/commands/scp.py" \
  "$partial_ls/src/cowrie/commands/ls.py" \
  "$partial_grep/src/cowrie/commands/fs.py" \
  "$partial_lspci/src/cowrie/commands/lspci.py" \
  "$partial_free/src/cowrie/commands/free.py" \
  "$partial_uname/src/cowrie/commands/uname.py" \
  "$partial_last/src/cowrie/commands/last.py" \
  "$partial_uptime/src/cowrie/commands/uptime.py" <<'PY'
import ast
import sys
from pathlib import Path


def string_constants(path: Path) -> dict[str, str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    constants: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                constants[target.id] = node.value.value
    return constants


def replace_once(path: Path, old: str, new: str, label: str) -> str:
    content = path.read_text(encoding="utf-8")
    if content.count(old) != 1 or content.count(new) != 0:
        raise SystemExit(f"cannot create deterministic {label} fixture in {path}")
    content = content.replace(old, new, 1)
    path.write_text(content, encoding="utf-8")
    return content


root = Path(sys.argv[1])
passwd_path = Path(sys.argv[2])
builtins_path = Path(sys.argv[3])
exec_path = Path(sys.argv[4])
capture_path = Path(sys.argv[5])
sharedfs_path = Path(sys.argv[6])
scp_path = Path(sys.argv[7])
ls_path = Path(sys.argv[8])
grep_path = Path(sys.argv[9])
lspci_path = Path(sys.argv[10])
free_path = Path(sys.argv[11])
uname_path = Path(sys.argv[12])
last_path = Path(sys.argv[13])
uptime_path = Path(sys.argv[14])

passwd = string_constants(root / "install/persona/patches/passwd-stdin.py")
early_return = "            return\n"
if passwd["NEW"].count(early_return) != 1:
    raise SystemExit("passwd NEW block does not contain the expected early return")
partial = passwd["NEW"].replace(early_return, "", 1)
content = replace_once(passwd_path, passwd["OLD"], partial, "passwd partial")
if content.count(passwd["OLD"]) != 0 or content.count(passwd["NEW"]) != 0:
    raise SystemExit(f"passwd partial fixture unexpectedly contains a complete block in {passwd_path}")

builtins = string_constants(root / "install/persona/patches/command-type-builtins.py")
type_registration = 'commands["type"] = Command_type\n'
if builtins["NEW"].count(type_registration) != 1:
    raise SystemExit("builtins NEW block does not contain the expected type registration")
partial = builtins["NEW"].replace(type_registration, "", 1)
content = replace_once(builtins_path, builtins["OLD"], partial, "builtins partial")
if content.count(builtins["OLD"]) != 0 or content.count(builtins["NEW"]) != 0:
    raise SystemExit(f"builtins partial fixture unexpectedly contains a complete block in {builtins_path}")

exec_emulation = string_constants(root / "install/persona/patches/exec-emulation.py")
content = replace_once(exec_path, exec_emulation["OLD"], exec_emulation["NEW"], "exec partial")
expected = {"OLD": 0, "NEW": 1, "OLD_DEF": 1, "NEW_DEF": 0}
if any(content.count(exec_emulation[name]) != count for name, count in expected.items()):
    raise SystemExit(f"exec partial fixture has unexpected block counts in {exec_path}")

capture = string_constants(root / "install/persona/patches/sftp-capture-permissions.py")
partial = capture["NEW"].replace("os.chmod(shasumfile, 0o640)", "os.chmod(shasumfile, 0o600)")
content = replace_once(capture_path, capture["OLD"], partial, "capture partial")
if content.count(capture["OLD"]) != 0 or content.count(capture["NEW"]) != 0:
    raise SystemExit(f"capture partial fixture unexpectedly contains a complete block in {capture_path}")

sharedfs = string_constants(root / "install/persona/patches/connection-shared-fs.py")
replace_once(sharedfs_path, sharedfs["OLD"], sharedfs["NEW"], "sharedfs partial")
sftp = sharedfs_path.parent / "filetransfer.py"
if sftp.read_text(encoding="utf-8").count(sharedfs["OLD_SFTP"]) != 1:
    raise SystemExit(f"sharedfs partial fixture lost its pristine half in {sftp}")

scp = string_constants(root / "install/persona/patches/scp-sink-target.py")
content = replace_once(scp_path, scp["OLD"], scp["NEW"], "scp partial")
expected = {"OLD": 0, "NEW": 1, "OLD_NAME": 1, "NEW_NAME": 0}
if any(content.count(scp[name]) != count for name, count in expected.items()):
    raise SystemExit(f"scp partial fixture has unexpected block counts in {scp_path}")

ls = string_constants(root / "install/persona/patches/ls-date-format.py")
old_form = '"%b %e  %Y"'
if ls["NEW"].count(old_form) != 1:
    raise SystemExit("ls NEW block does not contain the expected old-file format")
partial = ls["NEW"].replace(old_form, '"%Y-%m-%d %H:%M"', 1)
content = replace_once(ls_path, ls["OLD"], partial, "ls partial")
if content.count(ls["OLD"]) != 0 or content.count(ls["NEW"]) != 0:
    raise SystemExit(f"ls partial fixture unexpectedly contains a complete block in {ls_path}")

grep = string_constants(root / "install/persona/patches/grep-options.py")
ignore_case = 're.IGNORECASE if self.ignore_case else 0'
if grep["NEW"].count(ignore_case) != 1:
    raise SystemExit("grep NEW block does not contain the expected IGNORECASE flag")
partial = grep["NEW"].replace(ignore_case, "0", 1)
content = replace_once(grep_path, grep["OLD"], partial, "grep partial")
if content.count(grep["OLD"]) != 0 or content.count(grep["NEW"]) != 0:
    raise SystemExit(f"grep partial fixture unexpectedly contains a complete block in {grep_path}")

lspci = string_constants(root / "install/persona/patches/lspci-persona.py")
if lspci["NEW"].count('Cirrus Logic GD 5446') != 1:
    raise SystemExit("lspci NEW block does not contain the expected fixture anchor")
partial = lspci["NEW"].replace('Cirrus Logic GD 5446', 'Cirrus Logic GD 5430', 1)
content = replace_once(lspci_path, lspci["OLD"], partial, "lspci partial")
if content.count(lspci["OLD"]) != 0 or content.count(lspci["NEW"]) != 0:
    raise SystemExit(f"lspci partial fixture unexpectedly contains a complete block in {lspci_path}")

free = string_constants(root / "install/persona/patches/free-meminfo.py")
if free["NEW"].count('raw["Cached"] + raw["SReclaimable"]') != 1:
    raise SystemExit("free NEW block does not contain the expected fixture anchor")
partial = free["NEW"].replace('raw["Cached"] + raw["SReclaimable"]', 'raw["Cached"]', 1)
content = replace_once(free_path, free["OLD"], partial, "free partial")
if content.count(free["OLD"]) != 0 or content.count(free["NEW"]) != 0:
    raise SystemExit(f"free partial fixture unexpectedly contains a complete block in {free_path}")

uname = string_constants(root / "install/persona/patches/uname-a.py")
if uname["NEW"].count('"platform": False,') != 1:
    raise SystemExit("uname NEW block does not contain the expected fixture anchor")
partial = uname["NEW"].replace('"platform": False,', '"platform": True,', 1)
content = replace_once(uname_path, uname["OLD"], partial, "uname partial")
if content.count(uname["OLD"]) != 0 or content.count(uname["NEW"]) != 0:
    raise SystemExit(f"uname partial fixture unexpectedly contains a complete block in {uname_path}")

last = string_constants(root / "install/persona/patches/last-persona.py")
if last["NEW"].count('CALLER_TTY = "pts/1"') != 1:
    raise SystemExit("last NEW block does not contain the expected fixture anchor")
partial = last["NEW"].replace('CALLER_TTY = "pts/1"', 'CALLER_TTY = "pts/0"', 1)
content = replace_once(last_path, last["OLD"], partial, "last partial")
if content.count(last["OLD"]) != 0 or content.count(last["NEW"]) != 0:
    raise SystemExit(f"last partial fixture unexpectedly contains a complete block in {last_path}")

uptime = string_constants(root / "install/persona/patches/uptime-loadavg.py")
replace_once(uptime_path, uptime["OLD_UPTIME"], uptime["NEW_UPTIME"], "uptime partial")
base = uptime_path.parent / "base.py"
if base.read_text(encoding="utf-8").count(uptime["OLD"]) != 1:
    raise SystemExit(f"uptime partial fixture lost its pristine w half in {base}")
PY

# Every entry point must reject extra or misplaced arguments rather than
# silently applying a patch under a misspelled mode flag.
# Only the patches active on the pin are listed (see PATCHES in
# apply-patches.py); Tasks 3-4 of payload-yield Phase B add the ported ones back.
for patch in \
  "$ROOT/install/persona/patches/command-type-builtins.py" \
  "$ROOT/install/persona/patches/passwd-stdin.py" \
  "$ROOT/install/persona/patches/exec-emulation.py" \
  "$ROOT/install/persona/patches/connection-shared-fs.py" \
  "$ROOT/install/persona/patches/scp-sink-target.py" \
  "$ROOT/install/persona/patches/ls-date-format.py" \
  "$ROOT/install/persona/patches/grep-options.py" \
  "$ROOT/install/persona/patches/lspci-persona.py" \
  "$ROOT/install/persona/patches/free-meminfo.py" \
  "$ROOT/install/persona/patches/uname-a.py" \
  "$ROOT/install/persona/patches/last-persona.py" \
  "$ROOT/install/persona/patches/uptime-loadavg.py" \
  "$ROOT/install/persona/patches/sftp-capture-permissions.py"; do
  if python3 "$patch" "$args_checkout" --unexpected; then
    echo "[cowrie-patches] $(basename "$patch") accepted an unexpected argument" >&2
    exit 1
  fi
done
if python3 "$ORCHESTRATOR" "$cowrie" --unexpected; then
  echo "[cowrie-patches] orchestrator accepted an unexpected argument" >&2
  exit 1
fi

# Every partial state must fail both the individual script and the orchestrator
# in check and apply modes. Each invocation gets its own checkout so every
# path runs even if a broken apply path mutates its fixture.
working_tree_hash() {
  python3 - "$1" <<'PY'
import hashlib
import os
import stat
import sys
from pathlib import Path


root = Path(sys.argv[1])
digest = hashlib.sha256()
paths = sorted(root.rglob("*"), key=lambda path: os.fsencode(path.relative_to(root)))
for path in paths:
    relative = path.relative_to(root)
    if relative.parts[0] == ".git":
        continue

    relative_bytes = os.fsencode(relative)
    metadata = path.lstat()
    digest.update(len(relative_bytes).to_bytes(8, "big"))
    digest.update(relative_bytes)
    digest.update(stat.S_IMODE(metadata.st_mode).to_bytes(4, "big"))

    if stat.S_ISREG(metadata.st_mode):
        digest.update(b"f")
        digest.update(metadata.st_size.to_bytes(8, "big"))
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    elif stat.S_ISDIR(metadata.st_mode):
        digest.update(b"d")
    elif stat.S_ISLNK(metadata.st_mode):
        target = os.fsencode(os.readlink(path))
        digest.update(b"l")
        digest.update(len(target).to_bytes(8, "big"))
        digest.update(target)
    else:
        digest.update(b"o")
        digest.update(stat.S_IFMT(metadata.st_mode).to_bytes(4, "big"))

print(digest.hexdigest())
PY
}

partial_failures=0
assert_partial_rejected_unchanged() {
  local fixture_name="$1"
  local fixture="$2"
  local patch="$3"
  local mode="$4"
  local checkout="$tmp_root/test-${fixture_name}-${mode}"
  local before
  local after
  local -a command

  cp -a "$fixture" "$checkout"
  before="$(working_tree_hash "$checkout")"
  case "$mode" in
    individual-check)
      command=(python3 "$patch" "$checkout" --check)
      ;;
    individual-apply)
      command=(python3 "$patch" "$checkout")
      ;;
    orchestrator-check)
      command=(python3 "$ORCHESTRATOR" "$checkout" --check)
      ;;
    orchestrator-apply)
      command=(python3 "$ORCHESTRATOR" "$checkout")
      ;;
    *)
      echo "[cowrie-patches] unknown partial-state test mode: $mode" >&2
      exit 1
      ;;
  esac

  if "${command[@]}"; then
    echo "[cowrie-patches] $fixture_name partial state passed $mode" >&2
    partial_failures=1
  fi
  after="$(working_tree_hash "$checkout")"
  if [[ "$after" != "$before" ]]; then
    echo "[cowrie-patches] $fixture_name partial state changed during $mode" >&2
    partial_failures=1
  fi
}

for mode in individual-check individual-apply orchestrator-check orchestrator-apply; do
  assert_partial_rejected_unchanged \
    "passwd" \
    "$partial_passwd" \
    "$ROOT/install/persona/patches/passwd-stdin.py" \
    "$mode"
  assert_partial_rejected_unchanged \
    "builtins" \
    "$partial_builtins" \
    "$ROOT/install/persona/patches/command-type-builtins.py" \
    "$mode"
  assert_partial_rejected_unchanged \
    "exec" \
    "$partial_exec" \
    "$ROOT/install/persona/patches/exec-emulation.py" \
    "$mode"
  assert_partial_rejected_unchanged \
    "capture" \
    "$partial_capture" \
    "$ROOT/install/persona/patches/sftp-capture-permissions.py" \
    "$mode"
  assert_partial_rejected_unchanged \
    "sharedfs" \
    "$partial_sharedfs" \
    "$ROOT/install/persona/patches/connection-shared-fs.py" \
    "$mode"
  assert_partial_rejected_unchanged \
    "scp" \
    "$partial_scp" \
    "$ROOT/install/persona/patches/scp-sink-target.py" \
    "$mode"
  assert_partial_rejected_unchanged \
    "ls" \
    "$partial_ls" \
    "$ROOT/install/persona/patches/ls-date-format.py" \
    "$mode"
  assert_partial_rejected_unchanged \
    "grep" \
    "$partial_grep" \
    "$ROOT/install/persona/patches/grep-options.py" \
    "$mode"
  assert_partial_rejected_unchanged \
    "lspci" \
    "$partial_lspci" \
    "$ROOT/install/persona/patches/lspci-persona.py" \
    "$mode"
  assert_partial_rejected_unchanged \
    "free" \
    "$partial_free" \
    "$ROOT/install/persona/patches/free-meminfo.py" \
    "$mode"
  assert_partial_rejected_unchanged \
    "uname" \
    "$partial_uname" \
    "$ROOT/install/persona/patches/uname-a.py" \
    "$mode"
  assert_partial_rejected_unchanged \
    "last" \
    "$partial_last" \
    "$ROOT/install/persona/patches/last-persona.py" \
    "$mode"
  assert_partial_rejected_unchanged \
    "uptime" \
    "$partial_uptime" \
    "$ROOT/install/persona/patches/uptime-loadavg.py" \
    "$mode"
done
if ((partial_failures != 0)); then
  exit 1
fi

# A pristine preflight must be read-only.
python3 "$ORCHESTRATOR" "$cowrie" --check
if ! git -C "$cowrie" diff --quiet --; then
  echo "[cowrie-patches] --check modified the pristine checkout" >&2
  exit 1
fi

# Apply, verify every expected target changed, then prove check mode and normal
# reapplication leave the complete patch set byte-for-byte unchanged. The list is
# git-diff --name-only order (alphabetical by path); keep it sorted.
# shell/bashparse.py and shell/honeypot.py left with the patches upstream made
# redundant.
python3 "$ORCHESTRATOR" "$cowrie"
expected_changed=(
  "src/cowrie/commands/base.py"
  "src/cowrie/commands/busybox.py"
  "src/cowrie/commands/free.py"
  "src/cowrie/commands/fs.py"
  "src/cowrie/commands/last.py"
  "src/cowrie/commands/ls.py"
  "src/cowrie/commands/lspci.py"
  "src/cowrie/commands/scp.py"
  "src/cowrie/commands/uname.py"
  "src/cowrie/commands/uptime.py"
  "src/cowrie/commands/which.py"
  "src/cowrie/insults/insults.py"
  "src/cowrie/shell/filetransfer.py"
  "src/cowrie/shell/fs.py"
  "src/cowrie/shell/pipe.py"
  "src/cowrie/shell/protocol.py"
  "src/cowrie/shell/script.py"
  "src/cowrie/shell/session.py"
)
mapfile -t actual_changed < <(git -C "$cowrie" diff --name-only --)
if [[ "${actual_changed[*]}" != "${expected_changed[*]}" ]]; then
  echo "[cowrie-patches] patched files differ from the expected targets" >&2
  printf '  expected: %s\n' "${expected_changed[*]}" >&2
  printf '  actual:   %s\n' "${actual_changed[*]}" >&2
  exit 1
fi
patched_diff_hash="$(git -C "$cowrie" diff --binary -- | git -C "$cowrie" hash-object --stdin)"
python3 "$ORCHESTRATOR" "$cowrie" --check
checked_diff_hash="$(git -C "$cowrie" diff --binary -- | git -C "$cowrie" hash-object --stdin)"
if [[ "$checked_diff_hash" != "$patched_diff_hash" ]]; then
  echo "[cowrie-patches] --check changed an already-patched checkout" >&2
  exit 1
fi
python3 "$ORCHESTRATOR" "$cowrie"
reapplied_diff_hash="$(git -C "$cowrie" diff --binary -- | git -C "$cowrie" hash-object --stdin)"
if [[ "$reapplied_diff_hash" != "$patched_diff_hash" ]]; then
  echo "[cowrie-patches] patch reapplication was not idempotent" >&2
  exit 1
fi
git -C "$cowrie" diff --check

# scripts/install.sh fetches some patches from the release tag and runs each
# one ALONE against a fresh pin checkout. Prove each applies that way too, so a
# tag can never ship a patch install.sh fetches but the pin rejects (Task 2 of
# payload-yield Phase B parked one and nothing noticed). test_release_contracts
# keeps this list equal to what install.sh fetches.
install_sh_patches=(
  "sftp-capture-permissions.py"
)
for name in "${install_sh_patches[@]}"; do
  standalone="$tmp_root/standalone-${name%.py}"
  cp -a "$cowrie" "$standalone"
  git -C "$standalone" checkout -q -- .
  python3 "$ROOT/install/persona/patches/$name" "$standalone" --check
  python3 "$ROOT/install/persona/patches/$name" "$standalone"
  python3 "$ROOT/install/persona/patches/$name" "$standalone"
  if git -C "$standalone" diff --quiet --; then
    echo "[cowrie-patches] install.sh patch $name changed nothing on the pin" >&2
    exit 1
  fi
done

# Run the real pinned, patched SFTP methods against inert local files, including
# SHA-dedup destinations and publication-time permissions. No Twisted/network.
python3 "$ROOT/install/persona/test_capture_permissions.py" "$cowrie" -v
# Same approach for the scp sink: -t targets and unchanged capture.
python3 "$ROOT/install/persona/test_scp_sink_target.py" "$cowrie" -v
# And for connection-shared-fs's redirection backing rule: a redirection never
# writes into another channel's in-flight upload or a finished capture.
python3 "$ROOT/install/persona/test_shared_fs_backing.py" "$cowrie" -v
# And the persona time commands (last, then uptime/w), judged by the
# behavioural harness's own comparison over days of simulated Cowrie age.
python3 "$ROOT/install/persona/test_time_persona.py" "$cowrie" -v

# Drift the final target so a sequential check/apply implementation would alter
# earlier files before discovering incompatibility. The entire working tree
# must remain identical after the orchestrator's failed all-patch preflight.
# The target is read from PATCHES[-1] (its OLD block), so the fixture follows
# the chain as patches are added instead of falling behind it; it must live in
# a different file from at least one earlier patch, or "earlier targets stay
# untouched" would prove nothing.
python3 - "$ORCHESTRATOR" "$drifted" <<'PY'
import ast
import sys
from pathlib import Path


def assigned_constant(path: Path, name: str):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name):
            return ast.literal_eval(node.value)
    raise SystemExit(f"{path}: no {name} constant")


def target_of(old: str, root: Path) -> Path:
    hits = [p for p in sorted((root / "src/cowrie").rglob("*.py"))
            if p.read_text(encoding="utf-8").count(old) == 1]
    if len(hits) != 1:
        raise SystemExit(f"OLD block found in {len(hits)} files, want exactly 1")
    return hits[0]


orchestrator, root = Path(sys.argv[1]), Path(sys.argv[2])
patches_dir = orchestrator.parent / "patches"
patches = assigned_constant(orchestrator, "PATCHES")
if len(patches) < 2:
    raise SystemExit("atomic preflight needs at least two patches")
olds = [assigned_constant(patches_dir / name, "OLD") for name in patches]
path = target_of(olds[-1], root)
if all(target_of(old, root) == path for old in olds[:-1]):
    raise SystemExit(f"every earlier patch also targets {path}; drift proves nothing")

# Suffix the first non-blank line that OLD itself terminates with a newline;
# a suffix on an unterminated final line would leave OLD intact as a prefix.
old = olds[-1]
lines = old.split("\n")
first = next(i for i, line in enumerate(lines[:-1]) if line.strip())
lines[first] += "  # intentional compatibility drift"
content = path.read_text(encoding="utf-8")
path.write_text(content.replace(old, "\n".join(lines), 1), encoding="utf-8")
print(f"[cowrie-patches] drifted {patches[-1]} target {path.relative_to(root)}")
PY

drifted_before="$(working_tree_hash "$drifted")"
if python3 "$ORCHESTRATOR" "$drifted"; then
  echo "[cowrie-patches] drifted final target unexpectedly passed preflight" >&2
  exit 1
fi
drifted_after="$(working_tree_hash "$drifted")"
if [[ "$drifted_after" != "$drifted_before" ]]; then
  echo "[cowrie-patches] failed preflight modified an earlier patch target" >&2
  exit 1
fi

echo "[cowrie-patches] pin, 52 partial-state rejections, idempotence, install.sh standalone patches, capture, scp-target, shared-fs backing and time-persona behavior, and atomic preflight checks passed"
