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

# Build an exact incomplete state from the patch script's literal blocks:
# passwd has the piped-stdin branch without its early return, so neither OLD
# nor NEW is present. The grep and capture fixtures left with their patches
# (Task 4 restores a grep-options fixture, Task 3 the capture one); the
# bashparse and honeypot fixtures went with the patches upstream made redundant.
python3 - \
  "$ROOT" \
  "$partial_passwd/src/cowrie/commands/base.py" <<'PY'
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

passwd = string_constants(root / "install/persona/patches/passwd-stdin.py")
early_return = "            return\n"
if passwd["NEW"].count(early_return) != 1:
    raise SystemExit("passwd NEW block does not contain the expected early return")
partial = passwd["NEW"].replace(early_return, "", 1)
content = replace_once(passwd_path, passwd["OLD"], partial, "passwd partial")
if content.count(passwd["OLD"]) != 0 or content.count(passwd["NEW"]) != 0:
    raise SystemExit(f"passwd partial fixture unexpectedly contains a complete block in {passwd_path}")
PY

# Every entry point must reject extra or misplaced arguments rather than
# silently applying a patch under a misspelled mode flag.
# Only the patches active on the pin are listed (see PATCHES in
# apply-patches.py); Tasks 3-4 of payload-yield Phase B add the ported ones back.
for patch in \
  "$ROOT/install/persona/patches/passwd-stdin.py"; do
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
# git-diff --name-only order (alphabetical by path); keep it sorted. On v3.1.1
# only passwd-stdin is active: Task 3 adds back commands/which.py, shell/fs.py
# and shell/script.py, Task 4 commands/fs.py. shell/bashparse.py and
# shell/honeypot.py left with the patches upstream made redundant.
python3 "$ORCHESTRATOR" "$cowrie"
expected_changed=(
  "src/cowrie/commands/base.py"
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

# The SFTP capture-permission behaviour test
# (install/persona/test_capture_permissions.py) runs against the patched
# shell/fs.py, so it returns with sftp-capture-permissions in Task 3.

# Drift the final target so a sequential check/apply implementation would alter
# earlier files before discovering incompatibility. The entire working tree
# must remain identical after the orchestrator's failed all-patch preflight.
# With passwd-stdin the only active patch the final target is its anchor; move
# this back to the last patch in PATCHES when Tasks 3-4 restore the others.
python3 - "$drifted/src/cowrie/commands/base.py" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
content = path.read_text(encoding="utf-8")
old = '        self.write("Enter new UNIX password: ")\n        self.protocol.password_input = True'
new = old + "  # intentional compatibility drift"
if content.count(old) != 1:
    raise SystemExit(f"cannot create deterministic drift in {path}")
path.write_text(content.replace(old, new, 1), encoding="utf-8")
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

echo "[cowrie-patches] pin, 4 partial-state rejections, idempotence, and atomic preflight checks passed"
