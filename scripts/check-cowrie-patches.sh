#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED_PIN="65ded95b2d2b6555be8e4eb95315036a4db361f9"
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
partial_bashparse="$tmp_root/cowrie-partial-bashparse"
partial_grep="$tmp_root/cowrie-partial-grep"
partial_honeypot="$tmp_root/cowrie-partial-honeypot"
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
cp -a "$cowrie" "$partial_bashparse"
cp -a "$cowrie" "$partial_grep"
cp -a "$cowrie" "$partial_honeypot"

# Build three exact incomplete states from the patch scripts' literal blocks:
# bashparse has NEW1 + OLD2, grep has only its first NEW hunk, and honeypot
# has the assignment without the complete guarded NEW block.
python3 - \
  "$ROOT" \
  "$partial_bashparse/src/cowrie/shell/bashparse.py" \
  "$partial_grep/src/cowrie/commands/fs.py" \
  "$partial_honeypot/src/cowrie/shell/honeypot.py" <<'PY'
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
bashparse_path = Path(sys.argv[2])
grep_path = Path(sys.argv[3])
honeypot_path = Path(sys.argv[4])

bashparse = string_constants(
    root / "install/persona/patches/bashparse-subshell-pipe.py"
)
content = replace_once(
    bashparse_path, bashparse["OLD1"], bashparse["NEW1"], "bashparse partial"
)
expected = {
    "OLD1": 0,
    "NEW1": 1,
    "OLD2": 1,
    "NEW2": 0,
}
if any(content.count(bashparse[name]) != count for name, count in expected.items()):
    raise SystemExit(f"bashparse partial fixture has unexpected block counts in {bashparse_path}")

grep = string_constants(root / "install/persona/patches/grep-case-insensitive.py")
content = replace_once(
    grep_path, grep["OLD_GREP_APP"], grep["NEW_GREP_APP"], "grep partial"
)
expected = {
    "OLD_GREP_APP": 0,
    "NEW_GREP_APP": 1,
    "OLD_START_OPTS": 1,
    "NEW_START_OPTS": 0,
    "OLD_START_BEGIN": 1,
    "NEW_START_BEGIN": 0,
}
if any(content.count(grep[name]) != count for name, count in expected.items()):
    raise SystemExit(f"grep partial fixture has unexpected block counts in {grep_path}")

honeypot = string_constants(
    root / "install/persona/patches/honeypot-capture-redirect.py"
)
guarded_assignment = """\
                    if self.redirect:
                        self.protocol.pp = temp_pp
"""
unguarded_assignment = "                    self.protocol.pp = temp_pp\n"
if honeypot["NEW"].count(guarded_assignment) != 1:
    raise SystemExit("honeypot NEW block does not contain the expected guarded assignment")
partial = honeypot["NEW"].replace(guarded_assignment, unguarded_assignment, 1)
content = replace_once(honeypot_path, honeypot["OLD"], partial, "honeypot partial")
if content.count(honeypot["OLD"]) != 0 or content.count(honeypot["NEW"]) != 0:
    raise SystemExit(f"honeypot partial fixture unexpectedly contains a complete block in {honeypot_path}")
PY

# Every entry point must reject extra or misplaced arguments rather than
# silently applying a patch under a misspelled mode flag.
for patch in \
  "$ROOT/install/persona/patches/bashparse-subshell-pipe.py" \
  "$ROOT/install/persona/patches/grep-case-insensitive.py" \
  "$ROOT/install/persona/patches/honeypot-capture-redirect.py"; do
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
# in check and apply modes. Each invocation gets its own checkout so all twelve
# paths run even if a broken apply path mutates its fixture.
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
    "bashparse" \
    "$partial_bashparse" \
    "$ROOT/install/persona/patches/bashparse-subshell-pipe.py" \
    "$mode"
  assert_partial_rejected_unchanged \
    "grep" \
    "$partial_grep" \
    "$ROOT/install/persona/patches/grep-case-insensitive.py" \
    "$mode"
  assert_partial_rejected_unchanged \
    "honeypot" \
    "$partial_honeypot" \
    "$ROOT/install/persona/patches/honeypot-capture-redirect.py" \
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
# reapplication leave the complete patch set byte-for-byte unchanged.
python3 "$ORCHESTRATOR" "$cowrie"
expected_changed=(
  "src/cowrie/commands/fs.py"
  "src/cowrie/shell/bashparse.py"
  "src/cowrie/shell/honeypot.py"
)
mapfile -t actual_changed < <(git -C "$cowrie" diff --name-only --)
if [[ "${actual_changed[*]}" != "${expected_changed[*]}" ]]; then
  echo "[cowrie-patches] patched files differ from the expected three targets" >&2
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

# Drift the final target so a sequential check/apply implementation would alter
# the first two files before discovering incompatibility. The two checksums must
# remain identical after the orchestrator's failed all-patch preflight.
python3 - "$drifted/src/cowrie/shell/honeypot.py" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
content = path.read_text(encoding="utf-8")
old = """\
                    temp_pp.errReceived(message)
                    for real_path, virtual_path in temp_pp.redirect_real_files:"""
new = """\
                    temp_pp.errReceived(message)  # intentional compatibility drift
                    for real_path, virtual_path in temp_pp.redirect_real_files:"""
if content.count(old) != 1:
    raise SystemExit(f"cannot create deterministic drift in {path}")
path.write_text(content.replace(old, new, 1), encoding="utf-8")
PY

bashparse_rel="src/cowrie/shell/bashparse.py"
grep_rel="src/cowrie/commands/fs.py"
bashparse_before="$(git -C "$drifted" hash-object "$bashparse_rel")"
grep_before="$(git -C "$drifted" hash-object "$grep_rel")"
if python3 "$ORCHESTRATOR" "$drifted"; then
  echo "[cowrie-patches] drifted final target unexpectedly passed preflight" >&2
  exit 1
fi
bashparse_after="$(git -C "$drifted" hash-object "$bashparse_rel")"
grep_after="$(git -C "$drifted" hash-object "$grep_rel")"
if [[ "$bashparse_after" != "$bashparse_before" || "$grep_after" != "$grep_before" ]]; then
  echo "[cowrie-patches] failed preflight modified an earlier patch target" >&2
  exit 1
fi

echo "[cowrie-patches] pin, exact-state, idempotence, and atomic preflight checks passed"
