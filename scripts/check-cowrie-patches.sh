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

echo "[cowrie-patches] pin, idempotence, and atomic preflight checks passed"
