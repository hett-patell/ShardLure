#!/usr/bin/env bash
# Fail CI if any tracked text file is not valid UTF-8 (no BOM / NUL / UTF-16).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python3 - <<'PY'
import subprocess
import sys
from pathlib import Path

files = subprocess.check_output(["git", "ls-files"], text=True).splitlines()
bad = []
for rel in files:
    p = Path(rel)
    if not p.is_file():
        continue
    b = p.read_bytes()
    if b.startswith((b"\xff\xfe", b"\xfe\xff")):
        bad.append((rel, "UTF-16 BOM"))
        continue
    if b.count(b"\x00") > 0:
        bad.append((rel, f"contains {b.count(b'\x00')} NUL bytes"))
        continue
    try:
        b.decode("utf-8")
    except UnicodeDecodeError as e:
        bad.append((rel, str(e)))

if bad:
    print("Non-UTF-8 or corrupted text files:", file=sys.stderr)
    for rel, msg in bad:
        print(f"  {rel}: {msg}", file=sys.stderr)
    sys.exit(1)
print(f"OK: {len(files)} tracked files are UTF-8")
PY
