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

# Genuinely-binary assets. This check exists to catch TEXT sources corrupted to
# UTF-16 by scp (see the Deployment section of the README), so binary files are
# skipped rather than the NUL test being weakened for everything. Keep this list
# tight: anything not listed here is still held to strict UTF-8.
BINARY_SUFFIXES = {".ico", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf",
                   ".woff", ".woff2", ".ttf", ".otf", ".zip", ".gz", ".db",
                   # MaxMind GeoIP2/GeoLite2 databases (the geo MMDB test
                   # fixture in internal/web/testdata) are memory-mapped
                   # binary blobs, not text sources.
                   ".mmdb"}

bad = []
skipped = 0
for rel in files:
    p = Path(rel)
    if not p.is_file():
        continue
    if p.suffix.lower() in BINARY_SUFFIXES:
        skipped += 1
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
print(f"OK: {len(files) - skipped} tracked text files are UTF-8 ({skipped} binary skipped)")
PY
