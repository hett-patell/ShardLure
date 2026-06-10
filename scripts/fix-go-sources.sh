#!/usr/bin/env bash
# Strip NUL bytes / CRLF / UTF-16 from Go sources on the VPS (scp/rsync corruption).
set -euo pipefail

ROOT="${HOME}/ShardLure/shardlure"
if [[ -f "$(dirname "$0")/../go.mod" ]]; then
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi
cd "$ROOT"

ROOT="$ROOT" python3 - <<'PY'
import os
from pathlib import Path

root = Path(os.environ["ROOT"])
fixed = 0
for p in sorted(root.rglob("*.go")):
    b = p.read_bytes()
    if not b:
        continue
    orig = b
    if b.startswith(b"\xff\xfe"):
        s = b[2:].decode("utf-16-le", errors="ignore")
    elif b.startswith(b"\xfe\xff"):
        s = b[2:].decode("utf-16-be", errors="ignore")
    elif b"\x00" in b:
        s = b.replace(b"\x00", b"").decode("utf-8", errors="ignore")
    else:
        s = b.decode("utf-8", errors="ignore")
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    if not s.endswith("\n"):
        s += "\n"
    if s.encode("utf-8") != orig.replace(b"\x00", b"") if b"\x00" in orig else orig:
        p.write_text(s, encoding="utf-8", newline="\n")
        fixed += 1
        print("fixed", p.relative_to(root))

for name in ("go.mod", "go.sum"):
    p = root / name
    if not p.exists():
        continue
    b = p.read_bytes()
    if b"\x00" not in b and not b.startswith((b"\xff\xfe", b"\xfe\xff")):
        continue
    if b.startswith(b"\xff\xfe"):
        s = b[2:].decode("utf-16-le", errors="ignore")
    elif b.startswith(b"\xfe\xff"):
        s = b[2:].decode("utf-16-be", errors="ignore")
    else:
        s = b.replace(b"\x00", b"").decode("utf-8", errors="ignore")
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    if not s.endswith("\n"):
        s += "\n"
    p.write_text(s, encoding="utf-8", newline="\n")
    fixed += 1
    print("fixed", name)

if fixed == 0:
    print("no corrupted text files found")
else:
    print(f"repaired {fixed} file(s)")
PY

go mod tidy
# Unpredictable mktemp path instead of the fixed /tmp/shardlure: the operator
# installs this as root next, so a predictable name in world-writable /tmp
# would be a TOCTOU/symlink-swap target.
BUILD_BIN="$(mktemp /tmp/shardlure-build.XXXXXX)"
go build -o "$BUILD_BIN" ./cmd/shardlure
echo "OK: built $BUILD_BIN ($(wc -c < "$BUILD_BIN") bytes)"
echo "install with:"
echo "  sudo install -m 755 $BUILD_BIN /usr/local/bin/shardlure && rm -f $BUILD_BIN"
