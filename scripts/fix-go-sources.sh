#!/usr/bin/env bash
# Strip NUL bytes / CRLF / UTF-16 from Go sources on the VPS (scp/rsync corruption).
set -euo pipefail

ROOT="${HOME}/ShardLure/shardlure"
if [[ -f "$(dirname "$0")/../go.mod" ]]; then
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi
cd "$ROOT"

# Repair logic lives in ONE place (scripts/lib/repair_text.py) — the four
# previously-embedded copies drifted into independent bugs. The helper itself
# may be transfer-corrupted on a remote, so self-heal it first with a
# minimal NUL/BOM/CRLF strip that assumes nothing about its content.
LIB="$(dirname "$0")/lib/repair_text.py"
python3 -c 'import sys; p=sys.argv[1]; b=open(p,"rb").read(); c=b.replace(b"\x00",b"").replace(b"\xff\xfe",b"").replace(b"\xfe\xff",b"").replace(b"\r\n",b"\n"); open(p,"wb").write(c) if c!=b else None' "$LIB"
python3 "$LIB" --root "$ROOT" --mode go

go mod tidy
# Unpredictable mktemp path instead of the fixed /tmp/shardlure: the operator
# installs this as root next, so a predictable name in world-writable /tmp
# would be a TOCTOU/symlink-swap target.
BUILD_BIN="$(mktemp /tmp/shardlure-build.XXXXXX)"
go build -o "$BUILD_BIN" ./cmd/shardlure
echo "OK: built $BUILD_BIN ($(wc -c < "$BUILD_BIN") bytes)"
echo "install with:"
echo "  sudo install -m 755 $BUILD_BIN /usr/local/bin/shardlure && rm -f $BUILD_BIN"
