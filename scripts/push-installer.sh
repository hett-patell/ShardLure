#!/usr/bin/env bash
# Push clean shardlure.py to VPS without scp corruption.
set -euo pipefail
HOST="${1:-arm}"
REMOTE="${2:-/home/ubuntu/ShardLure/shardlure/scripts/shardlure.py}"
LOCAL="$(cd "$(dirname "$0")" && pwd)/shardlure.py"

# REMOTE is interpolated into remote shell commands and Python -c snippets;
# restrict to a safe path charset (also blocks the quote that would break the
# Python string literal) so a crafted value can't inject either.
case "$REMOTE" in
  *[!A-Za-z0-9/._~-]*) echo "error: REMOTE path has unsafe characters: $REMOTE" >&2; exit 1 ;;
esac

if [[ ! -f "$LOCAL" ]]; then
  echo "missing $LOCAL" >&2
  exit 1
fi

python3 -c "
from pathlib import Path
data = Path('$LOCAL').read_bytes()
if b'\x00' in data:
    raise SystemExit('local file contains NUL bytes')
print(f'local ok: {len(data)} bytes')
"

ssh "$HOST" "mkdir -p $(dirname "$REMOTE") && python3 -c \"
import sys
from pathlib import Path
p = Path('$REMOTE')
data = sys.stdin.buffer.read()
if b'\\x00' in data:
    raise SystemExit('received data contains NUL bytes')
p.write_bytes(data)
print(f'wrote {len(data)} bytes to {p}')
\"" < "$LOCAL"

ssh "$HOST" "python3 -c \"
from pathlib import Path
p = Path('$REMOTE')
data = p.read_bytes()
assert b'\\x00' not in data, 'NUL bytes remain'
assert data.startswith(b'#!/usr/bin/env python3'), data[:40]
print('verify ok:', p)
\""

echo "Done. On VPS run:"
echo "  cd ~/ShardLure/shardlure && sudo python3 scripts/shardlure.py run"
