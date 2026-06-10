#!/usr/bin/env bash
# Push ShardLure sources to VPS without scp/rsync NUL-byte corruption.
set -euo pipefail

HOST="${1:-arm}"
REMOTE="${2:-~/ShardLure/shardlure}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# $REMOTE is interpolated into remote shell commands (so the leading ~ can
# expand on the far side), which means a crafted value could inject commands
# (e.g. "x; rm -rf /"). We can't quote it without losing ~ expansion, so
# instead restrict it to a safe path charset: letters, digits, / . _ - ~
case "$REMOTE" in
  *[!A-Za-z0-9/._~-]*) echo "error: REMOTE path has unsafe characters: $REMOTE" >&2; exit 1 ;;
esac

echo "Packing $ROOT -> $HOST:$REMOTE"
ssh "$HOST" "mkdir -p $REMOTE"

tar -C "$ROOT" -czf - \
  --exclude='shardlure' \
  --exclude='*.db' \
  --exclude='*.db-wal' \
  --exclude='*.db-shm' \
  --exclude='.git' \
  . | ssh "$HOST" "tar -xzf - -C $REMOTE"

echo "Verifying Go sources on $HOST..."
# Pass REMOTE via the environment (read with os.environ) instead of
# interpolating it into the Python source, so it can't break the string literal.
ssh "$HOST" "SL_REMOTE=$REMOTE python3 - <<'PY'
import os
from pathlib import Path
root = Path(os.environ['SL_REMOTE']).expanduser()
bad = []
for p in root.rglob('*.go'):
    b = p.read_bytes()
    if b'\\x00' in b:
        bad.append(str(p))
if bad:
    raise SystemExit('NUL bytes remain: ' + ', '.join(bad[:5]))
print('ok:', len(list(root.rglob('*.go'))), 'go files, no NUL bytes')
PY"

echo "Done. On VPS finish setup with:"
echo "  cd ~/ShardLure/shardlure && bash scripts/fix-go-sources.sh"
echo "  # then run the 'sudo install ...' command fix-go-sources.sh prints"
echo "  sudo python3 scripts/shardlure.py finish   # or run remaining steps manually"
