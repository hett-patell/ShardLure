#!/bin/bash
# Push scripts/shardlure to VPS without scp corruption (use stdin cat).
set -eo pipefail
HOST="${1:-arm}"
DEST="${2:-~/ShardLure/shardlure/scripts/shardlure}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# DEST is interpolated into remote shell commands; restrict to a safe path
# charset so a crafted value can't inject commands (~ expansion preserved).
case "$DEST" in
  *[!A-Za-z0-9/._~-]*) echo "error: DEST path has unsafe characters: $DEST" >&2; exit 1 ;;
esac
bash "$ROOT/scripts/repair-text.sh"
ssh "$HOST" "mkdir -p $(dirname "$DEST")"
ssh "$HOST" "cat > $DEST" < "$ROOT/scripts/shardlure"
ssh "$HOST" "chmod 755 $DEST && head -1 $DEST"
echo "pushed to $HOST:$DEST"
echo "run on vps: cd ~/ShardLure/shardlure && sudo bash scripts/shardlure run"
