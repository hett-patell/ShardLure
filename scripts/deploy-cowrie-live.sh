#!/bin/bash
set -eo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> ensuring dirs on arm"
ssh arm 'mkdir -p ~/ShardLure/shardlure/internal/web ~/ShardLure/shardlure/internal/actor ~/ShardLure/shardlure/internal/ingest/cowrie ~/ShardLure/shardlure/cmd/shardlure'

echo "==> copying updated files"
scp internal/web/server.go arm:~/ShardLure/shardlure/internal/web/server.go
scp internal/actor/builder.go arm:~/ShardLure/shardlure/internal/actor/builder.go
scp internal/ingest/cowrie/ingest.go arm:~/ShardLure/shardlure/internal/ingest/cowrie/ingest.go
scp internal/ingest/cowrie/ingest_test.go arm:~/ShardLure/shardlure/internal/ingest/cowrie/ingest_test.go
scp cmd/shardlure/main.go arm:~/ShardLure/shardlure/cmd/shardlure/main.go
scp README.md arm:~/ShardLure/shardlure/README.md

echo "==> strip NUL bytes, format, test, build"
ssh arm "python3 - <<'PY'
from pathlib import Path
root = Path.home() / 'ShardLure/shardlure'
for p in root.rglob('*'):
    if p.is_file() and p.suffix in {'.go', '.md'}:
        b = p.read_bytes()
        if b"\x00" in b:
            p.write_bytes(b.replace(b"\x00", b""))
            print('fixed', p)
PY
cd ~/ShardLure/shardlure
gofmt -w \$(find . -name '*.go')
go test ./...
go build -o shardlure ./cmd/shardlure
./shardlure version"

echo "==> done. start live wrapper with:"
echo "ssh arm 'cd ~/ShardLure/shardlure && ./shardlure live :8080 --tailscale'"
