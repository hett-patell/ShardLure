#!/usr/bin/env bash
# Archive Cowrie attacker artifacts (tty transcripts, downloads, malicious commands) for offline analysis.
set -euo pipefail

CONFIG="${SHARDLURE_CONFIG:-/var/lib/shardlure/shardlure.yaml}"
DATA="${SHARDLURE_DATA:-/var/lib/shardlure}"
COWRIE="${SHARDLURE_COWRIE:-$DATA/cowrie}"
OUT="${1:-$DATA/payloads/archive-$(date -u +%Y%m%dT%H%M%SZ)}"
DB="${SHARDLURE_DB:-$DATA/shardlure.db}"
EVIDENCE="${SHARDLURE_EVIDENCE:-$DATA/evidence}"

mkdir -p "$OUT"/{tty,downloads,logs,commands,evidence}

echo "[collect] tty session recordings"
if [ -d "$COWRIE/var/lib/cowrie/tty" ]; then
  cp -a "$COWRIE/var/lib/cowrie/tty/." "$OUT/tty/" 2>/dev/null || true
fi

echo "[collect] cowrie downloads (SFTP/SCP drops)"
if [ -d "$COWRIE/var/lib/cowrie/downloads" ]; then
  cp -a "$COWRIE/var/lib/cowrie/downloads/." "$OUT/downloads/" 2>/dev/null || true
fi

echo "[collect] shardlure evidence (quarantine + cowrie copies)"
if [ -d "$EVIDENCE" ]; then
  cp -a "$EVIDENCE/." "$OUT/evidence/" 2>/dev/null || true
fi

echo "[collect] artifacts table"
python3 <<PY
import json, sqlite3
from pathlib import Path
db = Path("$DB")
out = Path("$OUT/commands/artifacts.jsonl")
if db.is_file():
    con = sqlite3.connect(db)
    try:
        rows = con.execute(
            "SELECT ts,src_ip,session_id,url,local_path,sha256,size_bytes,origin,status,detail FROM artifacts ORDER BY ts"
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []
    with out.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps({
                "ts": r[0], "src_ip": r[1], "session_id": r[2], "url": r[3],
                "local_path": r[4], "sha256": r[5], "size_bytes": r[6],
                "origin": r[7], "status": r[8], "detail": r[9],
            }) + "\n")
    print(f"wrote {len(rows)} artifact rows -> {out}")
PY

echo "[collect] cowrie json logs"
for f in "$COWRIE/var/log/cowrie"/cowrie.json*; do
  [ -f "$f" ] && cp -a "$f" "$OUT/logs/" || true
done

echo "[collect] malicious commands from sqlite"
python3 <<PY
import json, sqlite3
from pathlib import Path

db = Path("$DB")
out = Path("$OUT/commands/malicious_commands.jsonl")
patterns = ("%curl%", "%wget%", "%chmod +x%", "%/tmp/%", "%base64%", "%/dev/tcp%", "%nohup%", "%exec %")
if not db.is_file():
    print("skip db (missing)", db)
    raise SystemExit(0)
con = sqlite3.connect(db)
q = "SELECT ts,src_ip,username,kind,command,filename,sha256,actor_id,raw FROM events WHERE "
q += " OR ".join(["(command LIKE ? OR raw LIKE ?)"] * len(patterns))
params = [p for pat in patterns for p in (pat, pat)]
rows = con.execute(q, params).fetchall()
with out.open("w", encoding="utf-8") as f:
    for r in rows:
        f.write(json.dumps({
            "ts": r[0], "src_ip": r[1], "user": r[2], "kind": r[3],
            "command": r[4], "filename": r[5], "sha256": r[6], "actor_id": r[7],
            "raw": r[8],
        }) + "\n")
print(f"wrote {len(rows)} command rows -> {out}")
PY

echo "[collect] ingest rotated logs (if shardlure available)"
if command -v shardlure >/dev/null 2>&1; then
  for f in "$COWRIE/var/log/cowrie"/cowrie.json.*; do
    [ -f "$f" ] || continue
    echo "  ingest $f"
    shardlure -config "$CONFIG" ingest cowrie "$f" || true
  done
fi

tar -C "$(dirname "$OUT")" -czf "${OUT}.tar.gz" "$(basename "$OUT")"
echo "[collect] archive: ${OUT}.tar.gz"
ls -lah "${OUT}.tar.gz"
