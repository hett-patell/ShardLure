#!/usr/bin/env bash
# ci-web-smoke.sh - start ./shardlure web on a tmp data dir, hit a few endpoints,
# assert sane responses, then shut down. Runs in CI on amd64 only; cross-arch
# builds get a lighter 'version' smoke under QEMU.
#
# Exits non-zero on any failure. Designed to be fast (<10s) and self-contained.

set -euo pipefail

BIN="${BIN:-./shardlure}"
PORT="${PORT:-18080}"
TMPDIR="$(mktemp -d)"
LOG="$TMPDIR/server.log"
CFG="$TMPDIR/shardlure.yaml"
PID=""

cleanup() {
    local exit_code=$?
    if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    if [[ $exit_code -ne 0 ]]; then
        echo "=== server log ==="
        cat "$LOG" 2>/dev/null || true
        echo "=== /tmp data dir ==="
        ls -la "$TMPDIR" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR"
    exit $exit_code
}
trap cleanup EXIT

# Minimal config: just point data_dir at our tmp dir. Everything else uses
# defaults. The dashboard port is forced via the CLI arg, not the yaml,
# since the web subcommand takes the addr as a positional.
cat > "$CFG" <<EOF
data_dir: $TMPDIR/data
EOF

echo "[smoke] starting: $BIN -config $CFG web :$PORT"
"$BIN" -config "$CFG" web ":$PORT" > "$LOG" 2>&1 &
PID=$!

# Wait for listener (up to 10s). The first boot runs sqlite migrations,
# which on a clean tmp DB takes <1s but we give margin for CI jitter.
echo "[smoke] waiting for listener on :$PORT"
for i in $(seq 1 50); do
    if ss -ltn 2>/dev/null | grep -q ":$PORT "; then
        echo "[smoke] listener up after ${i}00ms"
        break
    fi
    if ! kill -0 "$PID" 2>/dev/null; then
        echo "[smoke] FAIL: process died before binding"
        exit 1
    fi
    sleep 0.2
done

if ! ss -ltn 2>/dev/null | grep -q ":$PORT "; then
    echo "[smoke] FAIL: listener never came up"
    exit 1
fi

# 1. Root path serves dashboard HTML (intel.html is embedded).
echo "[smoke] GET /"
body="$(curl -fsS "http://127.0.0.1:$PORT/" )"
if ! grep -qi '<html' <<<"$body"; then
    echo "[smoke] FAIL: / did not return HTML"
    echo "--- body (first 500 bytes) ---"
    echo "${body:0:500}"
    exit 1
fi
echo "[smoke] OK: / returned HTML ($(wc -c <<<"$body") bytes)"

# 2. /api/intel returns JSON (may be empty on a fresh DB, but must parse).
echo "[smoke] GET /api/intel"
intel="$(curl -fsS "http://127.0.0.1:$PORT/api/intel" )"
if ! python3 -c "import json,sys; json.loads(sys.argv[1])" "$intel" 2>/dev/null; then
    echo "[smoke] FAIL: /api/intel did not return parseable JSON"
    echo "--- body (first 500 bytes) ---"
    echo "${intel:0:500}"
    exit 1
fi
echo "[smoke] OK: /api/intel returned valid JSON"

# 3. /api/intel/payloads returns the aggregated shape introduced in v1.1.
echo "[smoke] GET /api/intel/payloads"
payloads="$(curl -fsS "http://127.0.0.1:$PORT/api/intel/payloads?window=24h" )"
if ! python3 -c '
import json, sys
d = json.loads(sys.argv[1])
assert "rows" in d, "missing rows"
assert "total" in d, "missing total"
# rows may be empty on a fresh DB; that is fine.
for r in d.get("rows", []):
    # v1.1 contract: aggregated shape, occurrences must exist.
    assert "occurrences" in r, "row missing occurrences: " + str(r)
    assert "urlCount" in r, "row missing urlCount: " + str(r)
print("ok: rows=%d total=%s" % (len(d.get("rows", [])), d.get("total")))
' "$payloads"; then
    echo "[smoke] FAIL: /api/intel/payloads shape mismatch"
    echo "--- body (first 500 bytes) ---"
    echo "${payloads:0:500}"
    exit 1
fi
echo "[smoke] OK: /api/intel/payloads shape valid"

# 4. /debug/runtime returns the bounded-cache snapshot (gated by dashboardAuth,
# but no token is set in CI so it should be open).
echo "[smoke] GET /debug/runtime"
runtime="$(curl -fsS "http://127.0.0.1:$PORT/debug/runtime" )"
if ! python3 -c '
import json, sys
d = json.loads(sys.argv[1])
for k in ("heapAlloc","numGoroutines","liveJournalCollectorMax","geoCacheMax"):
    assert k in d, "missing " + k
print("ok: heap=%dKB goroutines=%d liveMax=%d geoMax=%d" % (
    d["heapAlloc"]//1024, d["numGoroutines"],
    d["liveJournalCollectorMax"], d["geoCacheMax"]))
' "$runtime"; then
    echo "[smoke] FAIL: /debug/runtime shape mismatch"
    echo "--- body (first 500 bytes) ---"
    echo "${runtime:0:500}"
    exit 1
fi
echo "[smoke] OK: /debug/runtime returned bounded-cache snapshot"

echo "[smoke] all checks passed"
