#!/usr/bin/env bash
# Normalize all repository text to UTF-8 + LF (fixes UTF-16LE / NUL / CRLF corruption).
# Thin wrapper: the repair logic lives in scripts/lib/repair_text.py (shared
# with fix-go-sources.sh and vps-finish.sh so the copies can't drift again).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 "$(dirname "$0")/lib/repair_text.py" --root "$ROOT" --mode all
