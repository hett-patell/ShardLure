#!/usr/bin/env bash
# Normalize all repository text to UTF-8 + LF (fixes UTF-16LE / NUL / CRLF corruption).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$ROOT" python3 - <<'PY'
import os
import stat
from pathlib import Path

root = Path(os.environ["ROOT"])
SKIP_DIRS = {".git", "node_modules", "vendor"}
TEXT_SUFFIXES = {
    ".go", ".sh", ".py", ".md", ".yaml", ".yml", ".html", ".toml", ".cfg",
    ".conf", ".txt", ".env", ".journal", ".sum", ".mod", ".json", ".attrs",
}
TEXT_NAMES = {
    "Makefile", "LICENSE", "go.mod", "go.sum", ".gitignore", ".gitattributes",
    "shardlure", "ci.yml",
}
BINARY_SUFFIXES = {".db", ".png", ".jpg", ".jpeg", ".gif", ".zip", ".gz", ".exe"}


def is_text_path(p: Path) -> bool:
    if p.suffix.lower() in BINARY_SUFFIXES:
        return False
    if p.suffix.lower() in TEXT_SUFFIXES:
        return True
    if p.name in TEXT_NAMES:
        return True
    if p.parent.name == "workflows" and p.suffix == ".yml":
        return True
    # persona bait / honeyfs / testdata
    parts = set(p.parts)
    if "persona" in parts or "testdata" in parts or "install" in parts:
        if p.suffix in {".cfg", ".conf", ".txt", ".env", ".yml", ".yaml", ""} or "bait" in parts:
            if p.suffix.lower() not in BINARY_SUFFIXES:
                return True
    return False


def looks_utf16_le(b: bytes) -> bool:
    if len(b) < 4:
        return False
    if b.startswith(b"\xff\xfe"):
        return True
    sample = b[: min(800, len(b))]
    odd_nulls = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)
    even_nulls = sum(1 for i in range(0, len(sample), 2) if sample[i] == 0)
    return odd_nulls > 30 and even_nulls < 8


def decode_text(b: bytes) -> str:
    if b.startswith(b"\xff\xfe"):
        return b[2:].decode("utf-16-le")
    if b.startswith(b"\xfe\xff"):
        return b[2:].decode("utf-16-be")
    if looks_utf16_le(b):
        return b.decode("utf-16-le")
    if b"\x00" in b:
        b = b.replace(b"\x00", b"")
    return b.decode("utf-8")


def normalize(s: str) -> str:
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    # strip stray control chars except tab/newline
    s = "".join(ch if ch in "\n\t" or ord(ch) >= 32 else "" for ch in s)
    if s and not s.endswith("\n"):
        s += "\n"
    return s


repaired = 0
for p in sorted(root.rglob("*")):
    if not p.is_file():
        continue
    if SKIP_DIRS & set(p.parts):
        continue
    if not is_text_path(p):
        continue
    raw = p.read_bytes()
    if not raw:
        continue
    try:
        text = decode_text(raw)
    except UnicodeDecodeError:
        print("SKIP (not decodable):", p)
        continue
    out = normalize(text)
    if out.encode("utf-8") == raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n"):
        continue
    mode = p.stat().st_mode
    p.write_text(out, encoding="utf-8", newline="\n")
    if mode & stat.S_IXUSR:
        p.chmod(mode | 0o111)
    print("repaired", p)
    repaired += 1

print(f"done ({repaired} files changed)")
PY
