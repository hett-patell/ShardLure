#!/usr/bin/env python3
"""Repair NUL/UTF-16/CRLF corruption in repository text files.

Single canonical implementation shared by fix-go-sources.sh,
repair-text.sh and vps-finish.sh — the previous four embedded copies
drifted independently and two of them rotted into real bugs (a Python
precedence bug that rewrote every clean file, and a shell-quoting
corruption that crashed on the remote).

Modes select the file set and the touch policy:

  go      *.go everywhere + go.mod/go.sum at the root. Decodes with
          errors="ignore" (a corrupted Go file must end up compilable).
          Rewrites whenever normalization changed the bytes.
  deploy  the source/text extensions a tar/scp push ships. Only touches
          files showing corruption markers (NUL bytes or UTF-16 BOM) —
          clean files are left byte-identical.
  all     full repository normalization: wide text-suffix table,
          UTF-16LE heuristic (no BOM), stray-control-char stripping,
          exec-bit preservation. Skips undecodable files with a warning.

Callers that run on a remote host should sanitize THIS file first (it
may itself be transfer-corrupted): strip b"\\x00", b"\\xff\\xfe" and CRLF
before invoking — see fix-go-sources.sh for the one-liner.
"""

import argparse
import stat
import sys
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__"}

DEPLOY_SUFFIXES = {".go", ".mod", ".sum", ".py", ".sh", ".yaml", ".yml", ".md"}
DEPLOY_NAMES = {"go.mod", "go.sum", "Makefile"}

ALL_SUFFIXES = {
    ".go", ".sh", ".py", ".md", ".yaml", ".yml", ".html", ".toml", ".cfg",
    ".conf", ".txt", ".env", ".journal", ".sum", ".mod", ".json", ".attrs",
}
ALL_NAMES = {
    "Makefile", "LICENSE", "go.mod", "go.sum", ".gitignore", ".gitattributes",
    "shardlure", "ci.yml",
}
BINARY_SUFFIXES = {".db", ".png", ".jpg", ".jpeg", ".gif", ".zip", ".gz", ".exe"}


def is_text_path_all(p: Path) -> bool:
    if p.suffix.lower() in BINARY_SUFFIXES:
        return False
    if p.suffix.lower() in ALL_SUFFIXES:
        return True
    if p.name in ALL_NAMES:
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


def decode_text(b: bytes, lenient: bool) -> str:
    errors = "ignore" if lenient else "strict"
    if b.startswith(b"\xff\xfe"):
        return b[2:].decode("utf-16-le", errors=errors)
    if b.startswith(b"\xfe\xff"):
        return b[2:].decode("utf-16-be", errors=errors)
    if not lenient and looks_utf16_le(b):
        return b.decode("utf-16-le", errors=errors)
    if b"\x00" in b:
        b = b.replace(b"\x00", b"")
    return b.decode("utf-8", errors=errors)


def normalize(s: str, strip_controls: bool) -> str:
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    if strip_controls:
        # strip stray control chars except tab/newline
        s = "".join(ch if ch in "\n\t" or ord(ch) >= 32 else "" for ch in s)
    if s and not s.endswith("\n"):
        s += "\n"
    return s


def corrupted(b: bytes) -> bool:
    return b"\x00" in b or b.startswith((b"\xff\xfe", b"\xfe\xff"))


def iter_candidates(root: Path, mode: str):
    if mode == "go":
        yield from sorted(root.rglob("*.go"))
        for name in ("go.mod", "go.sum"):
            p = root / name
            if p.exists():
                yield p
        return
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if SKIP_DIRS & set(p.parts):
            continue
        if mode == "deploy":
            if p.suffix in DEPLOY_SUFFIXES or p.name in DEPLOY_NAMES:
                yield p
        else:  # all
            if is_text_path_all(p):
                yield p


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", required=True, type=Path)
    ap.add_argument("--mode", required=True, choices=("go", "deploy", "all"))
    args = ap.parse_args()
    root = args.root.resolve()
    mode = args.mode

    fixed = 0
    for p in iter_candidates(root, mode):
        if SKIP_DIRS & set(p.parts):
            continue
        raw = p.read_bytes()
        if not raw:
            continue
        # deploy mode only touches provably-corrupted files so a re-run
        # over a clean tree is a byte-for-byte no-op.
        if mode == "deploy" and not corrupted(raw):
            continue
        try:
            text = decode_text(raw, lenient=(mode == "go"))
        except UnicodeDecodeError:
            print("SKIP (not decodable):", p.relative_to(root))
            continue
        out = normalize(text, strip_controls=(mode == "all"))
        if out.encode("utf-8") == raw:
            continue
        mode_bits = p.stat().st_mode
        p.write_text(out, encoding="utf-8", newline="\n")
        if mode_bits & stat.S_IXUSR:
            p.chmod(mode_bits | 0o111)
        print("repaired", p.relative_to(root))
        fixed += 1

    if fixed == 0:
        print("no corrupted text files found")
    else:
        print(f"repaired {fixed} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
