#!/usr/bin/env python3
"""Patch cowrie/commands/awk.py: comparison patterns (`FNR == 2 {...}`) and FNR.

WHY (payload-yield Phase B Task 7; factsheet-phaseB 3 #17): v3.1.1's awk
parses only `/regex/ {action}` rules. The disk probe
`df -h | head -n 2 | awk 'FNR == 2 {print $2;}'` (35 sessions in 30 days)
is a comparison pattern, so the parser stopped at "FNR", no rule ran, and the
probe printed nothing where a real box prints the root fs size. Bots use the
same form for `NR==2`, `NR>1` (skip a header) and `$1 == "x"`.

A rule may now carry one comparison as its pattern: operands NR, FNR, NF,
$N, $NF, a number or a string constant; operators == != < <= > >=. Values
compare as mawk (22.04's awk) compares them: numerically when both sides look
numeric (a field is a "strnum"), else as strings, so `$2 > 9` is true for a
field "b". FNR restarts at each input file; `print` accepts FNR too. Checked
against ubuntu:22.04 mawk (scripts/behaviour awk-patterns).
"""
import sys
from pathlib import Path

OLD = r'''        code = []
        rule = re.compile(
            r"\s*(?:/(?P<pattern>(?:\\.|[^/\\])*)/)?\s*(?:\{(?P<code>[^}]*)\})?\s*;?"
        )
        pos = 0
        while pos < len(program):
            m = rule.match(program, pos)
            if not m or m.end() == pos:
                break
            if m.group("pattern") is not None or m.group("code") is not None:
                # A pattern without an action prints the matching line.
                action = m.group("code") if m.group("code") is not None else "print"
                code.append({"regex": m.group("pattern") or "", "code": action})
            pos = m.end()
        return code
'''

NEW = r'''        code = []
        # ShardLure (install/persona/patches/awk-patterns.py): a rule's pattern
        # may also be one comparison (`FNR == 2`, `NR>1`, `$1 == "x"`).
        operand = self._SHARDLURE_OPERAND
        rule = re.compile(
            r"\s*(?:/(?P<pattern>(?:\\.|[^/\\])*)/"
            r"|(?P<expr>" + operand + r"\s*(?:==|!=|<=|>=|<|>)\s*" + operand + r"))?"
            r"\s*(?:\{(?P<code>[^}]*)\})?\s*;?"
        )
        pos = 0
        while pos < len(program):
            m = rule.match(program, pos)
            if not m or m.end() == pos:
                break
            if (m.group("pattern") is not None or m.group("expr") is not None
                    or m.group("code") is not None):
                # A pattern without an action prints the matching line.
                action = m.group("code") if m.group("code") is not None else "print"
                code.append({"regex": m.group("pattern") or "",
                             "expr": m.group("expr") or "", "code": action})
            pos = m.end()
        return code

    _SHARDLURE_OPERAND = r'(?:FNR|NR|NF|\$(?:NF|\d+)|"(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?)'

    def _shardlure_value(self, token: str, line: str, fields: list[str]):
        """(number or None, string) for an awk operand. Constants keep their
        type; a field is a strnum, numeric only if it looks like a number."""
        if token.startswith('"'):
            return None, re.sub(
                r"\\(.)", lambda e: _STRING_ESCAPES.get(e.group(1), e.group(1)), token[1:-1]
            )
        if token in ("NR", "FNR", "NF"):
            n = {"NR": self.record_number, "FNR": getattr(self, "_shardlure_fnr", 0),
                 "NF": len(fields)}[token]
            return float(n), str(n)
        if token.startswith("$"):
            index = len(fields) if token == "$NF" else int(token[1:])
            text = line if index == 0 else (fields[index - 1] if index <= len(fields) else "")
            try:
                return float(text), text
            except ValueError:
                return None, text
        return float(token), token

    def _shardlure_compare(self, expr: str, line: str, fields: list[str]) -> bool:
        operand = self._SHARDLURE_OPERAND
        m = re.fullmatch(
            r"\s*(" + operand + r")\s*(==|!=|<=|>=|<|>)\s*(" + operand + r")\s*", expr
        )
        if not m:
            return False
        (ln, ls), op, (rn, rs) = (self._shardlure_value(m.group(1), line, fields), m.group(2),
                                  self._shardlure_value(m.group(3), line, fields))
        a, b = (ln, rn) if ln is not None and rn is not None else (ls, rs)
        return {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b,
                ">": a > b, ">=": a >= b}[op]
'''

OLD_LOOP = r'''        for inputline in inputlines:
            self.record_number += 1
            fields = self.split_fields(inputline)
            for c in self.code:
                try:
                    if c["regex"] and not re.search(c["regex"], inputline):
                        continue
                except re.error:
                    continue
'''

NEW_LOOP = r'''        for inputline in inputlines:
            self.record_number += 1
            # ShardLure (awk-patterns.py): FNR, the record number in this file.
            self._shardlure_fnr = getattr(self, "_shardlure_fnr", 0) + 1
            fields = self.split_fields(inputline)
            for c in self.code:
                try:
                    if c["regex"] and not re.search(c["regex"], inputline):
                        continue
                except re.error:
                    continue
                if c.get("expr") and not self._shardlure_compare(c["expr"], inputline, fields):
                    continue
'''

OLD_FILE = r'''                try:
                    contents = self.fs.file_contents(pname)
                    self.output(contents)
                except FileNotFound:
                    self.errorWrite(f"awk: {arg}: No such file or directory\n")
'''

NEW_FILE = r'''                try:
                    contents = self.fs.file_contents(pname)
                    # ShardLure (awk-patterns.py): FNR restarts per file.
                    self._shardlure_fnr = 0
                    self.output(contents)
                except FileNotFound:
                    self.errorWrite(f"awk: {arg}: No such file or directory\n")
'''

OLD_TERM = r'''        term = re.compile(r'\s*(\$NF|\$\d+|NR|NF|"(?:\\.|[^"\\])*"|\d+|,)')
'''

NEW_TERM = r'''        # ShardLure (awk-patterns.py): FNR as well.
        term = re.compile(r'\s*(\$NF|\$\d+|FNR|NR|NF|"(?:\\.|[^"\\])*"|\d+|,)')
'''

# Up to the NF branch, so the FNR branch NEW inserts breaks OLD apart.
OLD_NR = r'''            elif token == "NR":
                current += str(self.record_number)
            elif token == "NF":
'''

NEW_NR = r'''            elif token == "NR":
                current += str(self.record_number)
            elif token == "FNR":
                current += str(getattr(self, "_shardlure_fnr", 0))
            elif token == "NF":
'''

BLOCKS = ((OLD, NEW), (OLD_LOOP, NEW_LOOP), (OLD_FILE, NEW_FILE), (OLD_TERM, NEW_TERM),
          (OLD_NR, NEW_NR))


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/commands/awk.py"
    content = path.read_text(encoding="utf-8")
    counts = [(content.count(old), content.count(new)) for old, new in BLOCKS]
    if all(c == (0, 1) for c in counts):
        print(f"  [skip] {path}: already patched")
        return 0
    if not all(c == (1, 0) for c in counts):
        print(
            f"  [FAIL] {path}: target is neither pristine nor fully patched "
            f"(old/new counts {counts}) - upstream awk changed",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    for old, new in BLOCKS:
        content = content.replace(old, new, 1)
    path.write_text(content, encoding="utf-8")
    print(f"  [ok] {path}: patched (comparison patterns, FNR)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
