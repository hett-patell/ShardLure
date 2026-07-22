#!/usr/bin/env python3
"""Patch cowrie/shell/bashparse.py: handle subshells in pipelines.

Cowrie's parser dropped everything after a pipe that followed a subshell:
  ( echo hello ) | cat   → only the subshell ran, '| cat' was lost
  cmd | ( echo hello )   → syntax error

This patch fixes both paths so the pipe chain is preserved. The subshell's
last command gets the pipe tail appended to its items, and a subshell after
a pipe in _parse_simple is flattened into the pipeline.

Bot recon scripts use these patterns extensively in their FILTER probes.
"""
import sys
from pathlib import Path

cowrie_home = Path(sys.argv[1])
path = str(cowrie_home / "src/cowrie/shell/bashparse.py")
with open(path) as f:
    content = f.read()

# --- Fix 1: _parse_statement ---
OLD1 = """\
        # A subshell at command position runs in sequence; anything piped after
        # it is dropped (see the pipeline TODO below).
        if isinstance(node, Tree) and node.data == "subshell":
            cursor.next()
            self._skip_to_statement_end(cursor)
            return Subshell(statements=self._subshell_statements(line, node), op=op)"""

NEW1 = """\
        # A subshell at command position: parse its inner statements.
        # If a pipe follows (e.g. `( cmd1 ) | cmd2`), collect any
        # redirections on the subshell itself, then append the pipe and
        # remaining pipeline stages to the last inner command so
        # runCommand can wire up the pipe chain.
        if isinstance(node, Tree) and node.data == "subshell":
            cursor.next()
            inner = self._subshell_statements(line, node)
            # Collect any redirections attached to the subshell (e.g. 2>&1)
            redir_tokens: list[Tree | Token] = []
            while True:
                nxt = cursor.peek()
                if nxt is None:
                    break
                if self._token_type(nxt) in ("REDIR", "IO_REDIR"):
                    redir_tokens.append(cursor.next())
                    # The target word follows the redirect operator
                    target = cursor.peek()
                    if target is not None and isinstance(target, Tree) and target.data == "word":
                        redir_tokens.append(cursor.next())
                    continue
                break
            if self._token_type(cursor.peek()) == "PIPE":
                # Append the pipe tail to the last Command in the subshell
                tail_tokens = list(redir_tokens)
                while True:
                    nxt = cursor.peek()
                    if nxt is None or self._token_type(nxt) in _STATEMENT_END:
                        break
                    # Allow subshells in the pipe tail too
                    if isinstance(nxt, Tree) and nxt.data == "subshell":
                        sub_inner = self._subshell_statements(line, nxt)
                        cursor.next()
                        if sub_inner:
                            last_sub = sub_inner[-1]
                            if isinstance(last_sub, Command):
                                tail_tokens.extend(last_sub.items)
                        continue
                    tail_tokens.append(cursor.next())
                # Find the last Command in the subshell and append the pipe tail
                for i in range(len(inner) - 1, -1, -1):
                    if isinstance(inner[i], Command):
                        for t in tail_tokens:
                            if isinstance(t, str):
                                inner[i].items.append(t)
                            elif isinstance(t, Token):
                                inner[i].items.append(t.value)
                            else:
                                inner[i].items.append(t)
                        break
                return Subshell(statements=inner, op=op)
            else:
                self._skip_to_statement_end(cursor)
                return Subshell(statements=inner, op=op)"""

# --- Fix 2: _parse_simple ---
OLD2 = """\
            # A "(...)" that survived as a unit here is a subshell in the middle
            # of a command -- a bash syntax error reported on the "(" token.
            if isinstance(node, Tree) and node.data == "subshell":
                return SyntaxError_(token=self._error_token(line, node))"""

NEW2 = """\
            # A "(...)" after a pipe: flatten its last command into the pipeline
            if isinstance(node, Tree) and node.data == "subshell":
                if units and any(isinstance(u, Token) and u.type == "PIPE" for u in units):
                    sub_inner = self._subshell_statements(line, node)
                    cursor.next()
                    if sub_inner:
                        last_sub = sub_inner[-1]
                        if isinstance(last_sub, Command):
                            for item in last_sub.items:
                                if isinstance(item, str):
                                    units.append(Token("LITERAL", item))
                                elif isinstance(item, Token):
                                    units.append(item)
                                else:
                                    units.append(item)
                            continue
                return SyntaxError_(token=self._error_token(line, node))"""

# Check if already patched
if "If a pipe follows (e.g. `( cmd1 ) | cmd2`)" in content:
    print(f"  [skip] {path}: already patched")
    sys.exit(0)

if OLD1 not in content:
    print(f"  [FAIL] {path}: _parse_statement target block not found", file=sys.stderr)
    sys.exit(1)

if OLD2 not in content:
    print(f"  [FAIL] {path}: _parse_simple target block not found", file=sys.stderr)
    sys.exit(1)

content = content.replace(OLD1, NEW1)
content = content.replace(OLD2, NEW2)

with open(path, 'w') as f:
    f.write(content)
print(f"  [ok] {path}: patched")
