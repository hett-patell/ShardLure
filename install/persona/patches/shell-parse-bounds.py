#!/usr/bin/env python3
"""Patch cowrie/shell/bashparse.py: bound what one input costs the parser.

WHY (payload-yield Phase B Task 8b): Cowrie parses every command line, script
and command substitution with a Lark Earley grammar on the reactor thread, so
while one input parses every other session waits. Measured on v3.1.1 with the
ShardLure patch set (x86 here; arm is slower):

* A command substitution was parsed again each time it ran. Nested `$(`
  cost the depth times the body (8 levels around 11 KB: 23 s), and a loop
  re-parsed its body every pass: the 116-byte line
  `i=0; while true; do x=$(true w0 ... w19); done` made 1,001 parses and held
  the reactor 22 s (436 bytes: 107 s). The 189 s stall Task 8 saw live is
  this shape. A `$(...)` body now runs from the tree its enclosing line
  already produced; the differential over every `$(...)` in the harness,
  the profiler and Cowrie's own tests found no change in statements, line
  numbers or transcripts.
* A backtick body is one flat token, with no tree in its line to reuse, so
  the same line with backticks still parsed every pass (24 s). Each SSH
  connection now remembers its recent parse results (inputs up to 2 KiB,
  8 KiB in all), keyed by the exact input, and splits a repeat from the
  remembered tree: the 200-pass backtick loop went from 4.5 s to 0.26 s,
  the same as $(...). It is kept per connection, not per parser, because
  subshells, pipeline stages and substitutions each run in a new shell.
* Shape bounds alone kept missing costly inputs (each review round found
  another), so grammar time is also budgeted: PARSE_BUDGET_SECONDS (30 s)
  per connection, after which every parse that needs the grammar is
  refused at once. Whatever shape an input takes, one connection holds the
  reactor at most the budget plus one parse (the 10 s parse timeout).
* ~200 levels of "(", "{" or if raised RecursionError out of lineReceived
  (128 levels of `$(` raised one while evaluating), and nested case clauses
  are superlinear in the grammar itself (64 levels, 1.2 KB: 5.8 s). Input
  nested deeper than MAX_NESTING_DEPTH (16) is refused by a linear scan
  before the grammar runs; production's deepest input in 28,479 commands and
  104 captured scripts nests 6 levels.
* Nesting the scan does not count (if, while, `{ }`) parses in linear time
  but can still exhaust the stack; that RecursionError now fails the one
  parse instead of escaping into the protocol.

Refusals answer as bash answers an unclosed "( (" group, "syntax error:
unexpected end of file" with status 2: the reply Cowrie already gives an
oversized or timed-out parse, so a refusal is no new kind of answer. Nothing
is ever executed.
"""
import sys
from pathlib import Path

OLD_LIMITS = r'''    return CowrieConfig.getfloat("shell", "parse_timeout_seconds", fallback=10.0)


_HAS_PARSE_ALARM = all(
'''

NEW_LIMITS = r'''    return CowrieConfig.getfloat("shell", "parse_timeout_seconds", fallback=10.0)


# ShardLure (shell-parse-bounds.py): how deeply "(", "$(", backtick bodies and
# case clauses may nest in one input before it is refused without parsing.
# Every level costs a recursion in the statement splitter and in the
# substitution runtime, and nested case clauses are superlinear in the Earley
# grammar itself (64 levels, 1.2 KB: 5.8 s on the reactor thread). Unbounded,
# ~200 levels raised a RecursionError out of lineReceived. Production's deepest
# input in 28,479 commands and 104 captured scripts was 6 levels (the recurring
# 3-12 KB profiler); 16 leaves that 10 levels of headroom.
MAX_NESTING_DEPTH = 16

# Grammar time one SSH connection may spend, summed over its channels and the
# child shells its subshells, pipelines and substitutions run in. Shape bounds
# alone kept missing inputs (a review found a new costly shape per round); this
# bounds them all: past it every parse that needs the grammar is refused at
# once. A connection that spends it has held the reactor 30 s; a 16 KiB
# dropper script, the largest input [shell] max_input_size admits, costs 4-7 s
# on arm, and a bot's ordinary commands milliseconds.
PARSE_BUDGET_SECONDS = 30.0

# Parse results a connection remembers, keyed by the exact input: a loop runs
# the same backtick body, and the same line, every pass, and a backtick body is
# one flat token with no tree in its line to reuse the way a "$(...)" body
# does (the 104-byte `while` line with backticks parsed 1,000 times: 24 s).
# Only inputs up to PARSE_MEMO_ENTRY_CHARS are kept, PARSE_MEMO_CHARS in all:
# a tree holds 500-680 bytes per input character, so this is ~5 MB at most.
PARSE_MEMO_ENTRIES = 64
PARSE_MEMO_ENTRY_CHARS = 2048
PARSE_MEMO_CHARS = 8192

from time import perf_counter as _parse_clock

_NEST_WORD_BREAK = frozenset(" \t\r\n;&|<>()")
# A case clause opens at "case" and a blank at a word start, closed by "esac"
# as a whole word. The head's WORD is not read: the grammar takes any word
# there, quoted, "$(x)" or after a "\\"-newline, and a narrower head let
# 64 nested `case "a b" in` levels through (7.8 s). A "case" that never
# closes is read as a word on a second pass (nesting_too_deep).
_NEST_CASE_HEAD = re.compile(r"case(?:[ \t]|\\\r?\n)")
_NEST_ESAC = re.compile(r"esac(?![^ \t\r\n;&|<>()])")


def _nesting_scan(text: str, ignore: frozenset[int]) -> tuple[int, set[int]]:
    """One linear pass over ``text`` with the grammar's quoting rules.

    Returns the deepest nesting of "(", "$(", backtick bodies and case clauses,
    and the offsets of case heads that no "esac" closed (the grammar reads
    those as plain words). Heads at offsets in ``ignore`` are read as words.
    """
    deepest = 0
    unclosed: set[int] = set()
    # (start, end, depth) spans: a backtick body is scanned as its own input,
    # one level deeper, from this work list, so the scan never recurses.
    spans = [(0, len(text), 0)]
    while spans:
        pos, end, depth = spans.pop()
        # ("(", 0) group, ("$(", 0) substitution, ('"', 0) double quote,
        # ("case", offset) case clause.
        stack: list[tuple[str, int]] = []
        word_start = True
        while pos < end:
            if depth > deepest:
                deepest = depth
            ch = text[pos]
            top = stack[-1][0] if stack else ""
            if ch == "\\":
                # The grammar reads "\\"-newline as a blank (a case head may
                # follow it); any other escaped byte continues the word.
                if text.startswith("\n", pos + 1) or text.startswith("\r\n", pos + 1):
                    pos += 2 if text[pos + 1] == "\n" else 3
                    word_start = True
                else:
                    pos += 2
                    word_start = False
                continue
            if ch == "`":
                close = text.find("`", pos + 1, end)
                if close < 0:
                    break
                spans.append((pos + 1, close, depth + 1))
                pos = close + 1
                word_start = False
                continue
            if ch == "$" and text.startswith("$(", pos):
                stack.append(("$(", 0))
                depth += 1
                pos += 2
                word_start = True
                continue
            if top == '"':
                if ch == '"':
                    stack.pop()
                pos += 1
                continue
            if ch == "'":
                close = text.find("'", pos + 1, end)
                if close < 0:
                    break
                pos = close + 1
                word_start = False
                continue
            if ch == '"':
                stack.append(('"', 0))
                pos += 1
                word_start = False
                continue
            if ch == "#" and word_start:
                newline = text.find("\n", pos, end)
                pos = end if newline < 0 else newline
                continue
            if ch == "(":
                stack.append(("(", 0))
                depth += 1
                pos += 1
                word_start = True
                continue
            if ch == ")":
                # Inside a case clause a ")" may close a pattern, which opened
                # nothing; it only closes a group the scan saw open. A "$(...)"
                # is part of a word, so a "#" right after it continues the
                # word (`$(x)#` prints "#"); reading it as a comment hid the
                # rest of the line from the scan.
                pos += 1
                if top in ("(", "$("):
                    stack.pop()
                    depth -= 1
                    word_start = top == "("
                else:
                    word_start = True
                continue
            if (
                word_start
                and ch == "c"
                and pos not in ignore
                and _NEST_CASE_HEAD.match(text, pos, end)
            ):
                stack.append(("case", pos))
                depth += 1
                pos += 4
                word_start = False
                continue
            if word_start and ch == "e" and top == "case" and _NEST_ESAC.match(text, pos, end):
                stack.pop()
                depth -= 1
                pos += 4
                word_start = False
                continue
            word_start = ch in _NEST_WORD_BREAK
            pos += 1
        if depth > deepest:
            deepest = depth
        unclosed.update(offset for kind, offset in stack if kind == "case")
    return deepest, unclosed


def nesting_too_deep(text: str, limit: int = MAX_NESTING_DEPTH) -> bool:
    """Whether ``text`` nests groups deeper than ``limit``: a linear scan, run
    before the grammar so a refused input costs milliseconds, not the parse.
    A "case WORD in" that never closes is a word to the grammar, so a second
    pass reads it as one rather than as a level (`echo case x in y` repeated
    must not be refused)."""
    deepest, unclosed = _nesting_scan(text, frozenset())
    if unclosed:
        # Always, not only when the first pass found deep nesting: while an
        # unclosed head was on its stack, a pattern-like ")" closed nothing
        # and a "#" after it read as a comment, hiding the rest of the line.
        deepest, _ = _nesting_scan(text, frozenset(unclosed))
    return deepest > limit


_HAS_PARSE_ALARM = all(
'''

OLD = r'''        previous "unexpected end of file" fallback.
        """
        timed_out = False
        try:
            with _parse_alarm(parse_timeout_seconds()):
                tree = _parser.parse(line)
        except UnexpectedCharacters as error:
            return [
                SyntaxError_(
                    token=self._unexpected_char(line, error), lineno=error.line
                )
            ]
        except LarkError:
            return [SyntaxError_(token="", lineno=self._end_line(line))]
        except ParseTimeoutError:
            timed_out = True
            self._log.warn(
                "Shell parse exceeded {timeout}s (input: {length} characters)",
                timeout=parse_timeout_seconds(),
                length=len(line),
            )
            return [SyntaxError_(token="", lineno=self._end_line(line))]
        finally:
            if timed_out or len(line) >= gc_collect_threshold():
                gc.collect()
        return self._split_statements(line, tree)
'''

NEW = r'''        previous "unexpected end of file" fallback.

        ShardLure (shell-parse-bounds.py): the shell parses on the reactor
        thread, so one input's parse stalls every session. A ``$(...)`` body
        the evaluator is about to run is split from the tree its enclosing
        line already produced (see _substitute), never parsed again. Input
        nested deeper than MAX_NESTING_DEPTH is refused before the grammar
        runs, an input this connection parsed recently is split from its
        remembered tree (or answered its remembered syntax error) instead of
        parsed again, a connection past PARSE_BUDGET_SECONDS of grammar time
        is refused, and a RecursionError, from nesting the scan does not count
        (if/while/{ ...; }), fails this parse instead of escaping into the
        protocol. All three answer as bash answers an unclosed "( (" group:
        "syntax error: unexpected end of file", status 2, the reply Cowrie
        already gives an oversized or timed-out parse.
        """
        reused, self._reuse = self._reuse, None
        if reused is not None and reused[0] is line:
            return self._split_reused(reused[0], reused[1], reused[2])
        remembered = self._memo_lookup(line)
        if remembered is not None:
            return remembered
        if nesting_too_deep(line):
            self._log.warn(
                "Shell parse refused: groups nested deeper than {limit}"
                " (input: {length} characters)",
                limit=MAX_NESTING_DEPTH,
                length=len(line),
            )
            return [SyntaxError_(token="", lineno=self._end_line(line))]
        state = self._connection_state()
        if state["spent"] >= PARSE_BUDGET_SECONDS:
            if not state["warned"]:
                state["warned"] = True
                self._log.warn(
                    "Shell parse refused: this connection spent its {budget}s"
                    " parse budget",
                    budget=PARSE_BUDGET_SECONDS,
                )
            return [SyntaxError_(token="", lineno=self._end_line(line))]
        timed_out = False
        started = _parse_clock()
        try:
            with _parse_alarm(parse_timeout_seconds()):
                tree = _parser.parse(line)
        except UnexpectedCharacters as error:
            return self._memo_error(
                line, self._unexpected_char(line, error), error.line
            )
        except LarkError:
            return self._memo_error(line, "", self._end_line(line))
        except ParseTimeoutError:
            timed_out = True
            self._log.warn(
                "Shell parse exceeded {timeout}s (input: {length} characters)",
                timeout=parse_timeout_seconds(),
                length=len(line),
            )
            return [SyntaxError_(token="", lineno=self._end_line(line))]
        except RecursionError:
            self._log.warn(
                "Shell parse hit the recursion limit (input: {length} characters)",
                length=len(line),
            )
            return [SyntaxError_(token="", lineno=self._end_line(line))]
        finally:
            state["spent"] += _parse_clock() - started
            if timed_out or len(line) >= gc_collect_threshold():
                gc.collect()
        try:
            statements = self._split_statements(line, tree)
        except RecursionError:
            self._log.warn(
                "Shell parse hit the recursion limit (input: {length} characters)",
                length=len(line),
            )
            return [SyntaxError_(token="", lineno=self._end_line(line))]
        self._memo_put(line, tree)
        return statements
'''

OLD_LINES = r'''    @staticmethod
    def _end_line(line: str) -> int:
        """The line bash reports an unexpected end of input on: the one after
        the last."""
        return len(line.rstrip("\n").split("\n")) + 1

    @staticmethod
    def _node_line(node: Tree | Token | None) -> int:
        """The 1-based source line a grammar node starts on, or 0."""
        if isinstance(node, Token):
            return node.line or 0
        if isinstance(node, Tree) and not node.meta.empty:
            return node.meta.line
        return 0
'''

NEW_LINES = r'''    # ShardLure (shell-parse-bounds.py): while _split_reused splits a $(...)
    # body out of its enclosing line's tree, line numbers count from the
    # body's first line and the input ends where the body ends, exactly as a
    # fresh parse of the body numbered them, so the "line N:" of its errors
    # is unchanged.
    _reuse: tuple[str, str, Tree] | None = None
    _line_shift = 0
    _reuse_end: int | None = None

    def _end_line(self, line: str) -> int:
        """The line bash reports an unexpected end of input on: the one after
        the last."""
        if self._reuse_end is not None:
            return self._reuse_end
        return len(line.rstrip("\n").split("\n")) + 1

    def _node_line(self, node: Tree | Token | None) -> int:
        """The 1-based source line a grammar node starts on, or 0."""
        if isinstance(node, Token):
            raw = node.line or 0
        elif isinstance(node, Tree) and not node.meta.empty:
            raw = node.meta.line
        else:
            return 0
        return raw - self._line_shift if raw else 0

    def _connection_state(self) -> dict:
        """Parse budget and memo shared by everything one SSH connection runs.

        Every channel gets its own protocol, and every subshell, pipeline
        stage and substitution its own shell and parser, so state kept on the
        parser was reset by `( ... )` or `echo | ...` (a review put the 24 s
        backtick loop back that way). The connection's server object outlives
        them all; without one (tests, other contexts) the protocol, then this
        parser, holds it."""
        protocol = getattr(self.context, "protocol", None)
        owner = getattr(getattr(protocol, "user", None), "server", None)
        for holder in (owner, protocol, self):
            if holder is None:
                continue
            state = getattr(holder, "_shardlure_parse", None)
            if state is not None:
                return state
            state = {"memo": {}, "chars": 0, "spent": 0.0, "warned": False}
            try:
                holder._shardlure_parse = state
            except AttributeError:
                continue
            return state
        return {"memo": {}, "chars": 0, "spent": 0.0, "warned": False}

    def _memo_lookup(self, line: str) -> list[Statement] | None:
        """What parse(line) answered last time, if this connection remembers
        it: statements split afresh from the remembered tree (the evaluator
        mutates statements, never the tree), or the same syntax error. Only
        answers that depend on the input alone are remembered, never a
        timeout or the recursion limit (load and stack depth decide those)."""
        if len(line) > PARSE_MEMO_ENTRY_CHARS:
            return None
        hit = self._connection_state()["memo"].get(line)
        if hit is None:
            return None
        if isinstance(hit, tuple):
            return [SyntaxError_(token=hit[0], lineno=hit[1])]
        try:
            return self._split_statements(line, hit)
        except RecursionError:
            return [SyntaxError_(token="", lineno=self._end_line(line))]

    def _memo_put(self, line: str, entry: Tree | tuple[str, int]) -> None:
        if len(line) > PARSE_MEMO_ENTRY_CHARS:
            return
        state = self._connection_state()
        memo = state["memo"]
        if line in memo:
            return
        while memo and (
            len(memo) >= PARSE_MEMO_ENTRIES
            or state["chars"] + len(line) > PARSE_MEMO_CHARS
        ):
            oldest = next(iter(memo))
            del memo[oldest]
            state["chars"] -= len(oldest)
        memo[line] = entry
        state["chars"] += len(line)

    def _memo_error(self, line: str, token: str, lineno: int) -> list[Statement]:
        self._memo_put(line, (token, lineno))
        return [SyntaxError_(token=token, lineno=lineno)]

    def _split_reused(self, source: str, line: str, body: Tree) -> list[Statement]:
        """The statements of a ``$(...)`` body, from the ``start`` tree the
        grammar built for it inside ``line``: what parse(source) returns, with
        the word trees still pointing into ``line``."""
        self._line_shift = line.count("\n", 0, body.meta.start_pos)
        self._reuse_end = len(source.rstrip("\n").split("\n")) + 1
        try:
            return self._split_statements(line, body)
        except RecursionError:
            return [SyntaxError_(token="", lineno=self._reuse_end)]
        finally:
            self._line_shift = 0
            self._reuse_end = None
'''

OLD_ATOM = r'''        if atom.data == "cmdsub":
            return await self.context.command_substitution(
                self._group_source(line, atom)
            )
        if atom.data == "backtick":
'''

NEW_ATOM = r'''        if atom.data == "cmdsub":
            return await self._substitute(line, atom)
        if atom.data == "backtick":
'''

OLD_DQ = r'''            elif part.data == "cmdsub":
                parts.append(
                    await self.context.command_substitution(
                        self._group_source(line, part)
                    )
                )
            elif part.data == "backtick":
                parts.append(
                    await self.context.command_substitution(
                        self._backtick_source(line, part)
                    )
                )
        return "".join(parts)
'''

NEW_DQ = r'''            elif part.data == "cmdsub":
                parts.append(await self._substitute(line, part))
            elif part.data == "backtick":
                parts.append(
                    await self.context.command_substitution(
                        self._backtick_source(line, part)
                    )
                )
        return "".join(parts)

    def _substitute(self, line: str, node: Tree) -> Awaitable[str]:
        """Run a ``$(...)`` through the context's command_substitution.

        ShardLure (shell-parse-bounds.py): the body was parsed with the
        enclosing line, so its tree is handed to the parse() that the
        substitution makes instead of the Earley parser reading the same text
        again. A re-parse per evaluation made the cost the nesting depth
        times the body (8 levels around 11 KB: 23 s) and every loop pass
        (a 116-byte `while` line: 1,001 parses, 22 s), all on the reactor.
        """
        source = self._group_source(line, node)
        body = next(
            (
                child
                for child in node.children
                if isinstance(child, Tree) and child.data == "start"
            ),
            None,
        )
        if source and body is not None:
            self._reuse = (source, line, body)
        try:
            return self.context.command_substitution(source)
        finally:
            self._reuse = None
'''


BLOCKS = (
    (OLD_LIMITS, NEW_LIMITS),
    (OLD, NEW),
    (OLD_LINES, NEW_LINES),
    (OLD_ATOM, NEW_ATOM),
    (OLD_DQ, NEW_DQ),
)


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/shell/bashparse.py"
    content = path.read_text(encoding="utf-8")
    counts = [(content.count(old), content.count(new)) for old, new in BLOCKS]
    if all(c == (0, 1) for c in counts):
        print(f"  [skip] {path}: already patched")
        return 0
    if not all(c == (1, 0) for c in counts):
        print(
            f"  [FAIL] {path}: target is neither pristine nor fully patched "
            f"(old/new counts {counts}) - upstream bashparse changed",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    for old, new in BLOCKS:
        content = content.replace(old, new, 1)
    path.write_text(content, encoding="utf-8")
    print(f"  [ok] {path}: patched (parse once per substitution, nesting bound)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
