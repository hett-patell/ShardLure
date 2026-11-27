#!/usr/bin/env python3
"""Patch cowrie/shell/bashparse.py: bound what one input costs the parser.

WHY (payload-yield Phase B Task 8b, re-anchored on Cowrie v3.1.8): Cowrie
parses every command line, script, command substitution and here-document
body with a Lark Earley grammar on the reactor thread, so while one input
parses every other session waits. Measured with the ShardLure patch set (x86;
arm is slower):

* A command substitution is parsed again each time it runs. Nested `$(` cost
  the depth times the body (8 levels around 11 KB: 23 s on v3.1.1), and a
  loop re-parsed its body every pass: the 116-byte line
  `i=0; while true; do x=$(true w0 ... w19); done` made 1,001 parses and held
  the reactor 22 s. v3.1.8 still re-parses (stock v3.1.8: the harness's
  parse-loop-* cases take 5.7-5.8 s against their 3-4 s limits). A `$(...)`
  body now runs from the tree its enclosing line, or here-document body,
  already produced (_substitute, at all three sites: a word, a double-quoted
  part, a here-document body). Only when the body would parse the same way on
  its own: one that holds a here-document or ends inside a line continuation
  is parsed afresh, as stock does.
* A backtick body is one flat token, with no tree in its line to reuse. Each
  SSH connection remembers its recent grammar results (inputs up to 2 KiB,
  8 KiB in all), keyed by the exact input and grammar rule, and answers a
  repeat from the remembered tree or syntax error: the 200-pass backtick loop
  went from 4.5 s to 0.26 s. It is kept per connection, not per parser,
  because subshells, pipeline stages and substitutions each run in a new
  shell. A timeout or a recursion failure is never remembered (load and stack
  depth decide those, not the input).
* Shape bounds alone kept missing costly inputs, so grammar time is also
  budgeted: PARSE_BUDGET_SECONDS (30 s) per connection, after which every
  input that needs the grammar is refused at once. Whatever shape an input
  takes, one connection spends at most the budget plus one parse (the 10 s
  parse timeout) in the grammar. It bounds grammar time only, not the time
  spent running what parsed.
* v3.1.8 reads multi-line input like bash: a line-fed shell (interactive, or
  `bash` reading the channel's stdin) joins each new line onto a construct
  still open (an `if` without its `fi`) and parses the whole pending text
  again, up to [shell] max_input_size, so N lines cost N(N+1)/2 lines of
  grammar, and lines that queued while one parsed run back to back in one
  reactor turn: 100 lines of 80 B held every other session 39.6 s (37 s with
  only the budget). When the earlier text ended at a clean line boundary
  (nothing lexically open, no here-document), its tree is remembered and only
  the new lines are parsed (_extend_pending): the same 100 lines finish in
  2.9 s, 2.25 s of it the client's own pacing, and another session waits at
  most 0.57 s. Every parse, extended or whole, is charged to the budget.
* ~200 levels of "(", "{" or if raise RecursionError, and nested case clauses
  are superlinear in the grammar itself (64 levels, 1.2 KB: 5.8 s). Input
  nested deeper than MAX_NESTING_DEPTH (16) is refused by a linear scan of
  the pre-scanner's stripped text (here-document bodies lifted out) before
  the grammar runs; production's deepest input in 28,479 commands and 104
  captured scripts nests 6 levels. A here-document body is scanned only when
  it holds a `$(` or backtick, since its plain parentheses are text.
* Nesting the scan does not count (if, while, `{ }`) parses in linear time
  but can still exhaust the stack; that RecursionError, in the grammar or in
  the statement splitter, fails the one parse instead of escaping into the
  protocol.

Every refusal raises ParseRefusedError, a ParseTimeoutError, from _lark_parse,
so it takes the path stock v3.1.8 already gives a timed-out parse: a command
line answers bash's "syntax error: unexpected end of file" with status 2, and a
here-document body is used as written. A refusal is no new kind of answer.
Nothing is ever executed.
"""
import sys
from pathlib import Path

# The parse-timeout helper and the alarm guard after it: the constants, the
# nesting scan and ParseRefusedError go between them.
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

# Grammar time one SSH connection may spend, summed over its channels, the
# child shells its subshells, pipelines and substitutions run in, and every
# re-parse of a line-fed construct still open. Shape bounds alone kept missing
# inputs (a review found a new costly shape per round); this bounds them all:
# past it every input that needs the grammar is refused at once. It counts
# grammar time only, not the time spent running what parsed. A connection
# that spends it has held the reactor at least 30 s; a 16 KiB dropper script,
# the largest input [shell] max_input_size admits, costs 4-7 s on arm, and a
# bot's ordinary commands milliseconds.
PARSE_BUDGET_SECONDS = 30.0

# Grammar results a connection remembers, keyed by the grammar rule and the
# exact input: a loop runs the same backtick body, and the same line, every
# pass, and a backtick body is one flat token with no tree in its line to
# reuse the way a "$(...)" body does (the 104-byte `while` line with
# backticks parsed 1,000 times: 24 s). Only inputs up to
# PARSE_MEMO_ENTRY_CHARS are kept, PARSE_MEMO_CHARS in all: a tree holds
# 500-680 bytes per input character, so this is ~5 MB at most.
PARSE_MEMO_ENTRIES = 64
PARSE_MEMO_ENTRY_CHARS = 2048
PARSE_MEMO_CHARS = 8192


class ParseRefusedError(ParseTimeoutError):
    """ShardLure (shell-parse-bounds.py): the input was refused without a
    full parse (nested too deep, the connection's grammar budget is spent, or
    the recursion limit was hit). A ParseTimeoutError, so every caller answers
    it the way it answers a timed-out parse."""


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
                # Outside double quotes the grammar reads "\\"-newline as a
                # blank (a case head may follow it); inside them, and for any
                # other escaped byte, the word continues: a word start set
                # inside quotes outlived the closing quote, and a "#" after it
                # hid the rest of the line.
                if top != '"' and (
                    text.startswith("\n", pos + 1) or text.startswith("\r\n", pos + 1)
                ):
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
                    word_start = False
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


import copy as _copy

from cowrie.shell.prescan import ScanResult


def _moved(node, shift: int, rows: int):
    """A copy of a grammar node parsed from text that starts ``shift``
    characters and ``rows`` lines into a larger text, placed in that text.
    Columns stay: the smaller text starts a line. The node itself is never
    changed (it may be a remembered tree)."""
    if isinstance(node, Token):
        return Token(
            node.type,
            node.value,
            start_pos=None if node.start_pos is None else node.start_pos + shift,
            line=None if node.line is None else node.line + rows,
            column=node.column,
            end_line=None if node.end_line is None else node.end_line + rows,
            end_column=node.end_column,
            end_pos=None if node.end_pos is None else node.end_pos + shift,
        )
    if isinstance(node, Tree):
        meta = _copy.copy(node.meta)
        if not meta.empty:
            meta.start_pos += shift
            meta.end_pos += shift
            meta.line += rows
            meta.end_line += rows
        return Tree(node.data, [_moved(child, shift, rows) for child in node.children], meta)
    return node


def _remembered_error(error: LarkError) -> tuple:
    """What the memo keeps of a grammar error: the fields parse() reads, not
    the exception, which holds the parser's state."""
    if isinstance(error, UnexpectedCharacters):
        return ("chars", error.pos_in_stream, error.line, error.column)
    if isinstance(error, UnexpectedEOF):
        return ("eof",)
    return ("lark",)


def _raise_remembered(entry: tuple, text: str) -> None:
    """Raise a fresh grammar error equal to the remembered one."""
    if entry[0] == "chars":
        raise UnexpectedCharacters(text, entry[1], entry[2], entry[3])
    if entry[0] == "eof":
        raise UnexpectedEOF([])
    raise LarkError("remembered syntax error")


_HAS_PARSE_ALARM = all(
'''

# parse(): before the pre-scan, take the tree a $(...) body was handed.
OLD_PARSE = r'''        self._line_offset = first_line - 1
        scanned = scan(text, max_heredoc=max_heredoc_size())
'''

NEW_PARSE = r'''        self._line_offset = first_line - 1
        # ShardLure (shell-parse-bounds.py): a $(...) body the evaluator is
        # about to run is split from the tree its enclosing text produced
        # (see _substitute) instead of being parsed again.
        reused, self._reuse = self._reuse, None
        if reused is not None and reused[0] is text:
            statements = self._split_reused(*reused)
            if statements is not None:
                return statements
        scanned = scan(text, max_heredoc=max_heredoc_size())
'''

# parse(): a line-fed construct still open is extended, not parsed whole.
OLD_TREE = r'''        self._heredocs = scanned.heredocs
        try:
            tree = self._lark_parse(line, "start")
'''

NEW_TREE = r'''        self._heredocs = scanned.heredocs
        try:
            # ShardLure (shell-parse-bounds.py): a line-fed construct still
            # open is extended by its new lines, not parsed whole again (see
            # _extend_pending).
            tree = self._extend_pending(line, scanned)
            if tree is None:
                tree = self._lark_parse(line, "start")
'''

# parse(): a RecursionError in the statement splitter fails this parse only,
# and an input that ends inside an open compound command is remembered.
OLD_SPLIT = r'''        except (LarkError, ParseTimeoutError):
            return [SyntaxError_(token="", lineno=self._end_line(line))]
        statements = self._split_statements(line, tree)
'''

NEW_SPLIT = r'''        except (LarkError, ParseTimeoutError):
            # ShardLure (shell-parse-bounds.py): a ParseRefusedError (nested
            # too deep, budget spent, recursion limit) lands here too.
            return [SyntaxError_(token="", lineno=self._end_line(line))]
        try:
            statements = self._split_statements(line, tree)
        except RecursionError:
            self._log.warn(
                "Shell parse hit the recursion limit (input: {length} characters)",
                length=len(line),
            )
            return [SyntaxError_(token="", lineno=self._end_line(line))]
        self._remember_pending(line, scanned, tree, statements)
'''

# _lark_parse(), _end_line() and _node_line(): the one grammar entry point,
# and the line numbers a reused $(...) body must keep. Named OLD/NEW: the
# release contract and check-cowrie-patches.sh's drift step read that name.
OLD = r'''    def _lark_parse(self, text: str, start: str) -> Tree:
        """Run the grammar from ``start`` over ``text`` under the parse time
        limit, collecting the Earley garbage afterwards for larger input.
        Raises the Lark error or :class:`ParseTimeoutError`."""
        timed_out = False
        try:
            with _parse_alarm(parse_timeout_seconds()):
                return _parser.parse(text, start=start)
        except ParseTimeoutError:
            timed_out = True
            self._log.warn(
                "Shell parse exceeded {timeout}s (input: {length} characters)",
                timeout=parse_timeout_seconds(),
                length=len(text),
            )
            raise
        finally:
            if timed_out or len(text) >= gc_collect_threshold():
                gc.collect()

    def _end_line(self, line: str) -> int:
        """The line bash reports an unexpected end of input on: the one after
        the last."""
        return len(line.rstrip("\n").split("\n")) + 1 + self._line_offset

    def _node_line(self, node: Tree | Token | None) -> int:
        """The 1-based source line a grammar node starts on, or 0."""
        if isinstance(node, Token):
            return node.line + self._line_offset if node.line else 0
        if isinstance(node, Tree) and not node.meta.empty:
            return node.meta.line + self._line_offset
        return 0
'''

NEW = r'''    def _lark_parse(self, text: str, start: str) -> Tree:
        """Run the grammar from ``start`` over ``text`` under the parse time
        limit, collecting the Earley garbage afterwards for larger input.
        Raises the Lark error or :class:`ParseTimeoutError`.

        ShardLure (shell-parse-bounds.py): every grammar run of the shell
        comes through here (a line or script, each re-parse of a line-fed
        construct still open, a $(...) body that could not be reused, a
        here-document body), so this is where one input's cost is bounded.
        A result this connection remembers answers without the grammar.
        Input nested deeper than MAX_NESTING_DEPTH, and any input once the
        connection has spent PARSE_BUDGET_SECONDS of grammar time, raise
        ParseRefusedError unparsed; a RecursionError raises it for this parse
        only. ParseRefusedError is a ParseTimeoutError, so every caller
        answers it as it answers a timed-out parse.
        """
        key = (start, str(text))
        remembered = self._memo_lookup(key)
        if isinstance(remembered, tuple):
            _raise_remembered(remembered, text)
        if remembered is not None:
            return remembered
        # A here-document body's plain parentheses are text; only its $( and
        # backtick bodies nest the grammar.
        if (start == "start" or "$(" in text or "`" in text) and nesting_too_deep(text):
            self._log.warn(
                "Shell parse refused: groups nested deeper than {limit}"
                " (input: {length} characters)",
                limit=MAX_NESTING_DEPTH,
                length=len(text),
            )
            raise ParseRefusedError
        state = self._connection_state()
        if state["spent"] >= PARSE_BUDGET_SECONDS:
            if not state["warned"]:
                state["warned"] = True
                self._log.warn(
                    "Shell parse refused: this connection spent its {budget}s"
                    " parse budget",
                    budget=PARSE_BUDGET_SECONDS,
                )
            raise ParseRefusedError
        timed_out = False
        started = _parse_clock()
        try:
            with _parse_alarm(parse_timeout_seconds()):
                tree = _parser.parse(text, start=start)
        except ParseTimeoutError:
            timed_out = True
            self._log.warn(
                "Shell parse exceeded {timeout}s (input: {length} characters)",
                timeout=parse_timeout_seconds(),
                length=len(text),
            )
            raise
        except RecursionError:
            self._log.warn(
                "Shell parse hit the recursion limit (input: {length} characters)",
                length=len(text),
            )
            raise ParseRefusedError from None
        except LarkError as error:
            self._memo_put(key, _remembered_error(error))
            raise
        finally:
            state["spent"] += _parse_clock() - started
            if timed_out or len(text) >= gc_collect_threshold():
                gc.collect()
        self._memo_put(key, tree)
        return tree

    # ShardLure (shell-parse-bounds.py): while _split_reused splits a $(...)
    # body out of its enclosing text's tree, line numbers count from the
    # body's first line and the input ends where the body ends, exactly as a
    # fresh parse of the body numbered them, so the "line N:" of its errors
    # is unchanged.
    _reuse: tuple[str, str, Tree] | None = None
    _line_shift = 0
    _reuse_end: int | None = None
    # The last input that ended inside an open compound command, and its tree
    # (see _extend_pending).
    _pending_tree: tuple[str, Tree] | None = None

    def _extend_pending(self, line: str, scanned: ScanResult) -> Tree | None:
        """The tree of ``line`` built from the remembered tree of an earlier
        input it extends and a parse of the new lines alone, or None.

        A line-fed shell parses an open construct's whole pending text again
        with every line (honeypot.py _feed_line), N(N+1)/2 lines of grammar
        for N lines. The earlier text is remembered only when it ended at a
        line boundary with nothing lexically open and no here-document, and
        it parsed: no token, group or case clause then spans that boundary (an
        open group is reported by the pre-scanner, an open case clause fails
        the grammar), so the grammar's tree of the whole is the earlier tree
        followed by the new lines' tree moved to their place. New lines the
        grammar rejects on their own are parsed whole instead, so an error
        keeps its positions."""
        pending, self._pending_tree = self._pending_tree, None
        if pending is None or isinstance(line, SourceText) or scanned.heredocs:
            return None
        prefix, tree = pending
        if len(line) <= len(prefix) or not line.startswith(prefix):
            return None
        try:
            tail = self._lark_parse(line[len(prefix):], "start")
        except LarkError:
            return None
        shift, rows = len(prefix), prefix.count("\n")
        meta = _copy.copy(tree.meta)
        if not tail.meta.empty:
            if meta.empty:
                meta = _copy.copy(tail.meta)
                meta.start_pos += shift
                meta.line += rows
            meta.end_pos = tail.meta.end_pos + shift
            meta.end_line = tail.meta.end_line + rows
            meta.end_column = tail.meta.end_column
        children = [*tree.children, *(_moved(child, shift, rows) for child in tail.children)]
        return Tree(tree.data, children, meta)

    def _remember_pending(
        self, line: str, scanned: ScanResult, tree: Tree, statements: list[Statement]
    ) -> None:
        """Keep ``line``'s tree for _extend_pending when it ends inside an
        open compound command at a clean line boundary. One per parser: the
        line-fed shell's, held while its construct stays open (at most
        max_input_size characters of input)."""
        if (
            statements
            and isinstance(statements[-1], SyntaxError_)
            and statements[-1].incomplete
            and scanned.incomplete is None
            and not scanned.heredocs
            and not isinstance(line, SourceText)
            and line.endswith("\n")
        ):
            self._pending_tree = (str(line), tree)

    def _end_line(self, line: str) -> int:
        """The line bash reports an unexpected end of input on: the one after
        the last."""
        if self._reuse_end is not None:
            return self._reuse_end
        return len(line.rstrip("\n").split("\n")) + 1 + self._line_offset

    def _node_line(self, node: Tree | Token | None) -> int:
        """The 1-based source line a grammar node starts on, or 0."""
        if isinstance(node, Token):
            raw = node.line or 0
        elif isinstance(node, Tree) and not node.meta.empty:
            raw = node.meta.line
        else:
            return 0
        return raw - self._line_shift + self._line_offset if raw else 0

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

    def _memo_lookup(self, key: tuple[str, str]) -> Tree | tuple | None:
        """The remembered grammar result for (rule, input): a tree (the
        evaluator mutates statements, never the tree) or a syntax error
        record. Only results that depend on the input alone are remembered,
        never a timeout or the recursion limit."""
        if len(key[1]) > PARSE_MEMO_ENTRY_CHARS:
            return None
        return self._connection_state()["memo"].get(key)

    def _memo_put(self, key: tuple[str, str], entry: Tree | tuple) -> None:
        if len(key[1]) > PARSE_MEMO_ENTRY_CHARS:
            return
        state = self._connection_state()
        memo = state["memo"]
        if key in memo:
            return
        while memo and (
            len(memo) >= PARSE_MEMO_ENTRIES
            or state["chars"] + len(key[1]) > PARSE_MEMO_CHARS
        ):
            oldest = next(iter(memo))
            del memo[oldest]
            state["chars"] -= len(oldest[1])
        memo[key] = entry
        state["chars"] += len(key[1])

    def _split_reused(self, source: str, line: str, body: Tree) -> list[Statement] | None:
        """The statements of a ``$(...)`` body, from the ``start`` tree the
        grammar built for it inside ``line``: what parse(source) returns,
        with the word trees still pointing into ``line``. None when the body
        would not parse the same way on its own (it holds a here-document, or
        is lexically open, e.g. ends in a line continuation): parse() then
        reads it afresh, as stock does."""
        scanned = scan(source, max_heredoc=max_heredoc_size())
        if scanned.incomplete is not None or scanned.heredocs or scanned.stripped != source:
            return None
        self._heredocs = {}
        self._line_shift = line.count("\n", 0, body.meta.start_pos)
        self._reuse_end = len(source.rstrip("\n").split("\n")) + 1 + self._line_offset
        try:
            return self._split_statements(line, body)
        except RecursionError:
            return [SyntaxError_(token="", lineno=self._reuse_end)]
        finally:
            self._line_shift = 0
            self._reuse_end = None

    def _substitute(self, line: str, node: Tree) -> Awaitable[str]:
        """Run a ``$(...)`` through the context's command_substitution.

        ShardLure (shell-parse-bounds.py): the body was parsed with the
        enclosing text, so its tree is handed to the parse() that the
        substitution makes instead of the Earley parser reading the same text
        again. A re-parse per evaluation made the cost the nesting depth
        times the body (8 levels around 11 KB: 23 s) and every loop pass
        (a 116-byte `while` line: 1,001 parses, 22 s), all on the reactor.
        Text the pre-scanner cut here-documents out of (a SourceText) is
        parsed afresh: its bodies are keyed by positions in that parse.
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
        if source and body is not None and not isinstance(line, SourceText):
            self._reuse = (source, line, body)
        try:
            return self.context.command_substitution(source)
        finally:
            self._reuse = None
'''

# _expand_heredoc(): a $(...) in a here-document body.
OLD_HEREDOC = r'''            elif part.data == "cmdsub":
                parts.append(
                    await self.context.command_substitution(
                        self._group_source(text, part)
                    )
                )
'''

NEW_HEREDOC = r'''            elif part.data == "cmdsub":
                parts.append(await self._substitute(text, part))
'''

# A $(...) word atom.
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

# A $(...) inside double quotes.
OLD_DQ = r'''        if part.data == "cmdsub":
            return await self.context.command_substitution(
                self._group_source(line, part)
            )
        if part.data == "backtick":
'''

NEW_DQ = r'''        if part.data == "cmdsub":
            return await self._substitute(line, part)
        if part.data == "backtick":
'''


BLOCKS = (
    (OLD_LIMITS, NEW_LIMITS),
    (OLD_PARSE, NEW_PARSE),
    (OLD_TREE, NEW_TREE),
    (OLD_SPLIT, NEW_SPLIT),
    (OLD, NEW),
    (OLD_HEREDOC, NEW_HEREDOC),
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
    print(f"  [ok] {path}: patched (parse once per substitution, nesting bound, parse budget)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
