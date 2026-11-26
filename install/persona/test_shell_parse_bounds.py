#!/usr/bin/env python3
"""Pin what shell-parse-bounds.py promises, without Cowrie's dependencies.

Loads the checked-out Cowrie's patched src/cowrie/shell/bashparse.py (v3.1.8)
with stand-ins for lark, twisted.logger and Cowrie's config, the real
stdlib-only cowrie.shell.{prescan,parser,arithmetic} beside it, and a counting
stub in place of the Earley parser, so CI (which has neither lark nor Twisted)
exercises the patch's own logic:

- the nesting scan: the depth bound and each input that got past it in
  review (a "#" after "$(...)", quoted and continued case heads, an unclosed
  case head, a "\\"-newline inside double quotes), the inputs it must still
  accept, and linear time on 64 KiB;
- _lark_parse, the one grammar entry point: a refused input never reaches the
  grammar and raises ParseRefusedError (a ParseTimeoutError); a here-document
  body is scanned only when it holds a $( or backtick;
- the per-connection memo: a repeat is answered from the remembered tree or
  syntax error, the entry and total bounds hold, timeouts and recursion
  failures are never remembered, the grammar rule is part of the key, and
  child shells of one connection share it while two connections do not;
- the per-connection grammar budget: charged per grammar run (including each
  re-parse of a line-fed construct still open), never on a memo hit, and once
  spent every new input is refused unparsed;
- $(...) reuse: a substitution is split from its enclosing text's tree with
  its own line numbers, and parsed afresh when the text had here-documents cut
  out or the body is lexically open;
- line-fed extension: an input that ends inside an open compound command at a
  clean line boundary is remembered, and the next one that extends it parses
  only its new lines, placed by position; anything else is parsed whole;
- a RecursionError in the grammar or in the splitter fails one parse.

The real grammar and transcripts are covered by the behavioural harness
(scripts/behaviour/parse-*) against a running Cowrie.

Usage: test_shell_parse_bounds.py COWRIE_HOME [-v]
   or: COWRIE_HOME=... python3 -m unittest install/persona/test_shell_parse_bounds.py
"""

import importlib.util
import os
import sys
import time
import types
import unittest
from pathlib import Path

BP = None  # the loaded bashparse module


def _stub_modules(cowrie_home: Path) -> None:
    lark = types.ModuleType("lark")

    class Tree:
        def __init__(self, data="start", children=(), meta=None):
            self.data = data
            self.children = list(children)
            self.meta = meta if meta is not None else types.SimpleNamespace(empty=True)

    class Token(str):
        def __new__(cls, type_, value, start_pos=None, line=None, column=None,
                    end_line=None, end_column=None, end_pos=None):
            token = super().__new__(cls, value)
            token.type, token.value = type_, value
            token.start_pos, token.line, token.column = start_pos, line, column
            token.end_line, token.end_column, token.end_pos = end_line, end_column, end_pos
            return token

    class Lark:
        def __init__(self, *args, **kwargs):
            pass

        def parse(self, text, start="start"):
            raise AssertionError("grammar stand-in not installed")

    lark.Lark, lark.Tree, lark.Token = Lark, Tree, Token
    exceptions = types.ModuleType("lark.exceptions")

    class LarkError(Exception):
        pass

    class UnexpectedCharacters(LarkError):
        def __init__(self, seq, lex_pos, line, column, **kwargs):
            super().__init__(f"unexpected {seq[lex_pos]!r}")
            self.pos_in_stream, self.line, self.column = lex_pos, line, column

    class UnexpectedEOF(LarkError):
        def __init__(self, expected, **kwargs):
            super().__init__("unexpected end of input")
            self.expected = expected

    exceptions.LarkError = LarkError
    exceptions.UnexpectedCharacters = UnexpectedCharacters
    exceptions.UnexpectedEOF = UnexpectedEOF
    lark.exceptions = exceptions

    logger = types.ModuleType("twisted.logger")

    class Logger:
        def __getattr__(self, name):
            return lambda *a, **k: None

    logger.Logger = Logger
    twisted = types.ModuleType("twisted")
    twisted.logger = logger

    config = types.ModuleType("cowrie.core.config")

    class CowrieConfig:
        @staticmethod
        def getfloat(section, key, fallback=0.0):
            return fallback

        @staticmethod
        def getint(section, key, fallback=0):
            return fallback

        @staticmethod
        def get(section, key, fallback=None):
            return fallback

        @staticmethod
        def getboolean(section, key, fallback=False):
            return fallback

    config.CowrieConfig = CowrieConfig
    # cowrie.shell's own __init__ is not run: only its stdlib-only modules
    # (prescan, parser, arithmetic) are imported, from the checkout.
    cowrie = types.ModuleType("cowrie")
    cowrie.__path__ = [str(cowrie_home / "src/cowrie")]
    shell = types.ModuleType("cowrie.shell")
    shell.__path__ = [str(cowrie_home / "src/cowrie/shell")]
    for name, module in {
        "lark": lark, "lark.exceptions": exceptions, "twisted": twisted,
        "twisted.logger": logger, "cowrie": cowrie, "cowrie.shell": shell,
        "cowrie.core": types.ModuleType("cowrie.core"), "cowrie.core.config": config,
    }.items():
        sys.modules.setdefault(name, module)


def load(cowrie_home: Path):
    _stub_modules(cowrie_home)
    path = cowrie_home / "src/cowrie/shell/bashparse.py"
    spec = importlib.util.spec_from_file_location("bashparse_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up
    spec.loader.exec_module(module)
    return module


def setUpModule():
    global BP
    if BP is None:
        home = os.environ.get("COWRIE_HOME")
        if not home:
            raise unittest.SkipTest("set COWRIE_HOME to a Cowrie v3.1.8 checkout with"
                                    " shell-parse-bounds.py applied")
        BP = load(Path(home))


class Grammar:
    """Stands in for the Earley parser: counts runs, may cost clock time."""

    def __init__(self, clock=None, cost=0.0, fail=None):
        self.calls = []
        self.clock, self.cost, self.fail = clock, cost, fail

    def parse(self, text, start="start"):
        self.calls.append(text if start == "start" else (start, text))
        if self.clock is not None:
            self.clock[0] += self.cost
        if self.fail is not None:
            raise self.fail(text) if callable(self.fail) else self.fail
        return BP.Tree(start, [text])


class Connection:
    """protocol.user.server: the object one SSH connection shares."""

    def __init__(self):
        self.protocol = types.SimpleNamespace(user=types.SimpleNamespace(server=types.SimpleNamespace()))

    def parser(self):
        context = types.SimpleNamespace(protocol=self.protocol)
        p = BP.BashParser(context)
        # The shell's command_substitution parses the source on the same parser.
        context.command_substitution = lambda source: p.parse(source)
        # Statements from a tree; the real splitter needs the real grammar.
        p._split_statements = lambda line, tree: [("stmt", line)]
        return p


def deep(n: int, inner: str = "x") -> str:
    return "$(echo " * n + inner + ")" * n


def is_error(result, incomplete=False):
    return (len(result) == 1 and isinstance(result[0], BP.SyntaxError_)
            and result[0].incomplete == incomplete)


class NestingScanTests(unittest.TestCase):
    def assertRefused(self, text):
        self.assertTrue(BP.nesting_too_deep(text), repr(text[:60]))

    def assertAccepted(self, text):
        self.assertFalse(BP.nesting_too_deep(text), repr(text[:60]))

    def test_depth_bound(self):
        self.assertEqual(BP.MAX_NESTING_DEPTH, 16)
        self.assertAccepted("echo " + deep(16))
        self.assertRefused("echo " + deep(17))
        self.assertAccepted("( " * 16 + "echo x" + " )" * 16)
        self.assertRefused("( " * 17 + "echo x" + " )" * 17)

    def test_hash_after_substitution_continues_the_word(self):
        self.assertRefused("echo $(true)# " + deep(100))
        self.assertAccepted("echo $(echo a)#b")
        self.assertAccepted("(echo a)\n#" + "(" * 40)  # a real comment

    def test_any_case_head_word_counts(self):
        for head in ('case "a b" in a) ', "case $(x) in a) ", "case x\\\n in a) ",
                     'case "a b" in a)\\\n'):
            self.assertRefused(head * 32 + "echo" + " ;; esac" * 32)
        self.assertAccepted("case x in a) " * 16 + "echo" + " ;; esac" * 16)
        self.assertAccepted("case x in (a) echo ;; esac")

    def test_unclosed_case_head_cannot_hide_a_comment(self):
        self.assertRefused("echo $(case x in a)# " + deep(120) + ")")
        self.assertAccepted("echo case x in y " * 40)

    def test_quoted_backslash_newline_is_no_word_break(self):
        self.assertRefused('echo "\\\n"# ' + deep(120))
        self.assertAccepted('echo "a\\\nb"; echo ok')
        self.assertAccepted('echo "a"#b')

    def test_backtick_bodies_count(self):
        self.assertRefused("echo " + "`echo " * 1 + deep(16) + "`")

    def test_scan_is_linear(self):
        for text in ("( " * 32768, "$(" * 32768, "case " * 13107, "'\"`\\" * 16384):
            started = time.perf_counter()
            BP.nesting_too_deep(text)
            self.assertLess(time.perf_counter() - started, 2.0, repr(text[:10]))


class ParseTestCase(unittest.TestCase):
    def setUp(self):
        self.clock = [0.0]
        self._saved = (BP._parser, BP._parse_clock)
        BP._parse_clock = lambda: self.clock[0]

    def tearDown(self):
        BP._parser, BP._parse_clock = self._saved

    def use(self, grammar):
        BP._parser = grammar
        return grammar


class ParseTests(ParseTestCase):
    def test_refusal_is_a_parse_timeout(self):
        self.assertTrue(issubclass(BP.ParseRefusedError, BP.ParseTimeoutError))

    def test_refused_input_never_reaches_the_grammar(self):
        grammar = self.use(Grammar())
        p = Connection().parser()
        self.assertTrue(is_error(p.parse("echo " + deep(17))))
        with self.assertRaises(BP.ParseRefusedError):
            p._lark_parse("echo " + deep(17), "start")
        self.assertEqual(grammar.calls, [])

    def test_nesting_scan_runs_on_the_stripped_text(self):
        # Parentheses in a here-document body are data: the pre-scanner lifts
        # the body out before the scan and the grammar see the line.
        grammar = self.use(Grammar())
        text = "cat <<EOF\n" + "(" * 40 + "\nEOF\n"
        Connection().parser().parse(text)
        self.assertEqual(len(grammar.calls), 1)
        self.assertNotIn("(", grammar.calls[0])

    def test_repeat_is_split_from_the_remembered_tree(self):
        grammar = self.use(Grammar())
        conn = Connection()
        first = conn.parser().parse("echo a")
        again = conn.parser().parse("echo a")  # a child shell's parser
        self.assertEqual(first, again)
        self.assertEqual(grammar.calls, ["echo a"])

    def test_connections_do_not_share_state(self):
        grammar = self.use(Grammar())
        Connection().parser().parse("echo a")
        Connection().parser().parse("echo a")
        self.assertEqual(len(grammar.calls), 2)

    def test_memo_bounds(self):
        grammar = self.use(Grammar())
        p = Connection().parser()
        big = "x" * (BP.PARSE_MEMO_ENTRY_CHARS + 1)
        p.parse(big)
        p.parse(big)
        self.assertEqual(grammar.calls.count(big), 2)  # never remembered
        self.assertNotIn(("start", big), p._connection_state()["memo"])
        for i in range(200):
            p.parse(f"echo {i} " + "y" * 300)
        state = p._connection_state()
        self.assertLessEqual(len(state["memo"]), BP.PARSE_MEMO_ENTRIES)
        self.assertLessEqual(state["chars"], BP.PARSE_MEMO_CHARS)
        self.assertEqual(state["chars"], sum(len(k[1]) for k in state["memo"]))

    def test_grammar_rule_is_part_of_the_key(self):
        grammar = self.use(Grammar())
        p = Connection().parser()
        p._lark_parse("a $(b)", "start")
        p._lark_parse("a $(b)", "heredoc_body")
        p._lark_parse("a $(b)", "heredoc_body")
        self.assertEqual(grammar.calls, ["a $(b)", ("heredoc_body", "a $(b)")])

    def test_timeouts_are_never_remembered(self):
        grammar = self.use(Grammar(fail=BP.ParseTimeoutError()))
        p = Connection().parser()
        self.assertTrue(is_error(p.parse("slow")))
        p.parse("slow")
        self.assertEqual(grammar.calls, ["slow", "slow"])

    def test_recursion_limit_fails_one_parse_and_is_not_remembered(self):
        grammar = self.use(Grammar(fail=RecursionError()))
        p = Connection().parser()
        self.assertTrue(is_error(p.parse("deep")))
        p.parse("deep")
        self.assertEqual(grammar.calls, ["deep", "deep"])

    def test_recursion_in_the_splitter_fails_one_parse(self):
        self.use(Grammar())
        p = Connection().parser()

        def split(line, tree):
            raise RecursionError

        p._split_statements = split
        self.assertTrue(is_error(p.parse("if a; then if b; then x; fi; fi")))

    def test_syntax_errors_are_remembered(self):
        def unexpected(text):
            return BP.UnexpectedCharacters(text, text.index(")"), 1, text.index(")") + 1)

        grammar = self.use(Grammar(fail=unexpected))
        p = Connection().parser()
        a, b = p.parse("echo )"), p.parse("echo )")
        self.assertEqual(grammar.calls, ["echo )"])
        self.assertEqual((a[0].token, a[0].lineno), (")", 1))
        self.assertEqual((b[0].token, b[0].lineno), (")", 1))

    def test_unexpected_end_is_remembered_as_incomplete(self):
        grammar = self.use(Grammar(fail=BP.UnexpectedEOF([])))
        p = Connection().parser()
        a, b = p.parse("case x in a)"), p.parse("case x in a)")
        self.assertEqual(len(grammar.calls), 1)
        self.assertTrue(is_error(a, incomplete=True))
        self.assertTrue(is_error(b, incomplete=True))

    def test_other_grammar_errors_are_remembered(self):
        grammar = self.use(Grammar(fail=BP.LarkError()))
        p = Connection().parser()
        a, b = p.parse("bad"), p.parse("bad")
        self.assertEqual(grammar.calls, ["bad"])
        self.assertEqual((a[0].token, a[0].lineno), (b[0].token, b[0].lineno))

    def test_budget_refuses_new_input_once_spent(self):
        cost = BP.PARSE_BUDGET_SECONDS / 3 + 0.1
        grammar = self.use(Grammar(clock=self.clock, cost=cost))
        conn = Connection()
        for i in range(3):
            conn.parser().parse(f"echo {i}")
        self.assertEqual(len(grammar.calls), 3)
        self.assertTrue(is_error(conn.parser().parse("echo new")))
        self.assertEqual(len(grammar.calls), 3)
        # A remembered input still answers, uncharged.
        self.assertEqual(conn.parser().parse("echo 0"), [("stmt", "echo 0")])
        self.assertEqual(len(grammar.calls), 3)
        # Another connection has its own budget.
        Connection().parser().parse("echo new")
        self.assertEqual(len(grammar.calls), 4)

    def test_failed_parses_are_charged(self):
        self.use(Grammar(clock=self.clock, cost=BP.PARSE_BUDGET_SECONDS + 1,
                         fail=BP.ParseTimeoutError()))
        p = Connection().parser()
        p.parse("slow")
        self.assertGreaterEqual(p._connection_state()["spent"], BP.PARSE_BUDGET_SECONDS)

    def test_line_fed_reparses_are_charged_and_then_refused(self):
        # A line-fed shell re-parses an open construct with every new line
        # (honeypot.py _feed_line): each pass is a new input, so each one is
        # charged, and once the budget is gone the next one is refused rather
        # than parsed again.
        cost = BP.PARSE_BUDGET_SECONDS / 4 + 0.1
        grammar = self.use(Grammar(clock=self.clock, cost=cost))
        p = Connection().parser()
        pending = ""
        for n in range(1, 5):
            pending += "if true; then echo y\n"
            p.parse(pending, first_line=1)
        self.assertEqual(len(grammar.calls), 4)
        pending += "if true; then echo y\n"
        self.assertTrue(is_error(p.parse(pending)))
        self.assertEqual(len(grammar.calls), 4)

    def test_heredoc_body_is_budgeted_and_scanned_only_for_substitutions(self):
        grammar = self.use(Grammar(clock=self.clock, cost=BP.PARSE_BUDGET_SECONDS + 1))
        p = Connection().parser()
        p._lark_parse("ascii art " + "(" * 40, "heredoc_body")  # text, not groups
        self.assertEqual(len(grammar.calls), 1)
        with self.assertRaises(BP.ParseRefusedError):  # budget spent
            p._lark_parse("x", "heredoc_body")
        fresh = Connection().parser()
        with self.assertRaises(BP.ParseRefusedError):
            fresh._lark_parse("v=" + deep(17), "heredoc_body")
        self.assertEqual(len(grammar.calls), 1)

    def test_line_numbers_count_from_first_line(self):
        self.use(Grammar())
        p = Connection().parser()
        p.parse("x", first_line=5)
        self.assertEqual(p._end_line("a\nb"), 7)
        self.assertEqual(p._node_line(BP.Token("WORD", "w", line=2)), 6)
        self.assertEqual(p._node_line(BP.Token("WORD", "w")), 0)


class ReuseTests(ParseTestCase):
    def substitution(self, line, source):
        """A cmdsub node whose start child spans ``source`` inside ``line``."""
        start = line.index(source)
        meta = types.SimpleNamespace(empty=False, start_pos=start,
                                     end_pos=start + len(source), line=line.count("\n", 0, start) + 1)
        body = BP.Tree("start", ["body"], meta=meta)
        return BP.Tree("cmdsub", [BP.Token("CMDSUB_OPEN", "$("), body]), body

    def test_body_is_split_from_the_enclosing_tree(self):
        grammar = self.use(Grammar())
        p = Connection().parser()
        line = "a\necho $(b\nc)"
        node, body = self.substitution(line, "b\nc")
        seen = []

        def split(text, tree):
            seen.append((text, tree, p._line_shift, p._end_line(text),
                         p._node_line(BP.Token("WORD", "c", line=3))))
            return [("stmt", "reused")]

        p._split_statements = split
        self.assertEqual(p._substitute(line, node), [("stmt", "reused")])
        self.assertEqual(grammar.calls, [])
        # Numbered as a fresh parse of "b\nc" numbers it: c is on its line 2,
        # and the input ends on line 3.
        self.assertEqual(seen, [(line, body, 1, 3, 2)])
        self.assertIsNone(p._reuse)
        self.assertEqual((p._line_shift, p._reuse_end), (0, None))
        self.assertEqual(p._end_line("a\nb"), 3)

    def test_heredoc_body_substitution_is_reused_too(self):
        # _expand_heredoc hands the body text and its cmdsub node to the same
        # _substitute as a word does.
        grammar = self.use(Grammar())
        p = Connection().parser()
        text = "line one\nuser=$(id -un)\n"
        node, _ = self.substitution(text, "id -un")
        p._split_statements = lambda line, tree: [("stmt", "reused")]
        self.assertEqual(p._substitute(text, node), [("stmt", "reused")])
        self.assertEqual(grammar.calls, [])

    def test_text_with_heredocs_cut_out_is_parsed_afresh(self):
        grammar = self.use(Grammar())
        p = Connection().parser()
        original = "x=$(echo hi)\n"
        line = BP.SourceText(original, original, [(len(original), 4)])
        node, _ = self.substitution(line, "echo hi")
        p._substitute(line, node)
        self.assertEqual(grammar.calls, ["echo hi"])

    def test_lexically_open_body_is_parsed_afresh(self):
        grammar = self.use(Grammar())
        p = Connection().parser()
        line = "x=$(echo a \\\n)"
        node, _ = self.substitution(line, "echo a \\\n")
        p._substitute(line, node)
        self.assertEqual(grammar.calls, ["echo a \\\n"])

    def test_reuse_is_for_that_source_only(self):
        grammar = self.use(Grammar())
        p = Connection().parser()
        line = "x=$(echo hi)"
        node, body = self.substitution(line, "echo hi")
        p._reuse = ("echo hi", line, body)
        p.parse("echo other")  # not the handed source: parsed, reuse dropped
        self.assertEqual(grammar.calls, ["echo other"])
        self.assertIsNone(p._reuse)


class ExtendTests(ParseTestCase):
    """A line-fed shell's open construct grows one line at a time."""

    def parser(self):
        p = Connection().parser()
        # Open until a line "fi"; the statements show the tree's children.
        p._split_statements = lambda line, tree: (
            [("stmt", tuple(tree.children))] if line.endswith("fi\n")
            else [BP.SyntaxError_(token="", lineno=1, incomplete=True)])
        return p

    def test_only_new_lines_reach_the_grammar(self):
        grammar = self.use(Grammar())
        p = self.parser()
        pending = ""
        for line in ("if a; then\n", "echo b\n", "echo b\n", "fi\n"):
            pending += line
            result = p.parse(pending)
        self.assertEqual(grammar.calls, ["if a; then\n", "echo b\n", "fi\n"])  # memo: one "echo b"
        self.assertEqual(result, [("stmt", ("if a; then\n", "echo b\n", "echo b\n", "fi\n"))])
        self.assertIsNone(p._pending_tree)  # complete: nothing to extend

    def test_new_lines_are_placed_after_the_old(self):
        meta = types.SimpleNamespace(empty=False, start_pos=0, end_pos=6, line=1,
                                     column=1, end_line=2, end_column=3)
        token = BP.Token("WORD", "x", start_pos=0, line=1, column=3, end_line=1,
                         end_column=4, end_pos=1)
        tree = BP.Tree("word", [token, BP.Tree("start", [], meta)], meta)
        moved = BP._moved(tree, 10, 2)
        t = moved.children[0]
        self.assertEqual((t.type, t, t.start_pos, t.line, t.column, t.end_line, t.end_column,
                          t.end_pos), ("WORD", "x", 10, 3, 3, 3, 4, 11))
        m = moved.children[1].meta
        self.assertEqual((m.start_pos, m.end_pos, m.line, m.end_line, m.column, m.end_column),
                         (10, 16, 3, 4, 1, 3))
        # The remembered tree is never changed.
        self.assertEqual((token.start_pos, token.line, meta.start_pos, meta.line), (0, 1, 0, 1))
        empty = BP._moved(BP.Tree("start", []), 10, 2)
        self.assertTrue(empty.meta.empty)

    def test_new_lines_are_charged_and_refused_once_the_budget_is_spent(self):
        cost = BP.PARSE_BUDGET_SECONDS / 2 + 0.1
        grammar = self.use(Grammar(clock=self.clock, cost=cost))
        p = self.parser()
        p.parse("if a; then\n")
        p.parse("if a; then\necho 1\n")
        self.assertTrue(is_error(p.parse("if a; then\necho 1\necho 2\n")))
        self.assertEqual(grammar.calls, ["if a; then\n", "echo 1\n"])

    def test_rejected_new_lines_are_parsed_whole(self):
        def unexpected(text):
            if text == "if a; then\n":
                return None
            return BP.UnexpectedCharacters(text, text.index(")"), 1, 1)

        class Picky(Grammar):
            def parse(self, text, start="start"):
                self.calls.append(text)
                error = unexpected(text)
                if error is not None:
                    raise error
                return BP.Tree(start, [text])

        grammar = self.use(Picky())
        p = self.parser()
        p.parse("if a; then\n")
        result = p.parse("if a; then\necho )\n")
        # The new line alone, then the whole text for the error's position.
        self.assertEqual(grammar.calls, ["if a; then\n", "echo )\n", "if a; then\necho )\n"])
        self.assertEqual((result[0].token, result[0].lineno), (")", 1))

    def test_only_a_clean_open_construct_is_remembered(self):
        self.use(Grammar())
        p = self.parser()
        p.parse("if a; then\n")
        self.assertEqual(p._pending_tree[0], "if a; then\n")
        for text in ("if a; then\necho a \\\n",          # line continuation
                     "if a; then\ncat <<EOF\nbody\n",    # here-document body
                     "if a; then"):                      # no line boundary
            with self.subTest(text=text):
                p._pending_tree = None
                p.parse(text)
                self.assertIsNone(p._pending_tree)

    def test_unrelated_or_heredoc_text_is_parsed_whole(self):
        grammar = self.use(Grammar())
        p = self.parser()
        p.parse("if a; then\n")
        p.parse("while b; do\n")  # does not extend it
        p._pending_tree = ("if a; then\n", BP.Tree("start", ["if a; then\n"]))
        p.parse("if a; then\ncat <<EOF\nx\nEOF\n")  # here-document cut out
        self.assertEqual(grammar.calls, ["if a; then\n", "while b; do\n",
                                         "if a; then\ncat <<EOF\n\n\n"])


def main() -> int:
    global BP
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if len(args) != 1:
        print(__doc__.strip().splitlines()[-2], file=sys.stderr)
        return 2
    BP = load(Path(args[0]))
    verbosity = 2 if "-v" in sys.argv else 1
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
