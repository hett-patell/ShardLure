#!/usr/bin/env python3
"""Pin what shell-parse-bounds.py promises, without Cowrie's dependencies.

Loads the checked-out Cowrie's patched src/cowrie/shell/bashparse.py with
stand-ins for lark, twisted.logger and Cowrie's config, and a counting stub
in place of the Earley parser, so CI (which has neither lark nor Twisted)
exercises the patch's own logic:

- the nesting scan: the depth bound and each input that got past it in
  review (a "#" after "$(...)", quoted and continued case heads, an unclosed
  case head, a "\\"-newline inside double quotes), the inputs it must still
  accept, and linear time on 64 KiB;
- parse(): a refused input never reaches the grammar;
- the per-connection memo: a repeat is split from the remembered tree, the
  entry and total bounds hold, timeouts are never remembered, and child
  shells of one connection share it while two connections do not;
- the per-connection grammar budget: charged per grammar run, never on a
  memo hit, and once spent every new input is refused unparsed.

The real grammar and transcripts are covered by the behavioural harness
(scripts/behaviour/parse-*) against a running Cowrie.

Usage: test_shell_parse_bounds.py COWRIE_HOME [-v]
"""

import importlib.util
import sys
import time
import types
import unittest
from pathlib import Path

BP = None  # the loaded bashparse module


def _stub_modules() -> None:
    lark = types.ModuleType("lark")

    class Tree:
        def __init__(self, data="start", children=()):
            self.data = data
            self.children = list(children)

    class Token(str):
        pass

    class Lark:
        def __init__(self, *args, **kwargs):
            pass

        def parse(self, text):
            raise AssertionError("grammar stand-in not installed")

    lark.Lark, lark.Tree, lark.Token = Lark, Tree, Token
    exceptions = types.ModuleType("lark.exceptions")

    class LarkError(Exception):
        pass

    class UnexpectedCharacters(LarkError):
        pass

    exceptions.LarkError, exceptions.UnexpectedCharacters = LarkError, UnexpectedCharacters
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
    for name, module in {
        "lark": lark, "lark.exceptions": exceptions, "twisted": twisted,
        "twisted.logger": logger, "cowrie": types.ModuleType("cowrie"),
        "cowrie.core": types.ModuleType("cowrie.core"), "cowrie.core.config": config,
    }.items():
        sys.modules.setdefault(name, module)


def load(cowrie_home: Path):
    _stub_modules()
    path = cowrie_home / "src/cowrie/shell/bashparse.py"
    spec = importlib.util.spec_from_file_location("bashparse_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up
    spec.loader.exec_module(module)
    return module


class Grammar:
    """Stands in for the Earley parser: counts runs, may cost clock time."""

    def __init__(self, clock=None, cost=0.0, fail=None):
        self.calls = []
        self.clock, self.cost, self.fail = clock, cost, fail

    def parse(self, text):
        self.calls.append(text)
        if self.clock is not None:
            self.clock[0] += self.cost
        if self.fail is not None:
            raise self.fail
        return BP.Tree("start", [text])


class Connection:
    """protocol.user.server: the object one SSH connection shares."""

    def __init__(self):
        self.protocol = types.SimpleNamespace(user=types.SimpleNamespace(server=types.SimpleNamespace()))

    def parser(self):
        p = BP.BashParser(types.SimpleNamespace(protocol=self.protocol))
        # Statements from a tree; the real splitter needs the real grammar.
        p._split_statements = lambda line, tree: [("stmt", line)]
        return p


def deep(n: int, inner: str = "x") -> str:
    return "$(echo " * n + inner + ")" * n


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


class ParseTests(unittest.TestCase):
    def setUp(self):
        self.clock = [0.0]
        self._saved = (BP._parser, BP._parse_clock)
        BP._parse_clock = lambda: self.clock[0]

    def tearDown(self):
        BP._parser, BP._parse_clock = self._saved

    def use(self, grammar):
        BP._parser = grammar
        return grammar

    def test_refused_input_never_reaches_the_grammar(self):
        grammar = self.use(Grammar())
        result = Connection().parser().parse("echo " + deep(17))
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], BP.SyntaxError_)
        self.assertEqual(grammar.calls, [])

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
        conn = Connection()
        p = conn.parser()
        big = "x" * (BP.PARSE_MEMO_ENTRY_CHARS + 1)
        p.parse(big)
        p.parse(big)
        self.assertEqual(grammar.calls.count(big), 2)  # never remembered
        self.assertNotIn(big, p._connection_state()["memo"])
        for i in range(200):
            p.parse(f"echo {i} " + "y" * 300)
        state = p._connection_state()
        self.assertLessEqual(len(state["memo"]), BP.PARSE_MEMO_ENTRIES)
        self.assertLessEqual(state["chars"], BP.PARSE_MEMO_CHARS)
        self.assertEqual(state["chars"], sum(len(k) for k in state["memo"]))

    def test_timeouts_are_never_remembered(self):
        grammar = self.use(Grammar(fail=BP.ParseTimeoutError()))
        p = Connection().parser()
        p.parse("slow")
        p.parse("slow")
        self.assertEqual(grammar.calls, ["slow", "slow"])

    def test_recursion_limit_fails_one_parse_and_is_not_remembered(self):
        grammar = self.use(Grammar(fail=RecursionError()))
        p = Connection().parser()
        first = p.parse("deep")
        self.assertIsInstance(first[0], BP.SyntaxError_)
        p.parse("deep")
        self.assertEqual(grammar.calls, ["deep", "deep"])

    def test_syntax_errors_are_remembered(self):
        grammar = self.use(Grammar(fail=BP.LarkError()))
        p = Connection().parser()
        a, b = p.parse("bad ("), p.parse("bad (")
        self.assertEqual(grammar.calls, ["bad ("])
        self.assertIsInstance(b[0], BP.SyntaxError_)
        self.assertEqual((a[0].token, a[0].lineno), (b[0].token, b[0].lineno))

    def test_budget_refuses_new_input_once_spent(self):
        cost = BP.PARSE_BUDGET_SECONDS / 3 + 0.1
        grammar = self.use(Grammar(clock=self.clock, cost=cost))
        conn = Connection()
        for i in range(3):
            conn.parser().parse(f"echo {i}")
        self.assertEqual(len(grammar.calls), 3)
        refused = conn.parser().parse("echo new")
        self.assertIsInstance(refused[0], BP.SyntaxError_)
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


def main() -> int:
    global BP
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if len(args) != 1:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    BP = load(Path(args[0]))
    verbosity = 2 if "-v" in sys.argv else 1
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
