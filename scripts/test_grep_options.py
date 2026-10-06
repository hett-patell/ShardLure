"""grep-options.py against GNU grep 3.7, without Twisted or a Cowrie tree.

The patch's NEW text (the translator and Command_grep) is executed with stub
I/O and a stub filesystem holding two files, then every case is compared
with stdout, stderr and exit status recorded from GNU grep 3.7 in
ubuntu:22.04 (`docker run --network none ubuntu:22.04`, same files, same
stdin). The table pins the pattern dialects (Phase B Task 4 review I1: BRE
by default, -E, -F), `--color` (I2) and the profiler's own probes.

Not covered here on purpose: colour output (`--color=always` is accepted but
prints no escape codes), -r, -NUM context.
"""
from __future__ import annotations

import ast
import getopt
import os
import posixpath
import re
import unittest
from pathlib import Path

PATCH = Path(__file__).resolve().parent.parent / "install/persona/patches/grep-options.py"

FILES = {
    "/tmp/t": 'foo\na|b\na+\nab\nabb\nabbb\na.b\nabab\n1 23 456\n foo bar\nFoo\nx^y\nx$y\n\n]x\na]\nb\\\na\\b\n(paren)\n*foo\n',
    "/tmp/c": 'model name\t: Xeon\nflags\t: x\nHardware\t: BCM\n',
}

# (argv after "grep", stdin or None, stdout, stderr, exit status) from GNU grep 3.7.
GNU = [
    (['model name\\|Hardware', 'c'], None, 'model name\t: Xeon\nHardware\t: BCM\n', '', 0),
    (['-E', 'a|b', 't'], None, 'a|b\na+\nab\nabb\nabbb\na.b\nabab\n foo bar\na]\nb\\\na\\b\n(paren)\n', '', 0),
    (['a|b', 't'], None, 'a|b\n', '', 0),
    (['a\\|b', 't'], None, 'a|b\na+\nab\nabb\nabbb\na.b\nabab\n foo bar\na]\nb\\\na\\b\n(paren)\n', '', 0),
    (['-E', 'a\\|b', 't'], None, 'a|b\n', '', 0),
    (['a+', 't'], None, 'a+\n', '', 0),
    (['ab+', 't'], None, '', '', 1),
    (['ab\\+', 't'], None, 'ab\nabb\nabbb\nabab\n', '', 0),
    (['ab?', 't'], None, '', '', 1),
    (['ab{2}', 't'], None, '', '', 1),
    (['ab\\{2\\}', 't'], None, 'abb\nabbb\n', '', 0),
    (['-E', 'ab{2}', 't'], None, 'abb\nabbb\n', '', 0),
    (['-E', 'ab\\{2\\}', 't'], None, '', '', 1),
    (['(', 't'], None, '(paren)\n', '', 0),
    (['\\(', 't'], None, '', 'grep: Unmatched ( or \\(\n', 2),
    (['-E', '(', 't'], None, '', 'grep: Unmatched ( or \\(\n', 2),
    (['\\)', 't'], None, '', 'grep: Unmatched ) or \\)\n', 2),
    (['*foo', 't'], None, '*foo\n', '', 0),
    (['-E', '*foo', 't'], None, 'foo\n foo bar\n*foo\n', '', 0),
    (['\\<foo', 't'], None, 'foo\n foo bar\n*foo\n', '', 0),
    (['foo\\>', 't'], None, 'foo\n foo bar\n*foo\n', '', 0),
    (['[[:upper:]]oo', 't'], None, 'Foo\n', '', 0),
    (['[[:digit:]]\\{2\\}', 't'], None, '1 23 456\n', '', 0),
    (['-o', '[[:digit:]]\\{2\\}', 't'], None, '23\n45\n', '', 0),
    (['-E', '[[:digit:]]{2}', 't'], None, '1 23 456\n', '', 0),
    (['[[:space:]]foo', 't'], None, ' foo bar\n', '', 0),
    (['[:space:]', 't'], None, '', 'grep: character class syntax is [[:space:]], not [:space:]\n', 2),
    (['[[:nope:]]', 't'], None, '', 'grep: Invalid character class name\n', 2),
    (['[', 't'], None, '', 'grep: Invalid regular expression\n', 2),
    (['[a', 't'], None, '', 'grep: Unmatched [, [^, [:, [., or [=\n', 2),
    (['a\\', 't'], None, '', 'grep: Trailing backslash\n', 2),
    (['\\1', 't'], None, '', 'grep: Invalid back reference\n', 2),
    (['^\\(ab\\)\\1', 't'], None, 'abab\n', '', 0),
    (['-F', 'a.b', 't'], None, 'a.b\n', '', 0),
    (['-F', 'a.c', 't'], None, '', '', 1),
    (['-F', '-e', 'a+', '-e', 'x|y', 't'], None, 'a+\n', '', 0),
    (['x^y', 't'], None, 'x^y\n', '', 0),
    (['-E', 'x^y', 't'], None, '', '', 1),
    (['x$y', 't'], None, 'x$y\n', '', 0),
    (['[]a]x', 't'], None, ']x\n', '', 0),
    (['[a\\]', 't'], None, 'a|b\na+\nab\nabb\nabbb\na.b\nabab\n foo bar\na]\nb\\\na\\b\n(paren)\n', '', 0),
    (['-E', 'a**', 't'], None, 'foo\na|b\na+\nab\nabb\nabbb\na.b\nabab\n1 23 456\n foo bar\nFoo\nx^y\nx$y\n\n]x\na]\nb\\\na\\b\n(paren)\n*foo\n', '', 0),
    (['\\(a\\|b\\)\\{2\\}', 't'], None, 'ab\nabb\nabbb\nabab\n foo bar\n', '', 0),
    (['a\\{1', 't'], None, '', 'grep: Unmatched \\{\n', 2),
    (['a\\{2,1\\}', 't'], None, '', 'grep: Invalid content of \\{\\}\n', 2),
    (['[z-a]', 't'], None, '', 'grep: Invalid range end\n', 2),
    (['-E', '{1}', 't'], None, 'foo\na|b\na+\nab\nabb\nabbb\na.b\nabab\n1 23 456\n foo bar\nFoo\nx^y\nx$y\n\n]x\na]\nb\\\na\\b\n(paren)\n*foo\n', '', 0),
    (['-w', 'foo', 't'], None, 'foo\n foo bar\n*foo\n', '', 0),
    (['-x', 'foo', 't'], None, 'foo\n', '', 0),
    (['-n', 'foo', 't'], None, '1:foo\n10: foo bar\n20:*foo\n', '', 0),
    (['-L', 'foo', 't', 'c'], None, 'c\n', '', 0),
    (['-i', 'FOO\\|ZZZ', 't'], None, 'foo\n foo bar\nFoo\n*foo\n', '', 0),
    (['--color=auto', 'foo', 't'], None, 'foo\n foo bar\n*foo\n', '', 0),
    (['--colour', 'foo', 't'], None, 'foo\n foo bar\n*foo\n', '', 0),
    (['--color', 'foo', 't'], None, 'foo\n foo bar\n*foo\n', '', 0),
    (['--color=never', '-c', 'foo', 't'], None, '3\n', '', 0),
    (['--human', 'foo', 't'], None, '', "grep: unrecognized option '--human'\nUsage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.\n", 2),
    (['--count=1', 'foo', 't'], None, '', "grep: option '--count' doesn't allow an argument\nUsage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.\n", 2),
    (['-V'], None, 'grep (GNU grep) 3.7\nCopyright (C) 2021 Free Software Foundation, Inc.\nLicense GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\nThis is free software: you are free to change and redistribute it.\nThere is NO WARRANTY, to the extent permitted by law.\n\nWritten by Mike Haertel and others; see\n<https://git.sv.gnu.org/cgit/grep.git/tree/AUTHORS>.\n', '', 0),
    (['vga'], 'VGA x\n', '', '', 1),
    (['-i', 'vga'], 'VGA x\n', 'VGA x\n', '', 0),
    (['-q', 'lm'], 'flags: lm x\n', '', '', 0),
    (['-c', 'zzz'], 'a\n', '0\n', '', 1),
    (['-v', 'b'], 'a\nb\nc\n', 'a\nc\n', '', 0),
    (['-o', 'E5-[0-9]*'], 'model E5-2676 v3\n', 'E5-2676\n', '', 0),
]


class _Base:
    """The slice of HoneyPotCommand that Command_grep uses."""

    def write(self, data: str) -> None:
        self.out += data

    def writeBytes(self, data: bytes) -> None:
        self.out += data.decode("utf8")

    def errorWrite(self, data: str) -> None:
        self.err += data

    def exit(self, code: int | None = None) -> None:
        self.code = code


class _FS:
    def resolve_path(self, name: str, cwd: str) -> str:
        return posixpath.normpath(posixpath.join(cwd, name))

    def isdir(self, path: str) -> bool:
        return path in ("/tmp", "/")

    def file_contents(self, path: str) -> bytes:
        if path not in FILES:
            raise FileNotFoundError(path)
        return FILES[path].encode("utf8")


def load():
    tree = ast.parse(PATCH.read_text(encoding="utf-8"))
    new = next(n.value.value for n in tree.body if isinstance(n, ast.Assign)
               and getattr(n.targets[0], "id", "") == "NEW")
    ns = {"re": re, "getopt": getopt, "os": os, "HoneyPotCommand": _Base, "commands": {}}
    exec(compile("from __future__ import annotations\n" + new, str(PATCH), "exec"), ns)
    return ns


NS = load()


def run(args, stdin):
    cmd = NS["Command_grep"].__new__(NS["Command_grep"])
    cmd.args, cmd.cwd, cmd.fs = list(args), "/tmp", _FS()
    cmd.input_data = stdin.encode("utf8") if stdin is not None else None
    cmd.out = cmd.err = ""
    cmd.code = None
    cmd.start()
    return cmd.out, cmd.err, cmd.code


class GnuGrepTest(unittest.TestCase):
    def test_against_gnu_grep_3_7(self):
        for args, stdin, out, err, rc in GNU:
            with self.subTest(args=args, stdin=stdin):
                self.assertEqual(run(args, stdin), (out, err, rc))


class TranslatorTest(unittest.TestCase):
    def tr(self, pattern, extended=False):
        return NS["grep_translate"](pattern, extended)[0]

    def test_bre_operators_are_the_escaped_forms(self):
        self.assertTrue(re.search(self.tr(r"model name\|Hardware"), "Hardware\t: BCM"))
        self.assertIsNone(re.search(self.tr("a+"), "aa"))
        self.assertTrue(re.search(self.tr("a+"), "a+"))
        self.assertTrue(re.fullmatch(self.tr(r"[[:digit:]]\{2\}"), "23"))

    def test_ere_is_the_other_way_round(self):
        self.assertTrue(re.search(self.tr("a|b", True), "b"))
        self.assertIsNone(re.search(self.tr(r"a\|b", True), "b"))

    def test_back_references_shift_with_earlier_patterns(self):
        out, _, rc = run(["-e", r"\(x\)\1", "-e", r"\(a\)\1"], "aa\nxy\n")
        self.assertEqual((out, rc), ("aa\n", 0))


if __name__ == "__main__":
    unittest.main()
