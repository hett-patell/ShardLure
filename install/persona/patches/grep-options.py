#!/usr/bin/env python3
r"""Patch cowrie/commands/fs.py: GNU grep options, pattern dialects and exit status.

WHY (payload-yield Phase B Task 4; factsheet-phaseB 2 ARCH/CPUS/GPU, 3 #19):
v3.1.1's grep accepts -i -q -c -v -l -o through getopt and then ignores them.
The SHELL_BEHAVIOR profiler (1,452 sessions in 30 days, one actor) asks
`lspci | grep -i vga` for its GPU field, which never matches the persona's
"VGA compatible controller"; its arch fallback `grep -q lm /proc/cpuinfo`
prints every flags line, and its cpus fallback `grep -c "^processor"` prints
the lines instead of 4. Every one of those is a cheap honeypot tell.

Supersedes grep-case-insensitive.py, whose anchor (grep_application) v3.1.1
refactored into compile_match. This patch replaces the whole Command_grep
class (plus a pattern translator ahead of it) with one that follows GNU grep
3.7 (ubuntu:22.04), checked line by line against the real binary:
  -i  case-insensitive          -q  silent; exit 0 on the first selected line
  -c  count per input           -v  select non-matching lines
  -l/-L  name inputs with/without a selected line
  -o  print each non-empty match  -n  line numbers
  -w/-x  whole words / whole lines
  -H/-h  force/suppress "file:" prefixes (default: more than one file);
         stock Cowrie treated -h as "print usage"
  -s  no file error messages    -e PATTERN, repeatable; newline-separated
  --color/--colour[=WHEN]  accepted, no colour is emitted
  -V/--version, --help, --label, the common long option names
  exit status 0 selected / 1 none / 2 on any error, unless -q selected a line
  GNU's usage errors on stderr with exit 2 (stock: a BSD usage text, exit 0)
Pattern dialects: stock compiled the pattern as Python re (after taking its
os.path.basename() and dropping every '"'). It is now translated: the default
BRE (`\|` `\(` `\{` `\+` `\?` are operators, the bare forms literals, so
`grep "model name\|Hardware"` works), -E ERE, -F fixed strings, -P as Python
re. POSIX bracket classes, `\<` `\>` `\w` `\s` and back-references are
translated, and invalid patterns get regcomp's messages ("Unmatched ( or \(",
"Trailing backslash", ...).
Also: files win over a pipe ("-" names the pipe), a directory operand is
"grep: d: Is a directory", and a trailing newline no longer yields a phantom
empty last line.

-m, the exec-channel stdin log path and the up-front pattern check are kept
from v3.1.1. Not emulated: -r, -A/-B/-C context, -NUM, -z, binary-file
detection, colour output. Residual: matching is Python's backtracking re,
not GNU's DFA, so a pathological pattern on a long line (`(a+)+$`) can stall
the shared reactor, as it already could on stock. Nothing attacker-supplied
is executed; the pattern only ever reaches re.compile.
"""

import sys
from pathlib import Path

# v3.1.1's Command_grep, from the class line to its first registration.
OLD = r'''class Command_grep(HoneyPotCommand):
    """
    grep command
    """

    consumes_stdin = True

    interactive: bool = False
    matched: bool = False
    max_count: int | None = None
    match_count: int = 0

    def grep_get_contents(self, filename: str, match: str) -> None:
        try:
            contents = self.fs.file_contents(filename)
            self.grep_application(contents, match)
        except Exception:
            self.errorWrite(f"grep: {filename}: No such file or directory\n")

    def compile_match(self, match: str) -> re.Pattern[bytes]:
        bmatch = os.path.basename(match).replace('"', "").encode("utf8")
        return re.compile(bmatch)

    def grep_application(self, contents: bytes, match: str) -> None:
        matcher = self.compile_match(match)
        for line in contents.split(b"\n"):
            if self.max_count is not None and self.match_count >= self.max_count:
                break
            if matcher.search(line):
                self.matched = True
                self.match_count += 1
                self.writeBytes(line + b"\n")

    def help(self) -> None:
        self.writeBytes(
            b"usage: grep [-abcDEFGHhIiJLlmnOoPqRSsUVvwxZ] [-A num] [-B num] [-C[num]]\n"
        )
        self.writeBytes(
            b"\t[-e pattern] [-f file] [--binary-files=value] [--color=when]\n"
        )
        self.writeBytes(
            b"\t[--context[=num]] [--directories=action] [--label] [--line-buffered]\n"
        )
        self.writeBytes(b"\t[--null] [pattern] [file ...]\n")

    def start(self) -> None:
        if not self.args:
            self.help()
            self.exit()
            return

        try:
            optlist, args = getopt.getopt(
                self.args,
                "abcDEFGHhIiJLlnOoPqRSsUVvwxZA:B:C:e:f:m:",
                [
                    "binary-files=",
                    "color=",
                    "color",
                    "context=",
                    "directories=",
                    "label",
                    "line-buffered",
                ],
            )
        except getopt.GetoptError as err:
            self.errorWrite(f"grep: invalid option -- {err.opt}\n")
            self.help()
            self.exit()
            return

        for opt, arg in optlist:
            if opt == "-h":
                self.help()
            elif opt == "-m":
                try:
                    n = int(arg)
                except ValueError:
                    n = -1
                if n < 0:
                    self.errorWrite("grep: invalid max count\n")
                    self.exit(2)
                    return
                self.max_count = n

        if not args:
            # Options only, no pattern (e.g. `grep -h`).
            self.exit()
            return

        self.match = args[0]

        # grep validates the pattern before it reads any input, so a malformed
        # one is reported once rather than per file or per line of stdin.
        try:
            self.compile_match(self.match)
        except re.error:
            self.errorWrite("grep: Invalid regular expression\n")
            self.exit(2)
            return

        files = args[1:]

        if self.input_data is not None:
            self.grep_application(self.input_data, self.match)
        elif files:
            for pname in self.check_arguments("grep", files):
                self.grep_get_contents(pname, self.match)
        else:
            # No file and no pipe: read stdin until EOF.
            self.interactive = True
            return

        self.exit(0 if self.matched else 1)

    def lineReceived(self, line: str) -> None:
        self.protocol.events.dispatch(
            "cowrie.command.input",
            "INPUT (%(realm)s): %(input)s",
            realm="grep",
            input=line,
        )
        if self.interactive:
            self.grep_application(line.encode("utf8"), self.match)

    def eofReceived(self) -> None:
        if self.interactive:
            terminal = self.protocol.terminal
            if (
                getattr(terminal, "stdinlogOpen", False)
                and getattr(terminal, "stdinlogFile", "")
                and os.path.exists(terminal.stdinlogFile)
            ):
                # Live exec-channel stdin (e.g. `grep foo < file` over an ssh
                # exec): the bytes were streamed to the stdin log rather than
                # arriving via lineReceived, so match against them now.
                with open(terminal.stdinlogFile, "rb") as f:
                    self.grep_application(f.read(), self.match)
        self.exit(0 if self.matched else 1)


commands["/bin/grep"] = Command_grep
'''

NEW = r'''import signal as _grep_signal
import threading as _grep_threading
import time as _grep_time

# ShardLure persona (grep-options.py): a time budget per grep. Python's re
# backtracks; GNU grep's DFA does not. `printf 'aaa...a!' | grep -E '(a+)+$'`
# (40 bytes) would otherwise hold Cowrie's single reactor thread for hours:
# every session, and the JSON log ShardLure ingests, would freeze. CPython's
# sre checks for pending signals while it matches, so a SIGALRM interrupts it.
# The rule is upstream's bashparse _parse_alarm: only on the main thread, only
# while SIGALRM has its default handler and no real-time alarm is pending,
# always disarmed and the handler restored before returning.
GREP_BUDGET_SECONDS = 0.75
_GREP_HAS_ALARM = all(
    hasattr(_grep_signal, name) for name in ("SIGALRM", "ITIMER_REAL", "getitimer", "setitimer")
)


class GrepTimeout(Exception):
    """This grep's time budget ran out."""


def _grep_raise_timeout(signum: int, frame: object) -> None:
    raise GrepTimeout


def grep_alarm_usable() -> bool:
    if not _GREP_HAS_ALARM or _grep_threading.current_thread() is not _grep_threading.main_thread():
        return False
    if _grep_signal.getsignal(_grep_signal.SIGALRM) is not _grep_signal.SIG_DFL:
        return False
    delay, interval = _grep_signal.getitimer(_grep_signal.ITIMER_REAL)
    return not (delay or interval)


# ShardLure persona (grep-options.py): GNU grep 3.7's pattern dialects. Python
# re is neither BRE nor ERE, so every pattern is translated first: in the
# default BRE `\|` `\(` `\{` `\+` `\?` are the operators and the bare forms are
# literals (`grep "model name\|Hardware"` is a common recon idiom), ERE is the
# other way round, -F is literal. Error texts are glibc regcomp's.
GREP_POSIX_CLASSES = {
    "alpha": "a-zA-Z",
    "digit": "0-9",
    "alnum": "0-9A-Za-z",
    "upper": "A-Z",
    "lower": "a-z",
    "space": " \\t\\n\\r\\f\\v",
    "blank": " \\t",
    "punct": "".join("\\" + c for c in "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
    "print": "\\x20-\\x7e",
    "graph": "\\x21-\\x7e",
    "cntrl": "\\x00-\\x1f\\x7f",
    "xdigit": "0-9A-Fa-f",
}
GREP_DUP_MAX = 32767


class GrepPatternError(Exception):
    """A pattern GNU grep rejects; the message is GNU's."""


def _grep_bracket(pattern: str, i: int) -> tuple[str, int]:
    """Translate the bracket expression opening at pattern[i] == "[";
    return the Python class and the index just past its "]"."""
    n = len(pattern)
    j = i + 1
    if j >= n:
        raise GrepPatternError("Invalid regular expression")
    negate = pattern[j] == "^"
    if negate:
        j += 1
    start = j
    items: list[str] = []
    while True:
        if j >= n:
            raise GrepPatternError("Unmatched [, [^, [:, [., or [=")
        c = pattern[j]
        if c == "]" and j > start:
            break
        if c == "[" and j + 1 < n and pattern[j + 1] in ":=.":
            kind = pattern[j + 1]
            end = pattern.find(kind + "]", j + 2)
            if end < 0:
                raise GrepPatternError("Unmatched [, [^, [:, [., or [=")
            name = pattern[j + 2:end]
            j = end + 2
            if kind == ":":
                if name not in GREP_POSIX_CLASSES:
                    raise GrepPatternError("Invalid character class name")
                items.append(GREP_POSIX_CLASSES[name])
            else:
                items.append(re.escape(name))
            continue
        if (c != "]" or j == start) and j + 2 < n and pattern[j + 1] == "-" and pattern[j + 2] != "]":
            hi = pattern[j + 2]
            if hi == "[" and j + 3 < n and pattern[j + 3] in ".=":
                hi_end = pattern.find(pattern[j + 3] + "]", j + 4)
                if hi_end < 0:
                    raise GrepPatternError("Unmatched [, [^, [:, [., or [=")
                hi_name, after = pattern[j + 4:hi_end], hi_end + 2
                hi = hi_name if len(hi_name) == 1 else hi
            else:
                after = j + 3
            if ord(hi) < ord(c):
                raise GrepPatternError("Invalid range end")
            items.append(re.escape(c) + "-" + re.escape(hi))
            j = after
            continue
        items.append(re.escape(c))
        j += 1
    raw = pattern[start:j]
    if len(raw) >= 2 and raw[0] == ":" and raw[-1] == ":" and not negate:
        raise GrepPatternError(f"character class syntax is [[:space:]], not [{raw}]")
    return "[" + ("^" if negate else "") + "".join(items) + "]", j + 1


def grep_translate(pattern: str, extended: bool, group_base: int = 0) -> tuple[str, int]:
    """Translate one GNU BRE (or, with `extended`, ERE) to Python re.

    Returns the translation and its number of capturing groups (later
    patterns' back-references are shifted by it).
    """
    out: list[str] = []
    n = len(pattern)
    i = 0
    open_groups: list[int] = []  # out index of each open "("
    closed = 0
    atom: int | None = None  # out index where the last repeatable atom starts
    quantified = False
    at_start = True  # start of the RE, of a group or of an alternative

    def literal(text: str) -> None:
        nonlocal atom, quantified, at_start
        atom = len(out)
        out.append(re.escape(text))
        quantified = at_start = False

    def quantify(q: str) -> None:
        nonlocal quantified
        assert atom is not None
        if quantified and q in "*+?" and out[-1] in ("*", "+", "?"):
            # a**, a+*, a?+ ...: one simple repetition (collapsed rather than
            # re-wrapped, which is quadratic on `a` and 100k stars).
            out[-1] = q if q == out[-1] else "*"
            return
        if quantified:
            # GNU accepts stacked repetition (a{2}*); Python does not.
            out[atom:] = ["(?:" + "".join(out[atom:]) + ")"]
        out.append(q)
        quantified = True

    def interval(i: int, close: str) -> tuple[str | None, int]:
        """Parse "m}", "m,}", ",n}", "m,n}" after the opening brace (close
        is "}" or "\\}"); None when it is not a valid interval."""
        end = pattern.find(close, i)
        if end < 0:
            return None, i
        body = pattern[i:end]
        m = re.fullmatch(r"(\d*)(,?)(\d*)", body)
        if not m or (not m.group(1) and not m.group(3) and not m.group(2)):
            return None, i
        lo = int(m.group(1) or 0)
        hi = m.group(3)
        if not m.group(2):
            hi = m.group(1)
        if lo > GREP_DUP_MAX or (hi and int(hi) > GREP_DUP_MAX):
            raise GrepPatternError("Regular expression too big")
        if hi and int(hi) < lo:
            return "!", i
        return "{%d,%s}" % (lo, hi) if m.group(2) else "{%d}" % lo, end + len(close)

    while i < n:
        c = pattern[i]
        if c == "\\":
            if i + 1 >= n:
                raise GrepPatternError("Trailing backslash")
            d = pattern[i + 1]
            i += 2
            if not extended and d == "(":
                c = "("
            elif not extended and d == ")":
                c = ")"
            elif not extended and d == "|":
                c = "|"
            elif not extended and d == "{":
                if atom is None:
                    literal("{")
                    continue
                q, nxt = interval(i, "\\}")
                if q is None:
                    if pattern.find("\\}", i) < 0:
                        raise GrepPatternError("Unmatched \\{")
                    raise GrepPatternError("Invalid content of \\{\\}")
                if q == "!":
                    raise GrepPatternError("Invalid content of \\{\\}")
                quantify(q)
                i = nxt
                continue
            elif not extended and d in "+?":
                if atom is None:
                    literal(d)
                else:
                    quantify(d)
                continue
            elif d in "123456789":
                if int(d) > closed:
                    raise GrepPatternError("Invalid back reference")
                atom = len(out)
                out.append("(?:\\%d)" % (int(d) + group_base))
                quantified = at_start = False
                continue
            elif d == "<":
                out.append(r"\b(?=\w)")
                atom, quantified = None, False
                continue
            elif d == ">":
                out.append(r"\b(?<=\w)")
                atom, quantified = None, False
                continue
            elif d in "bB":
                out.append("\\" + d)
                atom, quantified = None, False
                continue
            elif d == "`":
                out.append(r"\A")
                atom, quantified = None, False
                continue
            elif d == "'":
                out.append(r"\Z")
                atom, quantified = None, False
                continue
            elif d in "wWsS":
                atom = len(out)
                out.append("\\" + d)
                quantified = at_start = False
                continue
            else:
                literal(d)
                continue
            i -= 1  # an operator: handled below as if unescaped
        elif not extended and c in "()|{}+?":
            literal(c)
            i += 1
            continue
        i += 1
        if c == "(":
            open_groups.append(len(out))
            out.append("(")
            atom, quantified, at_start = None, False, True
        elif c == ")":
            if not open_groups:
                if extended:
                    literal(")")
                    continue
                raise GrepPatternError("Unmatched ) or \\)")
            atom = open_groups.pop()
            out.append(")")
            closed += 1
            quantified = at_start = False
        elif c == "|":
            out.append("|")
            atom, quantified, at_start = None, False, True
        elif c == "{":  # ERE only
            q, nxt = interval(i, "}")
            if q == "!":
                raise GrepPatternError("Invalid content of \\{\\}")
            if q is None:
                literal("{")
                continue
            if atom is not None:
                quantify(q)
            # else: a leading ERE interval is ignored, like a leading "*"
            i = nxt
        elif c in "*+?":
            if atom is None:
                if extended:
                    if c in "*?" and out and out[-1] in ("^", "$"):
                        out.pop()  # (^)* matches the empty string anywhere
                    continue  # GNU ignores a leading ERE repetition
                literal(c)  # a leading BRE "*" is literal
                continue
            quantify(c)
        elif c == "^":
            if extended or at_start:
                out.append("^")
                atom, quantified, at_start = None, False, extended
            else:
                literal("^")
        elif c == "$":
            rest = pattern[i:]
            if extended or not rest or rest.startswith("\\)") or rest.startswith("\\|"):
                out.append("$")
                atom, quantified = None, False
            else:
                literal("$")
        elif c == ".":
            atom = len(out)
            out.append(".")
            quantified = at_start = False
        elif c == "[":
            cls, i = _grep_bracket(pattern, i - 1)
            atom = len(out)
            out.append(cls)
            quantified = at_start = False
        else:
            literal(c)
    if open_groups:
        raise GrepPatternError("Unmatched ( or \\(")
    return "".join(out), closed


GREP_LONGOPTS = {
    # long name (with "=" when it takes a value) -> the short option it means
    "extended-regexp": "-E", "fixed-strings": "-F", "basic-regexp": "-G",
    "perl-regexp": "-P", "regexp=": "-e", "file=": "-f", "ignore-case": "-i",
    "word-regexp": "-w", "line-regexp": "-x", "no-messages": "-s",
    "invert-match": "-v", "version": "-V", "help": "--help",
    "max-count=": "-m", "line-number": "-n", "with-filename": "-H",
    "no-filename": "-h", "only-matching": "-o", "quiet": "-q", "silent": "-q",
    "files-without-match": "-L", "files-with-matches": "-l", "count": "-c",
    "label=": "--label", "color=": "--color", "colour=": "--color",
    "binary-files=": "--binary-files", "context=": "-C",
    "before-context=": "-B", "after-context=": "-A", "directories=": "-d",
    "line-buffered": "--line-buffered", "text": "-a", "null": "-Z",
}

GREP_VERSION = """grep (GNU grep) 3.7
Copyright (C) 2021 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by Mike Haertel and others; see
<https://git.sv.gnu.org/cgit/grep.git/tree/AUTHORS>.
"""

GREP_HELP = """Usage: grep [OPTION]... PATTERNS [FILE]...
Search for PATTERNS in each FILE.
Example: grep -i 'hello world' menu.h main.c
PATTERNS can contain multiple patterns separated by newlines.

Pattern selection and interpretation:
  -E, --extended-regexp     PATTERNS are extended regular expressions
  -F, --fixed-strings       PATTERNS are strings
  -G, --basic-regexp        PATTERNS are basic regular expressions
  -P, --perl-regexp         PATTERNS are Perl regular expressions
  -e, --regexp=PATTERNS     use PATTERNS for matching
  -f, --file=FILE           take PATTERNS from FILE
  -i, --ignore-case         ignore case distinctions in patterns and data
      --no-ignore-case      do not ignore case distinctions (default)
  -w, --word-regexp         match only whole words
  -x, --line-regexp         match only whole lines
  -z, --null-data           a data line ends in 0 byte, not newline

Miscellaneous:
  -s, --no-messages         suppress error messages
  -v, --invert-match        select non-matching lines
  -V, --version             display version information and exit
      --help                display this help text and exit

Output control:
  -m, --max-count=NUM       stop after NUM selected lines
  -b, --byte-offset         print the byte offset with output lines
  -n, --line-number         print line number with output lines
      --line-buffered       flush output on every line
  -H, --with-filename       print file name with output lines
  -h, --no-filename         suppress the file name prefix on output
      --label=LABEL         use LABEL as the standard input file name prefix
  -o, --only-matching       show only nonempty parts of lines that match
  -q, --quiet, --silent     suppress all normal output
      --binary-files=TYPE   assume that binary files are TYPE;
                            TYPE is 'binary', 'text', or 'without-match'
  -a, --text                equivalent to --binary-files=text
  -I                        equivalent to --binary-files=without-match
  -d, --directories=ACTION  how to handle directories;
                            ACTION is 'read', 'recurse', or 'skip'
  -D, --devices=ACTION      how to handle devices, FIFOs and sockets;
                            ACTION is 'read' or 'skip'
  -r, --recursive           like --directories=recurse
  -R, --dereference-recursive  likewise, but follow all symlinks
      --include=GLOB        search only files that match GLOB (a file pattern)
      --exclude=GLOB        skip files that match GLOB
      --exclude-from=FILE   skip files that match any file pattern from FILE
      --exclude-dir=GLOB    skip directories that match GLOB
  -L, --files-without-match  print only names of FILEs with no selected lines
  -l, --files-with-matches  print only names of FILEs with selected lines
  -c, --count               print only a count of selected lines per FILE
  -T, --initial-tab         make tabs line up (if needed)
  -Z, --null                print 0 byte after FILE name

Context control:
  -B, --before-context=NUM  print NUM lines of leading context
  -A, --after-context=NUM   print NUM lines of trailing context
  -C, --context=NUM         print NUM lines of output context
  -NUM                      same as --context=NUM
      --group-separator=SEP  print SEP on line between matches with context
      --no-group-separator  do not print separator for matches with context
      --color[=WHEN],
      --colour[=WHEN]       use markers to highlight the matching strings;
                            WHEN is 'always', 'never', or 'auto'
  -U, --binary              do not strip CR characters at EOL (MSDOS/Windows)

When FILE is '-', read standard input.  With no FILE, read '.' if
recursive, '-' otherwise.  With fewer than two FILEs, assume -h.
Exit status is 0 if any line is selected, 1 otherwise;
if any error occurs and -q is not given, the exit status is 2.

Report bugs to: bug-grep@gnu.org
GNU grep home page: <https://www.gnu.org/software/grep/>
General help using GNU software: <https://www.gnu.org/gethelp/>
"""

GREP_COLORS = ("always", "yes", "force", "never", "no", "none", "auto", "tty", "if-tty")


class Command_grep(HoneyPotCommand):
    """
    grep command

    ShardLure persona (grep-options.py): GNU grep 3.7's options, pattern
    dialects (BRE, -E, -F, -P as Python re), exit status (0 selected, 1
    none, 2 error unless -q selected a line) and usage errors. Stock v3.1.1
    parsed -i -q -c -v -l -o and ignored them, so the SHELL_BEHAVIOR
    profiler's `lspci | grep -i vga` matched nothing, its
    `grep -q lm /proc/cpuinfo` printed every flags line and its
    `grep -c "^processor"` printed lines instead of a count.
    """

    consumes_stdin = True

    interactive: bool = False
    matched: bool = False
    max_count: int | None = None
    match_count: int = 0
    line_no: int = 0
    ignore_case: bool = False
    quiet: bool = False
    count_only: bool = False
    invert: bool = False
    list_mode: str | None = None  # "-l" or "-L"
    only_matching: bool = False
    no_messages: bool = False
    line_numbers: bool = False
    show_names: bool = False
    listed: bool = False
    errored: bool = False
    dialect: str = "-G"
    whole: str | None = None  # "-w" or "-x"
    match_nothing: bool = False  # -f with an empty pattern file
    timed_out: bool = False
    budget_left: float = GREP_BUDGET_SECONDS
    stdin_label: str = "(standard input)"

    def grep_get_contents(self, filename: str, match: str, label: str | None = None) -> None:
        try:
            contents = self.fs.file_contents(filename)
        except Exception:
            self.grep_error(f"grep: {label or filename}: No such file or directory\n")
            return
        self.grep_application(contents, match, label or filename)

    def grep_error(self, message: str) -> None:
        self.errored = True
        if not self.no_messages:
            self.errorWrite(message)

    def compile_match(self, match: str) -> re.Pattern[bytes]:
        """The selected dialect, translated to Python re; raises
        GrepPatternError (GNU's message) or re.error."""
        if self.match_nothing:
            return re.compile(b"(?!)")
        parts: list[str] = []
        groups = 0
        # PATTERNS can hold several patterns separated by newlines (repeated
        # -e options are joined that way).
        for p in match.split("\n"):
            if self.dialect == "-F":
                parts.append(re.escape(p))
            elif self.dialect == "-P":
                parts.append(p)
            else:
                text, count = grep_translate(p, self.dialect == "-E", groups)
                parts.append(text)
                groups += count
        regex = "|".join(f"(?:{p})" for p in parts)
        if self.whole == "-x":
            regex = f"^(?:{regex})$"
        elif self.whole == "-w":
            regex = rf"(?<!\w)(?:{regex})(?!\w)"
        return re.compile(regex.encode("utf8"), re.IGNORECASE if self.ignore_case else 0)

    def grep_application(self, contents: bytes, match: str, label: str | None = None) -> None:
        """One whole input: its lines, then its -c count or -L name."""
        label = self.stdin_label if label is None else label
        self.grep_lines(contents, match, label)
        self.grep_finish(label)

    def grep_bounded(self, fn) -> bool:
        """Run fn() within what is left of this grep's time budget. False
        when the budget ran out (fn was interrupted)."""
        if self.timed_out:
            return False
        if not grep_alarm_usable():
            fn()  # another component owns SIGALRM: unbounded, as upstream
            return True
        if self.budget_left <= 0:
            return self.grep_timeout()
        started = _grep_time.monotonic()
        previous = _grep_signal.signal(_grep_signal.SIGALRM, _grep_raise_timeout)
        try:
            try:
                _grep_signal.setitimer(_grep_signal.ITIMER_REAL, self.budget_left)
                try:
                    fn()
                finally:
                    _grep_signal.setitimer(_grep_signal.ITIMER_REAL, 0)
            finally:
                _grep_signal.signal(_grep_signal.SIGALRM, previous)
                self.budget_left -= _grep_time.monotonic() - started
        except GrepTimeout:
            return self.grep_timeout()
        return True

    def grep_timeout(self) -> bool:
        """The budget ran out: stop matching and finish as if nothing more
        was selected (a real grep would say so for the pathological inputs
        that get here). Logged for the operator, invisible to the client."""
        if not self.timed_out:
            self.timed_out = True
            log = getattr(self, "_log", None)
            if log is not None:
                log.info("grep: matching stopped after {s}s budget", s=GREP_BUDGET_SECONDS)
        return False

    def grep_lines(self, contents: bytes, match: str, label: str) -> None:
        if (self.quiet and self.matched) or self.timed_out:
            return
        if getattr(self, "matcher", None) is None:
            compiled: list[re.Pattern[bytes]] = []
            if not self.grep_bounded(lambda: compiled.append(self.compile_match(match))):
                return
            self.matcher = compiled[0]
        lines = contents.split(b"\n")
        if lines[-1] == b"":
            # The newline ends the last line; it does not start an empty one
            # (which `grep -v x` would otherwise print).
            lines.pop()
        # Output is collected and written after the alarm is disarmed, so a
        # timeout can never land inside a transport write.
        pending: list[bytes] = []
        self.grep_bounded(lambda: self.grep_scan(lines, label, pending))
        for chunk in pending:
            self.writeBytes(chunk)

    def grep_scan(self, lines: list[bytes], label: str, pending: list[bytes]) -> None:
        matcher = self.matcher
        name = label.encode("utf8") + b":" if self.show_names else b""
        for line in lines:
            self.line_no += 1
            if self.listed:
                break
            if self.max_count is not None and self.match_count >= self.max_count:
                break
            if bool(matcher.search(line)) == self.invert:
                continue
            self.matched = True
            self.match_count += 1
            if self.quiet:
                break
            if self.list_mode:
                if self.list_mode == "-l":
                    pending.append(label.encode("utf8") + b"\n")
                self.listed = True
                break
            if self.count_only:
                continue
            prefix = name + (b"%d:" % self.line_no if self.line_numbers else b"")
            if self.only_matching:
                # GNU -o prints each non-empty match; with -v there is no
                # match to print, only the exit status.
                if not self.invert:
                    for m in matcher.finditer(line):
                        if m.group(0):
                            pending.append(prefix + m.group(0) + b"\n")
                continue
            pending.append(prefix + line + b"\n")

    def grep_finish(self, label: str) -> None:
        if self.list_mode == "-L" and not self.match_count and not self.quiet:
            self.write(f"{label}\n")
        elif self.count_only and not self.quiet and not self.list_mode:
            prefix = f"{label}:" if self.show_names else ""
            self.write(f"{prefix}{self.match_count}\n")
        self.match_count = 0
        self.line_no = 0
        self.listed = False

    def grep_status(self) -> int:
        if self.quiet and self.matched:
            return 0
        if self.errored:
            return 2
        return 0 if self.matched else 1

    def help(self) -> None:
        self.errorWrite(
            "Usage: grep [OPTION]... PATTERNS [FILE]...\n"
            "Try 'grep --help' for more information.\n"
        )

    @staticmethod
    def getopt_message(err: getopt.GetoptError) -> str:
        """glibc getopt_long's wording for Python getopt's errors."""
        msg, opt = err.msg, err.opt
        if msg.startswith("option --"):
            if "not a unique prefix" in msg:
                names = " ".join(
                    f"'--{name.rstrip('=')}'" for name in GREP_LONGOPTS if name.startswith(opt)
                )
                return f"option '--{opt}' is ambiguous; possibilities: {names}"
            if "requires argument" in msg:
                return f"option '--{opt}' requires an argument"
            if "must not have an argument" in msg:
                return f"option '--{opt}' doesn't allow an argument"
            return f"unrecognized option '--{opt}'"
        if "requires argument" in msg:
            return f"option requires an argument -- '{opt}'"
        return f"invalid option -- '{opt}'"

    @staticmethod
    def color_prepass(args: list[str]) -> list[str]:
        """--color/--colour take an OPTIONAL value, which Python getopt cannot
        express: a bare one (or an abbreviation) means --color=auto."""
        out: list[str] = []
        takes_value = False
        for k, a in enumerate(args):
            if takes_value:
                takes_value = False
            elif a == "--":
                return out + args[k:]
            elif m := re.fullmatch(r"--(col|colo|color|colou|colour)(=.*)?", a):
                a = "--color" + (m.group(2) if m.group(2) is not None else "=auto")
            elif a in ("-e", "-f", "-m", "-A", "-B", "-C", "-d"):
                takes_value = True
            out.append(a)
        return out

    def start(self) -> None:
        if not self.args:
            self.help()
            self.exit(2)
            return

        try:
            optlist, args = getopt.gnu_getopt(
                self.color_prepass(list(self.args)),
                "abcDEFGHhIiJLlnOoPqRSsUVvwxZA:B:C:d:e:f:m:",
                list(GREP_LONGOPTS),
            )
        except getopt.GetoptError as err:
            self.errorWrite(f"grep: {self.getopt_message(err)}\n")
            self.help()
            self.exit(2)
            return

        with_filename: bool | None = None
        patterns: list[str] = []
        from_file = False
        for opt, arg in optlist:
            if opt.startswith("--"):
                opt = GREP_LONGOPTS.get(opt[2:] + "=", GREP_LONGOPTS.get(opt[2:], opt))
            if opt == "-e":
                patterns.append(arg)
            elif opt == "-f":
                # Patterns from a file of the FAKE filesystem, one per line;
                # an empty file contributes none (and so matches nothing).
                path = self.fs.resolve_path(arg, self.cwd)
                try:
                    if self.fs.isdir(path):
                        raise IsADirectoryError
                    text = self.fs.file_contents(path).decode("utf8", "surrogateescape")
                except IsADirectoryError:
                    self.errorWrite(f"grep: {arg}: Is a directory\n")
                    self.exit(2)
                    return
                except Exception:
                    self.errorWrite(f"grep: {arg}: No such file or directory\n")
                    self.exit(2)
                    return
                from_file = True
                patterns.extend(text[:-1].split("\n") if text.endswith("\n") else
                                text.split("\n") if text else [])
            elif opt in ("-E", "-F", "-G", "-P"):
                self.dialect = opt
            elif opt in ("-w", "-x"):
                if self.whole != "-x":  # -x wins over -w in any order
                    self.whole = opt
            elif opt == "-i":
                self.ignore_case = True
            elif opt == "-q":
                self.quiet = True
            elif opt == "-c":
                self.count_only = True
            elif opt == "-v":
                self.invert = True
            elif opt in ("-l", "-L"):
                self.list_mode = opt
            elif opt == "-o":
                self.only_matching = True
            elif opt == "-n":
                self.line_numbers = True
            elif opt == "-s":
                self.no_messages = True
            elif opt == "-H":
                with_filename = True
            elif opt == "-h":
                # GNU: --no-filename, not help.
                with_filename = False
            elif opt == "--binary-files":
                if arg not in ("binary", "text", "without-match"):
                    self.errorWrite("grep: unknown binary-files type\n")
                    self.exit(2)
                    return
            elif opt == "--label":
                self.stdin_label = arg
            elif opt == "--color":
                # Accepted and ignored: no colour codes are emitted.
                if arg not in GREP_COLORS:
                    # grep 3.7 answers a bad WHEN with its full help, exit 0.
                    self.write(GREP_HELP)
                    self.exit(0)
                    return
            elif opt == "-V":
                self.write(GREP_VERSION)
                self.exit(0)
                return
            elif opt == "--help":
                self.write(GREP_HELP)
                self.exit(0)
                return
            elif opt == "-m":
                try:
                    n = int(arg)
                except ValueError:
                    n = -1
                if n < 0:
                    self.errorWrite("grep: invalid max count\n")
                    self.exit(2)
                    return
                self.max_count = n

        if patterns or from_file:
            # -e PATTERN / -f FILE (repeatable): every operand is then a file.
            self.match_nothing = not patterns
            args = ["\n".join(patterns), *args]
        if not args:
            # Options only, no pattern (e.g. `grep -i`).
            self.help()
            self.exit(2)
            return

        self.match = args[0]

        # grep validates the pattern before it reads any input, so a malformed
        # one is reported once rather than per file or per line of stdin.
        try:
            compiled: list[re.Pattern[bytes]] = []
            if not self.grep_bounded(lambda: compiled.append(self.compile_match(self.match))):
                # Only a pathological pattern gets here; GNU's own answer to
                # a regex it cannot build is this message.
                self.errorWrite("grep: memory exhausted\n")
                self.exit(2)
                return
            self.matcher = compiled[0]
        except GrepPatternError as err:
            self.errorWrite(f"grep: {err}\n")
            self.exit(2)
            return
        except (re.error, RecursionError, OverflowError):
            self.errorWrite("grep: Invalid regular expression\n")
            self.exit(2)
            return

        files = args[1:]
        self.show_names = len(files) > 1 if with_filename is None else with_filename

        if files:
            # Files win over a pipe, as in GNU grep; "-" names the pipe.
            for name in files:
                if self.quiet and self.matched:
                    break
                if name == "-":
                    self.grep_application(self.input_data or b"", self.match)
                    continue
                path = self.fs.resolve_path(name, self.cwd)
                if self.fs.isdir(path):
                    self.grep_error(f"grep: {name}: Is a directory\n")
                    continue
                self.grep_get_contents(path, self.match, name)
        elif self.input_data is not None:
            self.grep_application(self.input_data, self.match)
        else:
            # No file and no pipe: read stdin until EOF.
            self.interactive = True
            return

        self.exit(self.grep_status())

    def lineReceived(self, line: str) -> None:
        self.protocol.events.dispatch(
            "cowrie.command.input",
            "INPUT (%(realm)s): %(input)s",
            realm="grep",
            input=line,
        )
        if self.interactive:
            self.grep_lines(line.encode("utf8") + b"\n", self.match, self.stdin_label)

    def eofReceived(self) -> None:
        if self.interactive:
            terminal = self.protocol.terminal
            if (
                getattr(terminal, "stdinlogOpen", False)
                and getattr(terminal, "stdinlogFile", "")
                and os.path.exists(terminal.stdinlogFile)
            ):
                # Live exec-channel stdin (e.g. `grep foo < file` over an ssh
                # exec): the bytes were streamed to the stdin log rather than
                # arriving via lineReceived, so match against them now.
                with open(terminal.stdinlogFile, "rb") as f:
                    self.grep_lines(f.read(), self.match, self.stdin_label)
            self.grep_finish(self.stdin_label)
        self.exit(self.grep_status())


commands["/bin/grep"] = Command_grep
'''


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/commands/fs.py"
    content = path.read_text(encoding="utf-8")
    old, new = content.count(OLD), content.count(NEW)
    if (old, new) == (0, 1):
        print(f"  [skip] {path}: already patched")
        return 0
    if (old, new) != (1, 0):
        print(
            f"  [FAIL] {path}: target is neither pristine nor fully patched "
            f"(old/new counts {(old, new)}) - upstream grep changed",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    path.write_text(content.replace(OLD, NEW, 1), encoding="utf-8")
    print(f"  [ok] {path}: patched (GNU grep options, dialects and exit status)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
