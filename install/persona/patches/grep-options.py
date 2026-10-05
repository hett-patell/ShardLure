#!/usr/bin/env python3
"""Patch cowrie/commands/fs.py: GNU grep options and exit status.

WHY (payload-yield Phase B Task 4; factsheet-phaseB 2 ARCH/CPUS/GPU, 3 #19):
v3.1.1's grep accepts -i -q -c -v -l -o through getopt and then ignores them.
The SHELL_BEHAVIOR profiler (1,452 sessions in 30 days, one actor) asks
`lspci | grep -i vga` for its GPU field, which never matches the persona's
"VGA compatible controller"; its arch fallback `grep -q lm /proc/cpuinfo`
prints every flags line, and its cpus fallback `grep -c "^processor"` prints
the lines instead of 4. Every one of those is a cheap honeypot tell.

Supersedes grep-case-insensitive.py, whose anchor (grep_application) v3.1.1
refactored into compile_match. This patch replaces the whole Command_grep
class with one that follows GNU grep 3.7 (ubuntu:22.04), checked line by line
against the real binary:
  -i  case-insensitive          -q  silent; exit 0 on the first selected line
  -c  count per input           -v  select non-matching lines
  -l  name each matching input  -o  print each non-empty match
  -H/-h  force/suppress "file:" prefixes (default: more than one file);
         stock Cowrie treated -h as "print usage"
  -s  no file error messages    -e PATTERN, repeatable
  exit status 0 selected / 1 none / 2 on any error, unless -q selected a line
  GNU's usage errors on stderr with exit 2 (stock: a BSD usage text, exit 0)
Also: files win over a pipe ("-" names the pipe), a directory operand is
"grep: d: Is a directory", and a trailing newline no longer yields a phantom
empty last line. The pattern is compiled as given: stock v3.1.1 took its
os.path.basename() and dropped every '"'.

-m, the invalid-regex check and the exec-channel stdin log path are kept
from v3.1.1. Not emulated: -n -w -x -F -E/-P semantics beyond Python re,
-A/-B/-C context, -r. Nothing attacker-supplied is executed; the pattern
only ever reaches re.compile, as before.
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

NEW = r'''class Command_grep(HoneyPotCommand):
    """
    grep command

    ShardLure persona (grep-options.py): GNU grep 3.7's -i -q -c -v -l -o
    -H -h -s -e and its exit status (0 selected, 1 none, 2 error unless -q
    selected a line), and its usage errors. Stock v3.1.1 parsed these and ignored them, so the
    SHELL_BEHAVIOR profiler's `lspci | grep -i vga` matched nothing, its
    `grep -q lm /proc/cpuinfo` printed every flags line and its
    `grep -c "^processor"` printed lines instead of a count.
    """

    consumes_stdin = True

    interactive: bool = False
    matched: bool = False
    max_count: int | None = None
    match_count: int = 0
    ignore_case: bool = False
    quiet: bool = False
    count_only: bool = False
    invert: bool = False
    files_with_matches: bool = False
    only_matching: bool = False
    no_messages: bool = False
    show_names: bool = False
    listed: bool = False
    errored: bool = False

    STDIN_LABEL = "(standard input)"

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
        # The pattern as given: stock v3.1.1 took os.path.basename() of it
        # and dropped every '"', so `grep /bin/bash` searched for "bash".
        return re.compile(match.encode("utf8"), re.IGNORECASE if self.ignore_case else 0)

    def grep_application(self, contents: bytes, match: str, label: str | None = None) -> None:
        """One whole input: its lines, then its -c count."""
        label = self.STDIN_LABEL if label is None else label
        self.grep_lines(contents, match, label)
        self.grep_finish(label)

    def grep_lines(self, contents: bytes, match: str, label: str) -> None:
        if self.quiet and self.matched:
            return
        matcher = self.compile_match(match)
        lines = contents.split(b"\n")
        if lines[-1] == b"":
            # The newline ends the last line; it does not start an empty one
            # (which `grep -v x` would otherwise print).
            lines.pop()
        prefix = label.encode("utf8") + b":" if self.show_names else b""
        for line in lines:
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
            if self.files_with_matches:
                self.writeBytes(label.encode("utf8") + b"\n")
                self.listed = True
                break
            if self.count_only:
                continue
            if self.only_matching:
                # GNU -o prints each non-empty match; with -v there is no
                # match to print, only the exit status.
                if not self.invert:
                    for m in matcher.finditer(line):
                        if m.group(0):
                            self.writeBytes(prefix + m.group(0) + b"\n")
                continue
            self.writeBytes(prefix + line + b"\n")

    def grep_finish(self, label: str) -> None:
        if self.count_only and not self.quiet and not self.files_with_matches:
            prefix = f"{label}:" if self.show_names else ""
            self.write(f"{prefix}{self.match_count}\n")
        self.match_count = 0
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

    def start(self) -> None:
        if not self.args:
            self.help()
            self.exit(2)
            return

        try:
            optlist, args = getopt.gnu_getopt(
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
            if err.msg.startswith("option --"):
                self.errorWrite(f"grep: unrecognized option '--{err.opt}'\n")
            elif "requires argument" in err.msg:
                self.errorWrite(f"grep: option requires an argument -- '{err.opt}'\n")
            else:
                self.errorWrite(f"grep: invalid option -- '{err.opt}'\n")
            self.help()
            self.exit(2)
            return

        with_filename: bool | None = None
        patterns: list[str] = []
        for opt, arg in optlist:
            if opt == "-e":
                patterns.append(arg)
            elif opt == "-i":
                self.ignore_case = True
            elif opt == "-q":
                self.quiet = True
            elif opt == "-c":
                self.count_only = True
            elif opt == "-v":
                self.invert = True
            elif opt == "-l":
                self.files_with_matches = True
            elif opt == "-o":
                self.only_matching = True
            elif opt == "-s":
                self.no_messages = True
            elif opt == "-H":
                with_filename = True
            elif opt == "-h":
                # GNU: --no-filename, not help.
                with_filename = False
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

        if patterns:
            # -e PATTERN (repeatable): every operand is then a file.
            args = ["|".join(f"(?:{p})" for p in patterns), *args]
        if not args:
            # Options only, no pattern (e.g. `grep -i`).
            self.help()
            self.exit(2)
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
            self.grep_lines(line.encode("utf8") + b"\n", self.match, self.STDIN_LABEL)

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
                    self.grep_lines(f.read(), self.match, self.STDIN_LABEL)
            self.grep_finish(self.STDIN_LABEL)
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
    print(f"  [ok] {path}: patched (GNU grep options and exit status)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
