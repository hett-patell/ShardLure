#!/usr/bin/env python3
"""Patch cowrie/commands/scp.py: `scp -t <path>` saves to <path>.

WHY (measured on the arm deployment): scp droppers (RedTail, Outlaw) upload
with `scp -t /bin/<random>` and then run `/bin/<random>`. The client sends a
C-record whose name is the LOCAL file's name (`C0755 <size> <name>`); the -t
argument is where the server must put it. Cowrie v3.1.1 reads args[0] only
under -d and otherwise saves the upload as <cwd>/<record name>, so the bot's
run of <path> finds nothing (26 of 26 prod scp sessions failed there). Together
with connection-shared-fs.py (the run arrives on a second channel) this is
the whole tell.

Fix, following OpenSSH's sink (scp.c sink(): targisdir from stat(targ)):
  - an existing directory target (`scp -t /tmp`, `scp -t /tmp/`) receives the
    file under the record's name, as before for -d;
  - any other target IS the destination path, for every record (OpenSSH
    writes each record to targ when it is not a directory);
  - a target with a trailing slash that is not a directory is refused, as
    open(2) refuses it on a real box (EISDIR, or ENOTDIR for a file).
-d keeps Cowrie's existing behaviour, and with no -t argument nothing changes.

Capture is unchanged: the bytes still land in download_path_uniq/<sha256>, and
the cowrie.session.file_upload event keeps its shasum/outfile; only the fake-FS
path (and so the event's destfile/url/filename) becomes the real target.
Nothing is executed; a run of the file is answered by exec-emulation.py.
"""
import sys
from pathlib import Path


# start(): remember the sink target (-t without -d).
OLD = """\
        self.out_dir = ""

        for opt in optlist:
            if opt[0] == "-d":
                self.out_dir = args[0]
                break
"""

NEW = """\
        self.out_dir = ""
        # ShardLure (install/persona/patches/scp-sink-target.py): the -t
        # argument is where OpenSSH's sink writes the upload.
        self.sink_target = ""

        for opt in optlist:
            if opt[0] == "-d":
                self.out_dir = args[0]
                break
        else:
            if ("-t", "") in optlist and args:
                self.sink_target = args[0]
"""

# parse_scp_data(): the destination of each C-record.
OLD_NAME = """\
                    if self.out_dir:
                        fname = posixpath.join(self.out_dir, scpname)
                    else:
                        fname = scpname
"""

NEW_NAME = """\
                    if self.out_dir:
                        fname = posixpath.join(self.out_dir, scpname)
                    elif self.sink_target:
                        # OpenSSH's sink: an existing directory gets the file
                        # under the record's name; anything else is the path.
                        target = self.fs.resolve_path(self.sink_target, self.cwd)
                        if self.fs.isdir(target):
                            fname = posixpath.join(self.sink_target, scpname)
                        elif self.sink_target.endswith("/"):
                            reason = ("Not a directory" if self.fs.exists(target)
                                      else "Is a directory")
                            self.errorWrite(f"scp: {self.sink_target}: {reason}\\n")
                            return b""
                        else:
                            fname = self.sink_target
                    else:
                        fname = scpname
"""

BLOCKS = ((OLD, NEW), (OLD_NAME, NEW_NAME))


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/commands/scp.py"
    content = path.read_text(encoding="utf-8")
    counts = [(content.count(old), content.count(new)) for old, new in BLOCKS]
    if all(c == (0, 1) for c in counts):
        print(f"  [skip] {path}: already patched")
        return 0
    if not all(c == (1, 0) for c in counts):
        print(
            f"  [FAIL] {path}: target is neither pristine nor fully patched "
            f"(old/new counts {counts})",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    for old, new in BLOCKS:
        content = content.replace(old, new, 1)
    path.write_text(content, encoding="utf-8")
    print(f"  [ok] {path}: patched (scp -t saves to its target)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
