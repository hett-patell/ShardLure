#!/usr/bin/env python3
"""Patch cowrie/shell/{session,filetransfer}.py: one fake filesystem per connection.

WHY (measured on the arm deployment): scp droppers (RedTail, Outlaw) deliver a
payload on one SSH channel and run it on the next channel of the same
connection:
    channel 1: scp -t /bin/<random>     # upload (captured by ShardLure here)
    channel 2: /bin/<random>            # run it
All 26 prod `scp -t` sessions failed at channel 2. Cowrie v3.1.1 creates one
CowrieServer per authenticated connection (shell/realm.py), but Twisted builds
a new SSHSessionForCowrieUser for every session channel (shell/avatar.py
registers it as a plain ISession adapter), and its __init__ calls
server.initFileSystem() unconditionally, replacing server.fs with a fresh
HoneyPotFilesystem. The SFTP subsystem (SFTPServerForCowrieUser) does the same.
So channel 2 never sees what channel 1 wrote, and "No such file or directory"
for a file the client just uploaded is the honeypot tell.

Fix: build the filesystem only when the connection has none yet, and create a
temporary avatar's home only when it is missing (a second mkdir on the shared
tree would list it twice). CowrieServer is already per connection, so this is
exactly "the files a client wrote on this connection stay there", as on a real
box; another connection still gets its own pristine tree. The new-file quota
(fs.newcount) becomes per connection too, so opening more channels no longer
resets it.

Capture is unchanged: uploads still land in download_path(_uniq) under their
sha256 and the upload events are untouched; only the fake-FS view is shared.
Nothing is executed. A run of the uploaded binary is answered by
exec-emulation.py (exit 0, no output). scp-sink-target.py makes `scp -t <path>`
save to <path>, the other half of the same bot pattern.

Both files are checked before either is written: pristine -> apply, fully
patched -> [skip], anything else -> [FAIL] with nothing written.
"""
import sys
from pathlib import Path


# shell/session.py, SSHSessionForCowrieUser.__init__
OLD = """\
        self.server.initFileSystem(self.avatar.home)

        if self.avatar.temporary:
            self.server.fs.mkdir(
                self.avatar.home, self.uid, self.gid, 4096, stat.S_IFDIR | 0o755
            )
"""

NEW = """\
        # ShardLure (install/persona/patches/connection-shared-fs.py): every
        # session channel gets a new instance of this class, but the server is
        # per connection; build its filesystem once so a file scp'd on one
        # channel is still there when the next channel runs it.
        if self.server.fs is None:
            self.server.initFileSystem(self.avatar.home)

        if self.avatar.temporary and not self.server.fs.exists(self.avatar.home):
            self.server.fs.mkdir(
                self.avatar.home, self.uid, self.gid, 4096, stat.S_IFDIR | 0o755
            )
"""

# shell/filetransfer.py, SFTPServerForCowrieUser.__init__
OLD_SFTP = """\
        self.avatar = avatar
        self.avatar.server.initFileSystem(self.avatar.home)
        self.fs = self.avatar.server.fs
"""

NEW_SFTP = """\
        self.avatar = avatar
        # ShardLure (install/persona/patches/connection-shared-fs.py): share
        # the connection's filesystem with its shell/exec channels.
        if self.avatar.server.fs is None:
            self.avatar.server.initFileSystem(self.avatar.home)
        self.fs = self.avatar.server.fs
"""

TARGETS = (
    ("src/cowrie/shell/session.py", OLD, NEW),
    ("src/cowrie/shell/filetransfer.py", OLD_SFTP, NEW_SFTP),
)


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    home = Path(args[0])
    files = [(home / rel, old, new) for rel, old, new in TARGETS]
    contents = [path.read_text(encoding="utf-8") for path, _, _ in files]
    counts = [(c.count(old), c.count(new)) for c, (_, old, new) in zip(contents, files)]
    names = ", ".join(str(path) for path, _, _ in files)
    if all(c == (0, 1) for c in counts):
        print(f"  [skip] {names}: already patched")
        return 0
    if not all(c == (1, 0) for c in counts):
        print(
            f"  [FAIL] {names}: targets are neither pristine nor fully patched "
            f"(old/new counts {counts})",
            file=sys.stderr,
        )
        return 1
    if len(args) == 2:
        print(f"  [check] {names}: compatible")
        return 0
    for content, (path, old, new) in zip(contents, files):
        path.write_text(content.replace(old, new, 1), encoding="utf-8")
    print(f"  [ok] {names}: patched (one fake filesystem per connection)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
