#!/usr/bin/env python3
"""Patch Cowrie for one fake filesystem per connection, not per channel.

Touches shell/session.py, shell/filetransfer.py, insults/insults.py,
shell/pipe.py and shell/fs.py.

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

Sharing the tree makes several per-channel lifetimes visible across channels,
found on the Task 3b rehearsal and review (insults.py, pipe.py, fs.py and
protocol.py blocks):
  - A redirection (`echo x > f`, sed -i) writes a temp file
    download_path/redir_<uuid> and points the node at it; when the CHANNEL
    closes, LoggingServerProtocol.connectionLost renames it to <sha256> (or
    deletes it if empty). The node still named the temp file, so `cat f` on
    the next channel raised FileNotFoundError and hung the session. The nodes
    are now re-pointed at the finalised file (an empty one reads as empty).
  - pipe.py reuses a node's existing backing file for a redirection,
    truncating or appending in place. For a file backed by a finished capture
    (download_path*/<sha256>: an scp/SFTP upload, a wget/curl download, a
    finalised redirection) that rewrote the captured, possibly deduplicated,
    bytes under their old hash. Upstream already did this within one channel
    (`scp -t x; echo > x`); sharing would extend it to `> /tmp/x` on a later
    channel, and to an SFTP upload still open on another channel, whose temp
    file was truncated and then renamed at the redirecting channel's close,
    so the upload itself was never captured (review I-1). Now only a redir_
    temp this channel created is written in place; every other backing is
    copied on write: a fresh redir backing (with the old bytes first for
    `>>`, and the old mode). The new node takes the writer's owner and ctime
    (bash keeps the owner; it is root over root's file in practice). With
    each channel owning its backing, concurrent channels redirecting into
    one file no longer split it across captures.
  - An SFTP upload's node kept naming the temp file close() had just renamed
    or removed (update_realfile() never replaces a set path), so reading it
    on a later channel raised FileNotFoundError too. close() now names the
    finished capture (fs.py block).
  - /proc/uptime was registered as a bound method of the last channel to
    open; once that channel closed, reading it on a channel still open
    printed nothing (review I-2). It is now a function of the factory's
    start time and the shared fs (protocol.py block).

Capture is otherwise unchanged: uploads still land in download_path(_uniq)
under their sha256 and the upload events are untouched; only the fake-FS view
is shared. Nothing is executed. A run of the uploaded binary is answered by
exec-emulation.py (exit 0, no output). scp-sink-target.py makes
`scp -t <path>` save to <path>, the other half of the same bot pattern.

Every file is checked before any is written: pristine -> apply, fully
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

# insults/insults.py, LoggingServerProtocol.connectionLost: re-point nodes
# at the finalised redirection files.
OLD_REDIR = """\
        if self.redirFiles:
            for rp in self.redirFiles:
                rf = rp[0]

                if rp[1]:
                    url = rp[1]
                else:
                    url = rf[rf.find("redir_") + len("redir_") :]

                try:
                    if not os.path.exists(rf):
                        continue

                    if os.path.getsize(rf) == 0:
                        os.remove(rf)
                        continue

                    with open(rf, "rb") as f:
                        shasum = hashlib.sha256(f.read()).hexdigest()
                    shasumfile = os.path.join(self.downloadPath, shasum)
                    if os.path.exists(shasumfile):
                        os.remove(rf)
                        duplicate = True
                    else:
                        os.rename(rf, shasumfile)
                        duplicate = False
"""

NEW_REDIR = """\
        if self.redirFiles:
            # ShardLure (install/persona/patches/connection-shared-fs.py): the
            # fake filesystem outlives this channel, so its nodes must stop
            # naming the temp files finalised (renamed or deleted) below.
            moved: dict[str, str | None] = {}
            for rp in self.redirFiles:
                rf = rp[0]

                if rp[1]:
                    url = rp[1]
                else:
                    url = rf[rf.find("redir_") + len("redir_") :]

                try:
                    if not os.path.exists(rf):
                        continue

                    if os.path.getsize(rf) == 0:
                        os.remove(rf)
                        moved[rf] = None
                        continue

                    with open(rf, "rb") as f:
                        shasum = hashlib.sha256(f.read()).hexdigest()
                    shasumfile = os.path.join(self.downloadPath, shasum)
                    if os.path.exists(shasumfile):
                        os.remove(rf)
                        duplicate = True
                    else:
                        os.rename(rf, shasumfile)
                        duplicate = False
                    moved[rf] = shasumfile
"""

OLD_REDIR_END = """\
                except OSError:
                    pass
            self.redirFiles.clear()
"""

NEW_REDIR_END = """\
                except OSError:
                    pass
            if moved:
                try:
                    from cowrie.shell.fs import A_CONTENTS, A_REALFILE, A_TYPE, T_DIR

                    stack = [self.terminalProtocol.fs.fs]
                    while stack:
                        node = stack.pop()
                        if node[A_TYPE] == T_DIR:
                            stack.extend(node[A_CONTENTS])
                        elif node[A_REALFILE] in moved:
                            node[A_REALFILE] = moved[node[A_REALFILE]]
                except Exception:
                    # Logged, not raised: a failure here brings back the
                    # cross-channel FileNotFoundError hang, so leave a trace.
                    self._log.failure(
                        "connection-shared-fs: re-pointing redirected files failed"
                    )
            self.redirFiles.clear()
"""

# shell/pipe.py, PipeProtocol._prepare_output_file: write in place only into
# this channel's own redirection temp; copy anything else on write.
OLD_PIPE = """\
        start_size = p[fs.A_SIZE] if p and append else 0

        if self._needs_new_backing(p):
            safeoutfile = self._create_redirect_target(outfile)
            if safeoutfile is None:
                return None
        else:
"""

NEW_PIPE = """\
        start_size = p[fs.A_SIZE] if p and append else 0

        # ShardLure (install/persona/patches/connection-shared-fs.py): write
        # in place only into a redir_ temp this channel created; anything
        # else (a finished <sha256> capture, another channel's in-flight SFTP
        # or redirection temp, a honeyfs file) gets a fresh backing, with the
        # old bytes first for >>.
        terminal = getattr(self.protocol, "terminal", None)
        owned = {real for real, _ in getattr(terminal, "redirFiles", None) or ()}
        owned.update(real for real, _ in self.redirect_real_files)
        foreign = _shardlure_foreign_backing(p, owned)
        if foreign or self._needs_new_backing(p):
            safeoutfile = self._create_redirect_target(outfile)
            if safeoutfile is None:
                return None
            if foreign:
                # bash keeps an existing file's mode; >> keeps its bytes too.
                import shutil

                try:
                    self.protocol.fs.chmod(outfile, stat.S_IMODE(p[fs.A_MODE]))
                    if append:
                        shutil.copyfile(foreign, safeoutfile)
                        self.protocol.fs.update_size(outfile, start_size)
                except OSError:
                    start_size = 0
        else:
"""

OLD_PIPE_DEF = """\
    from twisted.python import failure

# FD target type constants
"""

NEW_PIPE_DEF = """\
    from twisted.python import failure


def _shardlure_foreign_backing(p: Any, owned: set[str]) -> str | None:
    \"\"\"The node's backing file unless a redirection may write it in place.

    Only a redir_<uuid> temp this channel created (in `owned`) is written in
    place. Every other backing is someone else's: a finished capture named by
    its sha256, an SFTP upload still open on another channel (sftp_<uuid>:
    truncating it lost the capture), another channel's redirection temp, a
    honeyfs file. See connection-shared-fs.py.
    \"\"\"
    real = p[fs.A_REALFILE] if p else None
    if not isinstance(real, str):
        return None
    if real.rsplit("/", 1)[-1].startswith("redir_") and real in owned:
        return None
    return real


# FD target type constants
"""

# shell/fs.py, HoneyPotFilesystem.close (SFTP): name the finished capture.
# The anchor is the last line of sftp-capture-permissions.py's block (in its
# OLD and NEW alike) plus the line after it, and nothing is inserted inside
# that block, so either patch applies with or without the other
# (scripts/install.sh fetches sftp-capture-permissions.py standalone).
OLD_SFTP_CLOSE = """\
        self.update_realfile(self.getfile(self.filenames[fd]), shasumfile)
        self.events.dispatch(
"""

NEW_SFTP_CLOSE = """\
        self.update_realfile(self.getfile(self.filenames[fd]), shasumfile)
        # ShardLure (install/persona/patches/connection-shared-fs.py): open()
        # pointed the node at the temp file just renamed or removed, and
        # update_realfile() never replaces a set path; name the capture so a
        # later channel of this connection can read and run the upload.
        node = self.getfile(self.filenames[fd])
        if node is not None and node[A_REALFILE] == self.tempfiles[fd]:
            node[A_REALFILE] = shasumfile
        self.events.dispatch(
"""

# shell/protocol.py, HoneyPotBaseProtocol.connectionMade: /proc/uptime must not
# be bound to whichever channel opened last.
OLD_UPTIME = """\
        self.fs.generated_files["/proc/uptime"] = self.proc_uptime
"""

NEW_UPTIME = """\
        # ShardLure (install/persona/patches/connection-shared-fs.py): the fs
        # is shared by every channel of the connection, and a bound method of
        # this protocol stopped working once this channel closed (terminal and
        # fs are dropped), so /proc/uptime read nothing on channels still
        # open. The same values, bound to no channel: the factory's start time
        # and the shared fs.
        starttime = float(self.factory.starttime)
        shared_fs = self.fs

        def _shardlure_proc_uptime() -> bytes:
            uptime = time.time() - (starttime - boot_offset())
            try:
                cpuinfo = shared_fs.file_contents("/proc/cpuinfo")
            except (fs.FileNotFound, IsADirectoryError):
                cpuinfo = b""
            processors = [x for x in cpuinfo.splitlines() if x.startswith(b"processor")]
            cpus = max(1, len(processors))
            return f"{uptime:.2f} {uptime * cpus * 0.97:.2f}\\n".encode()

        self.fs.generated_files["/proc/uptime"] = _shardlure_proc_uptime
"""

# (file, OLD, NEW); a file may carry several blocks, applied in order.
TARGETS = (
    ("src/cowrie/shell/session.py", OLD, NEW),
    ("src/cowrie/shell/filetransfer.py", OLD_SFTP, NEW_SFTP),
    ("src/cowrie/insults/insults.py", OLD_REDIR, NEW_REDIR),
    ("src/cowrie/insults/insults.py", OLD_REDIR_END, NEW_REDIR_END),
    ("src/cowrie/shell/pipe.py", OLD_PIPE, NEW_PIPE),
    ("src/cowrie/shell/pipe.py", OLD_PIPE_DEF, NEW_PIPE_DEF),
    ("src/cowrie/shell/fs.py", OLD_SFTP_CLOSE, NEW_SFTP_CLOSE),
    ("src/cowrie/shell/protocol.py", OLD_UPTIME, NEW_UPTIME),
)


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    home = Path(args[0])
    paths = list(dict.fromkeys(home / rel for rel, _, _ in TARGETS))
    contents = {path: path.read_text(encoding="utf-8") for path in paths}
    counts = [(contents[home / rel].count(old), contents[home / rel].count(new))
              for rel, old, new in TARGETS]
    names = ", ".join(str(path) for path in paths)
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
    for rel, old, new in TARGETS:
        contents[home / rel] = contents[home / rel].replace(old, new, 1)
    for path in paths:
        path.write_text(contents[path], encoding="utf-8")
    print(f"  [ok] {names}: patched (one fake filesystem per connection)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
