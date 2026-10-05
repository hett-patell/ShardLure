#!/usr/bin/env python3
"""Exercise the checked-out Cowrie redirection backing choice with inert files.

Runs the real pinned (and, after apply-patches.py, patched) PipeProtocol
methods that pick a redirection's backing file, without importing Twisted or
starting a honeypot. It pins connection-shared-fs.py's rule: a redirection
writes in place only into a redir_ temp its own channel created; any other
backing (another channel's in-flight SFTP upload, a finished <sha256>
capture, another channel's redirection temp) is copied on write and left
byte for byte untouched (Task 3b review I-1, M-1).
"""

import ast
import hashlib
import os
import stat
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_FILE = 2


class FileNotFound(Exception):
    pass


class PermissionDenied(Exception):
    pass


class FakeFS:
    """The HoneyPotFilesystem calls pipe.py makes, over a dict of nodes."""

    def __init__(self):
        self.nodes = {}

    def resolve_path(self, path, cwd):
        return os.path.normpath(os.path.join(cwd, path))

    def getfile(self, path):
        return self.nodes.get(path)

    def mkfile(self, path, uid, gid, size, mode):
        self.nodes[path] = [os.path.basename(path), T_FILE, uid, gid, size, mode, 0, [], None, None]
        return True

    def update_realfile(self, node, realfile):
        if node is not None and not node[A_REALFILE]:
            node[A_REALFILE] = realfile

    def update_size(self, path, size):
        self.nodes[path][A_SIZE] = size

    def chmod(self, path, perm):
        node = self.nodes[path]
        node[A_MODE] = stat.S_IFMT(node[A_MODE]) | perm


class SharedFsBackingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (COWRIE_HOME / "src/cowrie/shell/pipe.py").read_text()

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.downloads = Path(directory.name)
        tree = ast.parse(self.source)
        helpers = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
        cls = next(node for node in tree.body
                   if isinstance(node, ast.ClassDef) and node.name == "PipeProtocol")
        methods = [node for node in cls.body if isinstance(node, ast.FunctionDef)
                   and node.name in ("_prepare_output_file", "_needs_new_backing",
                                     "_create_redirect_target", "_reuse_existing_backing",
                                     "_emit_redirection_error")]
        fs = SimpleNamespace(FileNotFound=FileNotFound, PermissionDenied=PermissionDenied,
                             A_SIZE=A_SIZE, A_MODE=A_MODE, A_REALFILE=A_REALFILE)
        scope = dict(
            stat=stat, fs=fs, Any=object,
            CowrieConfig=SimpleNamespace(get=lambda *args, **kw: "honeyfs"),
            temp_download_path=lambda prefix: str(
                self.downloads / f"{prefix}_{uuid.uuid4().hex}"),
        )
        exec(compile(ast.Module(body=helpers + methods, type_ignores=[]), "cowrie_pipe",
                     "exec"), scope)
        self.scope = scope
        self.fs = FakeFS()
        self.redir_files = set()

    def pipe(self):
        pp = SimpleNamespace(
            protocol=SimpleNamespace(fs=self.fs, terminal=SimpleNamespace(
                redirFiles=self.redir_files)),
            user={"uid": 0, "gid": 0}, cwd="/root", error_prefix="bash: ",
            redirect_real_files=[], redirection_error=False,
            _log=SimpleNamespace(info=lambda *a, **k: None),
            write=lambda data: None, errorWrite=lambda data: None,
        )
        for name in ("_prepare_output_file", "_needs_new_backing", "_create_redirect_target",
                     "_reuse_existing_backing", "_emit_redirection_error"):
            setattr(pp, name, self.scope[name].__get__(pp))
        return pp

    def backed(self, path, name, data, mode=0o755):
        real = self.downloads / name
        real.write_bytes(data)
        self.fs.mkfile(path, 0, 0, len(data), stat.S_IFREG | mode)
        self.fs.nodes[path][A_REALFILE] = str(real)
        return real

    def redirect(self, path, append=False):
        pp = self.pipe()
        info = pp._prepare_output_file(path, append)
        # What honeypot.py/command.py do after the command: the channel now
        # owns the backing it wrote.
        self.redir_files.update(pp.redirect_real_files)
        return pp, info

    def test_inflight_sftp_temp_is_never_written_or_registered(self):
        temp = self.backed("/tmp/up", f"sftp_{uuid.uuid4().hex}", b"\x7fELF half of the upload")
        for append in (False, True):
            with self.subTest(append=append):
                pp, info = self.redirect("/tmp/up", append)
                self.assertEqual(temp.read_bytes(), b"\x7fELF half of the upload")
                self.assertNotIn(str(temp), [real for real, _ in pp.redirect_real_files])
                self.assertTrue(os.path.basename(info["real"]).startswith("redir_"))
                self.assertEqual(self.fs.nodes["/tmp/up"][A_REALFILE], info["real"])

    def test_finished_capture_is_copied_on_write_keeping_mode(self):
        data = b"\x7fELF captured payload"
        capture = self.backed("/tmp/x", hashlib.sha256(data).hexdigest(), data)
        pp, info = self.redirect("/tmp/x", append=True)
        self.assertEqual(capture.read_bytes(), data)
        self.assertEqual(Path(info["real"]).read_bytes(), data)
        self.assertEqual(info["written"], len(data))
        self.assertEqual(stat.S_IMODE(self.fs.nodes["/tmp/x"][A_MODE]), 0o755)
        pp, info = self.redirect("/tmp/x", append=False)
        self.assertEqual(capture.read_bytes(), data)
        self.assertEqual(info["written"], 0)

    def test_own_redirection_temp_is_reused_in_place(self):
        # `echo a > f; echo b >> f` on one channel keeps one backing.
        _, first = self.redirect("/root/f")
        Path(first["real"]).write_bytes(b"a\n")
        self.fs.update_size("/root/f", 2)
        _, second = self.redirect("/root/f", append=True)
        self.assertEqual(second["real"], first["real"])
        self.assertEqual(second["written"], 2)

    def test_another_channels_redirection_temp_is_copied_on_write(self):
        other = self.backed("/root/f", f"redir_{uuid.uuid4().hex}", b"theirs\n", mode=0o644)
        _, info = self.redirect("/root/f", append=True)
        self.assertNotEqual(info["real"], str(other))
        self.assertEqual(other.read_bytes(), b"theirs\n")
        self.assertEqual(Path(info["real"]).read_bytes(), b"theirs\n")

    def test_new_file_gets_a_redirection_temp(self):
        _, info = self.redirect("/root/new")
        self.assertTrue(os.path.basename(info["real"]).startswith("redir_"))
        self.assertEqual(info["written"], 0)


if __name__ == "__main__":
    COWRIE_HOME = Path(sys.argv.pop(1))
    unittest.main()
