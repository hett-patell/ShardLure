#!/usr/bin/env python3
"""Exercise the checked-out Cowrie SFTP methods with inert local captures."""

import ast
import hashlib
import os
import re
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace


class CapturePermissionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (COWRIE_HOME / "src/cowrie/shell/fs.py").read_text()

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.downloads = Path(directory.name)
        # Execute the actual pinned/patched methods, without importing Twisted
        # or starting a honeypot. Only virtual filesystem/event plumbing is fake.
        tree = ast.parse(self.source)
        fs = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                  and any(isinstance(method, ast.FunctionDef) and method.name == "open"
                          for method in node.body))
        methods = [node for node in fs.body if isinstance(node, ast.FunctionDef)
                   and node.name in ("open", "close")]
        for method in methods:
            method.name = "sftp_" + method.name
        scope = dict(os=os, re=re, stat=stat, time=time, hashlib=hashlib,
                     CowrieConfig=SimpleNamespace(get=lambda *args: str(self.downloads)))
        exec(compile(ast.Module(body=methods, type_ignores=[]), "cowrie_sftp", "exec"), scope)
        self.open = scope["sftp_open"]
        self.close = scope["sftp_close"]
        self.events = []
        self.fs = SimpleNamespace(
            tempfiles={}, filenames={}, mkfile=lambda *args: None,
            update_realfile=lambda *args: None, getfile=lambda *args: None,
            events=SimpleNamespace(dispatch=lambda *args, **event: self.events.append(
                (event, stat.S_IMODE(Path(event["outfile"]).stat().st_mode))))
        )

    def upload(self, requested, umask, content):
        old_umask = os.umask(umask)
        fd = None
        try:
            fd = self.open(self.fs, "/inert-upload",
                           os.O_WRONLY | os.O_CREAT | os.O_TRUNC, requested)
            os.write(fd, content)
            self.close(self.fs, fd)
            fd = None
        finally:
            if fd is not None:
                os.close(fd)
            os.umask(old_umask)
        saved = self.downloads / hashlib.sha256(content).hexdigest()
        self.assertEqual(saved.read_bytes(), content)
        self.assertEqual(stat.S_IMODE(saved.stat().st_mode), 0o640)
        self.assertEqual(self.events[-1][1], 0o640, "mode must be set before the upload event")
        self.assertEqual(self.events[-1][0]["shasum"], saved.name)
        self.assertEqual(self.fs.tempfiles, {})
        self.assertEqual(self.fs.filenames, {})
        self.assertEqual(list(self.downloads.iterdir()), [saved])
        return saved

    def test_new_capture_is_group_readable_without_execute_or_other_access(self):
        for requested in (0o600, 0o644, 0o755, 0o777, 0o6777):
            for umask in (0o027, 0o077, 0o000):
                with self.subTest(requested=oct(requested), umask=oct(umask)):
                    try:
                        self.upload(requested, umask, b"inert SFTP fixture\n")
                    finally:
                        for saved in self.downloads.iterdir():
                            saved.unlink()

    def test_duplicate_capture_normalizes_existing_destination(self):
        content = b"duplicate inert SFTP fixture\n"
        saved = self.downloads / hashlib.sha256(content).hexdigest()
        saved.write_bytes(content)
        for mode in (0o600, 0o640, 0o777, 0o6777):
            with self.subTest(existing_mode=oct(mode)):
                saved.chmod(mode)
                before = saved.stat()
                self.upload(0o755, 0o027, content)
                after = saved.stat()
                self.assertEqual((after.st_ino, after.st_uid, after.st_gid),
                                 (before.st_ino, before.st_uid, before.st_gid))

    def test_read_only_open_does_not_publish_or_change_captures(self):
        saved = self.downloads / "unrelated"
        saved.write_bytes(b"unchanged")
        saved.chmod(0o600)
        fd = self.open(self.fs, "/read-only", os.O_RDONLY, 0o644)
        self.close(self.fs, fd)
        self.assertIsNone(fd)
        self.assertEqual(self.events, [])
        self.assertEqual(stat.S_IMODE(saved.stat().st_mode), 0o600)
        self.assertEqual(saved.read_bytes(), b"unchanged")


if __name__ == "__main__":
    COWRIE_HOME = Path(sys.argv.pop(1))
    unittest.main()
