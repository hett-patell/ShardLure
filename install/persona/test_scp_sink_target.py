#!/usr/bin/env python3
"""Exercise the checked-out Cowrie scp sink with inert uploads.

Runs the real pinned (and, after apply-patches.py, patched) Command_scp
methods start/parse_scp_data/save_file/drop_tmp_file without importing Twisted
or starting a honeypot. Only the fake filesystem, the event sink and the
command plumbing are stand-ins. It pins what scp-sink-target.py promises:
`scp -t <path>` saves to <path> (a directory target keeps the record's name,
as OpenSSH's sink does), and capture is unchanged: the bytes land in
download_path_uniq/<sha256> and the upload event's shasum/outfile name it.
"""

import ast
import getopt
import hashlib
import os
import posixpath
import re
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace


class FakeFS:
    """The few HoneyPotFilesystem calls scp makes, over a dict of nodes."""

    def __init__(self, dirs):
        self.dirs = set(dirs)
        self.files = {}

    def resolve_path(self, path, cwd):
        return posixpath.normpath(posixpath.join(cwd, path)).replace("//", "/")

    def exists(self, path):
        return path in self.dirs or path in self.files

    def isdir(self, path):
        return path in self.dirs

    def mkfile(self, path, uid, gid, size, mode):
        if posixpath.dirname(path) not in self.dirs:
            raise FileNotFound()
        self.files[path] = {"size": size, "mode": mode, "realfile": None}
        return True

    def getfile(self, path):
        return self.files.get(path)

    def update_realfile(self, node, realfile):
        node["realfile"] = realfile

    def chown(self, path, uid, gid):
        pass


class FileNotFound(Exception):
    pass


class PermissionDenied(Exception):
    pass


class ScpSinkTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (COWRIE_HOME / "src/cowrie/commands/scp.py").read_text()

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.downloads = Path(directory.name)
        tree = ast.parse(self.source)
        cls = next(node for node in tree.body
                   if isinstance(node, ast.ClassDef) and node.name == "Command_scp")
        methods = [node for node in cls.body if isinstance(node, ast.FunctionDef)
                   and node.name in ("start", "parse_scp_data", "save_file", "drop_tmp_file")]
        scope = dict(
            getopt=getopt, hashlib=hashlib, os=os, posixpath=posixpath, re=re,
            fs=SimpleNamespace(FileNotFound=FileNotFound, PermissionDenied=PermissionDenied),
            temp_download_path=lambda prefix: str(
                self.downloads / f"{prefix}_{uuid.uuid4().hex}"),
        )
        exec(compile(ast.Module(body=methods, type_ignores=[]), "cowrie_scp", "exec"), scope)
        self.scope = scope

    def run_scp(self, args, records, cwd="/root"):
        """Start `scp ARGS` and feed it the wire bytes of `records`."""
        events, errors = [], []
        cmd = SimpleNamespace(
            args=args, cwd=cwd, out_dir="", download_path_uniq=str(self.downloads),
            fs=FakeFS({"/", "/root", "/tmp", "/bin"}), user={"uid": 0, "gid": 0},
            write=lambda data: None, errorWrite=errors.append, exit=lambda: None,
            help=lambda: None, _log=SimpleNamespace(error=lambda *a, **k: None),
            protocol=SimpleNamespace(events=SimpleNamespace(
                dispatch=lambda *args, **event: events.append(event))),
        )
        cmd.fs.files["/tmp/file"] = {"size": 1, "mode": 0o644, "realfile": None}
        for name in ("start", "parse_scp_data", "save_file", "drop_tmp_file"):
            setattr(cmd, name, self.scope[name].__get__(cmd))
        cmd.start()
        data = b"".join(f"C0755 {len(body)} {name}\n".encode() + body + b"\x00"
                        for name, body in records)
        while data:
            data = cmd.parse_scp_data(data)
        return cmd.fs, events, errors

    def assert_captured(self, fs, events, path, body):
        sha = hashlib.sha256(body).hexdigest()
        self.assertEqual((self.downloads / sha).read_bytes(), body)
        self.assertEqual(fs.files[path]["realfile"], str(self.downloads / sha))
        self.assertEqual(fs.files[path]["mode"], 0o755)
        event = events[-1]
        self.assertEqual((event["shasum"], event["outfile"]), (sha, sha))
        self.assertEqual((event["destfile"], event["url"]), (path, path))
        self.assertEqual(event["filename"], posixpath.basename(path))

    def test_file_target_is_the_destination(self):
        fs, events, errors = self.run_scp(["-t", "/tmp/x"], [("hw", b"\x7fELF one")])
        self.assertEqual(errors, [])
        self.assertNotIn("/root/hw", fs.files)
        self.assert_captured(fs, events, "/tmp/x", b"\x7fELF one")

    def test_relative_file_target_resolves_against_cwd(self):
        fs, events, _ = self.run_scp(["-t", "x"], [("hw", b"\x7fELF rel")])
        self.assert_captured(fs, events, "/root/x", b"\x7fELF rel")

    def test_existing_file_target_is_replaced(self):
        fs, events, _ = self.run_scp(["-t", "/tmp/file"], [("hw", b"\x7fELF new")])
        self.assert_captured(fs, events, "/tmp/file", b"\x7fELF new")

    def test_directory_target_keeps_the_record_name(self):
        for target in ("/tmp", "/tmp/", "."):
            with self.subTest(target=target):
                fs, events, errors = self.run_scp(["-t", target], [("hw", b"\x7fELF dir")],
                                                  cwd="/tmp")
                self.assertEqual(errors, [])
                self.assert_captured(fs, events, "/tmp/hw", b"\x7fELF dir")

    def test_every_record_goes_to_a_file_target(self):
        # OpenSSH's sink writes each record to targ when it is not a directory.
        fs, events, _ = self.run_scp(["-t", "/tmp/x"],
                                     [("a", b"\x7fELF first"), ("b", b"\x7fELF second")])
        self.assertEqual(sorted(fs.files), ["/tmp/file", "/tmp/x"])
        self.assertEqual([e["destfile"] for e in events], ["/tmp/x", "/tmp/x"])
        self.assert_captured(fs, events, "/tmp/x", b"\x7fELF second")

    def test_trailing_slash_on_a_non_directory_is_refused(self):
        for target, reason in (("/tmp/nope/", "Is a directory"),
                               ("/tmp/file/", "Not a directory")):
            with self.subTest(target=target):
                fs, events, errors = self.run_scp(["-t", target], [("hw", b"\x7fELF")])
                self.assertEqual(errors, [f"scp: {target}: {reason}\n"])
                self.assertEqual(events, [])
                self.assertEqual(list(self.downloads.iterdir()), [])

    def test_missing_parent_still_fails_as_before(self):
        fs, events, errors = self.run_scp(["-t", "/nope/x"], [("hw", b"\x7fELF")])
        self.assertEqual(errors, ["-scp: /nope/x: No such file or directory\n"])
        self.assertEqual(events, [])

    def test_dash_d_keeps_cowries_directory_join(self):
        fs, events, _ = self.run_scp(["-t", "-d", "/tmp"], [("hw", b"\x7fELF d")])
        self.assert_captured(fs, events, "/tmp/hw", b"\x7fELF d")

    def test_source_mode_ignores_its_argument(self):
        # `scp -f path` sends a file; it never names an upload destination.
        fs, events, _ = self.run_scp(["-f", "/tmp/x"], [("hw", b"\x7fELF f")])
        self.assert_captured(fs, events, "/root/hw", b"\x7fELF f")


if __name__ == "__main__":
    COWRIE_HOME = Path(sys.argv.pop(1))
    unittest.main()
