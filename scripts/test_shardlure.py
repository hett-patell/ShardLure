from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import shardlure


EXPECTED_PIN = "65ded95b2d2b6555be8e4eb95315036a4db361f9"


def read_cowrie_pin(path: Path) -> str:
    fn = getattr(shardlure, "read_cowrie_pin", None)
    if fn is None:
        raise AssertionError("scripts.shardlure.read_cowrie_pin is not implemented")
    return fn(path)


def ensure_cowrie_checkout(target: Path, pin: str, repository: str) -> None:
    fn = getattr(shardlure, "ensure_cowrie_checkout", None)
    if fn is None:
        raise AssertionError("scripts.shardlure.ensure_cowrie_checkout is not implemented")
    fn(target, pin, repository)


class CowriePinTests(unittest.TestCase):
    def test_read_cowrie_pin_accepts_one_lowercase_full_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cowrie.commit"
            path.write_text(EXPECTED_PIN + "\n", encoding="utf-8")
            self.assertEqual(read_cowrie_pin(path), EXPECTED_PIN)

    def test_read_cowrie_pin_rejects_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "missing.commit"
            with self.assertRaises(FileNotFoundError):
                read_cowrie_pin(path)

    def test_read_cowrie_pin_rejects_nonimmutable_values(self) -> None:
        invalid = {
            "branch": "main\n",
            "tag": "v3.0.8\n",
            "short hash": EXPECTED_PIN[:12] + "\n",
            "uppercase hash": EXPECTED_PIN.upper() + "\n",
            "nonhex hash": EXPECTED_PIN[:-1] + "g\n",
            "extra line": EXPECTED_PIN + "\nmain\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cowrie.commit"
            for name, content in invalid.items():
                with self.subTest(name=name):
                    path.write_text(content, encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "invalid Cowrie pin"):
                        read_cowrie_pin(path)


class CowrieCheckoutTests(unittest.TestCase):
    def _git(self, repository: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(repository), *args],
            check=check,
            capture_output=True,
            text=True,
        )

    def _source_repository(self, base: Path) -> tuple[Path, str, str]:
        source = base / "source"
        source.mkdir()
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        self._git(source, "config", "user.email", "tests@example.invalid")
        self._git(source, "config", "user.name", "ShardLure Tests")

        tracked = source / "tracked.txt"
        tracked.write_text("first\n", encoding="utf-8")
        self._git(source, "add", "tracked.txt")
        self._git(source, "commit", "-q", "-m", "first")
        first = self._git(source, "rev-parse", "HEAD").stdout.strip()

        tracked.write_text("second\n", encoding="utf-8")
        self._git(source, "commit", "-q", "-am", "second")
        second = self._git(source, "rev-parse", "HEAD").stdout.strip()
        return source, first, second

    def test_new_checkout_fetches_only_requested_detached_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source, pin, _ = self._source_repository(base)
            target = base / "cowrie"

            ensure_cowrie_checkout(target, pin, source.resolve().as_uri())

            self.assertEqual(self._git(target, "rev-parse", "HEAD").stdout.strip(), pin)
            self.assertNotEqual(
                self._git(target, "symbolic-ref", "-q", "HEAD", check=False).returncode,
                0,
                "Cowrie checkout must be detached",
            )
            self.assertEqual((target / "tracked.txt").read_text(encoding="utf-8"), "first\n")

    def test_matching_existing_checkout_preserves_dirty_patch_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source, pin, _ = self._source_repository(base)
            target = base / "cowrie"
            ensure_cowrie_checkout(target, pin, source.resolve().as_uri())
            (target / "tracked.txt").write_text("locally patched\n", encoding="utf-8")

            ensure_cowrie_checkout(target, pin, source.resolve().as_uri())

            self.assertEqual((target / "tracked.txt").read_text(encoding="utf-8"), "locally patched\n")
            self.assertEqual(self._git(target, "rev-parse", "HEAD").stdout.strip(), pin)

    def test_mismatched_existing_checkout_fails_without_reset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source, expected, actual = self._source_repository(base)
            target = base / "cowrie"
            subprocess.run(["git", "clone", "-q", source.resolve().as_uri(), str(target)], check=True)
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
                ensure_cowrie_checkout(target, expected, source.resolve().as_uri())

            self.assertEqual(self._git(target, "rev-parse", "HEAD").stdout.strip(), actual)
            self.assertIn("refusing to pull or reset", stderr.getvalue())

    def test_existing_non_git_target_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source, pin, _ = self._source_repository(base)
            target = base / "cowrie"
            target.mkdir()
            sentinel = target / "keep-me"
            sentinel.write_text("operator data\n", encoding="utf-8")
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
                ensure_cowrie_checkout(target, pin, source.resolve().as_uri())

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "operator data\n")
            self.assertIn("not a Git checkout", stderr.getvalue())


class PatchDeploymentTests(unittest.TestCase):
    def test_deploy_patches_invokes_atomic_orchestrator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            orchestrator = root / "install/persona/apply-patches.py"
            orchestrator.parent.mkdir(parents=True)
            orchestrator.write_text("# test orchestrator\n", encoding="utf-8")
            cowrie = root / "cowrie"
            fake_run = mock.Mock(
                return_value=subprocess.CompletedProcess(args=[], returncode=0)
            )

            with (
                mock.patch.object(shardlure, "ROOT", root),
                mock.patch.object(shardlure, "COWRIE_HOME", cowrie),
                mock.patch.object(shardlure, "run", fake_run),
            ):
                shardlure.deploy_patches()

            fake_run.assert_called_once_with(
                [sys.executable, str(orchestrator), str(cowrie)]
            )

    def test_deploy_patches_fails_hard_when_orchestrator_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            orchestrator = root / "install/persona/apply-patches.py"
            orchestrator.parent.mkdir(parents=True)
            orchestrator.write_text("# test orchestrator\n", encoding="utf-8")
            fake_run = mock.Mock(
                return_value=subprocess.CompletedProcess(args=[], returncode=1)
            )
            stderr = io.StringIO()

            with (
                mock.patch.object(shardlure, "ROOT", root),
                mock.patch.object(shardlure, "COWRIE_HOME", root / "cowrie"),
                mock.patch.object(shardlure, "run", fake_run),
                contextlib.redirect_stderr(stderr),
                self.assertRaises(SystemExit),
            ):
                shardlure.deploy_patches()

            self.assertIn("preflight/apply failed", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
