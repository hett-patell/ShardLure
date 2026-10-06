from __future__ import annotations

import configparser
import contextlib
import datetime
import io
import json
import os
import pwd
import re
import grp
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import shardlure


EXPECTED_PIN = "c17c9b73d6af0972334ea1e90b20d974cb24eeca"


def tailscale_fixture(root: Path) -> tuple[Path, dict[str, str]]:
    # Quotes, shell variables and systemd specifiers must remain literal.
    directory = root / "custom bin \"quoted\" $HOME %n and apostrophe's \\ path"
    directory.mkdir()
    executable = directory / "tailscale"
    executable.write_text(
        '#!/bin/sh\n'
        'printf \'%s\\n\' "$*" >> "$TAILSCALE_CALLS"\n'
        '[ "$*" = "ip -4" ] || exit 99\n'
        'case "$TAILSCALE_STATE" in\n'
        '  empty) exit 0 ;;\n'
        '  error) printf \'100.64.0.10\\n\'; exit 1 ;;\n'
        '  delayed) [ "$(wc -l < "$TAILSCALE_CALLS")" -ge 3 ] || exit 1 ;;\n'
        'esac\n'
        'printf \'100.64.0.10\\n\'\n'
    )
    executable.chmod(0o755)
    runtime_bin = root / "runtime-bin"
    runtime_bin.mkdir()
    sleep = runtime_bin / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n")
    sleep.chmod(0o755)
    env = dict(os.environ, PATH=f"{runtime_bin}:/usr/bin:/bin",
               TAILSCALE_CALLS=str(root / "tailscale-calls"), TAILSCALE_STATE="ready",
               TAILSCALE_EXECUTABLE=str(executable))
    return executable, env


def service_command(unit: str, directive: str) -> list[str]:
    lines = [line.partition("=")[2] for line in unit.splitlines()
             if line.startswith(f"{directive}=")]
    if len(lines) != 1:
        raise AssertionError(f"expected one {directive} command, got {lines}")
    # These commands use systemd's quoted-word subset shared with shlex, then
    # literal dollar/specifier escapes. No host service is started in the test.
    return [arg.replace("%%", "%").replace("$$", "$") for arg in shlex.split(lines[0])]


def service_values(unit: str, directive: str) -> list[str]:
    return [word.replace("%%", "%") for line in unit.splitlines()
            if line.startswith(directive + "=") for word in shlex.split(line.partition("=")[2])]


def run_service_prestart(unit: str, env: dict[str, str]) -> subprocess.CompletedProcess:
    args = service_command(unit, "ExecStartPre")
    if env["TAILSCALE_EXECUTABLE"] not in args:
        raise AssertionError("readiness command does not use the resolved Tailscale executable")
    return subprocess.run(args, env=env, capture_output=True, text=True, timeout=5)


def daemon_fixture(root: Path) -> Path:
    executable = root / "shardlure"
    executable.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
    executable.chmod(0o755)
    return executable


def installation_fixture(root: Path, systemd: Path | None = None):
    data = root / "provenance-data"
    data.mkdir(mode=0o700)
    state = shardlure.installer_safety.InstallationState(data, systemd or root)
    state.begin()
    return state


def check_service_unit(test: unittest.TestCase, root: Path, text: str) -> None:
    if shutil.which("systemd-analyze"):
        unit = root / "readiness-test.service"
        unit.write_text(text)
        checked = subprocess.run(["systemd-analyze", "verify", str(unit)],
                                 capture_output=True, text=True)
        test.assertEqual(checked.returncode, 0, checked.stderr)


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

    def test_repository_pin_is_the_tested_cowrie_commit(self) -> None:
        # The persona patches are anchored on exact upstream text, so the
        # shipped pin must be the commit the patch set was validated against
        # (v3.1.1). check-cowrie-patches.sh asserts the same value.
        self.assertEqual(read_cowrie_pin(shardlure.COWRIE_PIN_FILE), EXPECTED_PIN)

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

    def test_existing_checkout_validation_scopes_safe_directory_to_resolved_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "nested").mkdir()
            resolved_target = base / "cowrie"
            (resolved_target / ".git").mkdir(parents=True)
            target = base / "nested" / ".." / "cowrie"
            fake_run = mock.Mock(
                return_value=subprocess.CompletedProcess(
                    args=[], returncode=0, stdout=EXPECTED_PIN + "\n"
                )
            )

            with mock.patch.object(shardlure, "run", fake_run):
                ensure_cowrie_checkout(target, EXPECTED_PIN, "https://example.invalid/cowrie.git")

            fake_run.assert_called_once_with(
                [
                    "git",
                    "-c",
                    f"safe.directory={resolved_target.resolve()}",
                    "-C",
                    str(target),
                    "rev-parse",
                    "HEAD",
                ],
                capture_output=True,
                text=True,
            )
            command = fake_run.call_args.args[0]
            self.assertNotIn("--global", command)
            self.assertNotIn("safe.directory=*", command)

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


class ServiceSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        # SSH changes are validated for the operator's real source address;
        # fixtures declare it instead of relying on a guessed loopback.
        operator = mock.patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.10 50000 192.0.2.1 2200"})
        operator.start()
        self.addCleanup(operator.stop)
        self.old_umask = os.umask(0o077)
        # These renderer/publication tests do not talk to the host manager.
        # Effective-account policy is tested against real/fake manager results
        # separately, and against real service accounts in the Ubuntu guest.
        policy = mock.patch.object(shardlure.installer_safety, "verify_unit_accounts")
        self.unit_policy = policy.start()
        self.addCleanup(policy.stop)

    def tearDown(self) -> None:
        os.umask(self.old_umask)

    def test_public_key_install_refuses_authorized_keys_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            ssh = home / ".ssh"
            ssh.mkdir(parents=True)
            victim = root / "unrelated"
            victim.write_text("operator data\n")
            victim.chmod(0o644)
            (ssh / "authorized_keys").symlink_to(victim)
            account = pwd.struct_passwd(("root", "x", os.getuid(), os.getgid(), "", str(home), "/bin/sh"))
            real_path = Path
            with (mock.patch.dict(os.environ, SUDO_USER="root"),
                  mock.patch("pwd.getpwnam", return_value=account),
                  mock.patch.object(shardlure, "Path", side_effect=lambda p: home if str(p)=="/root" else real_path(p)),
                  mock.patch.object(shardlure, "run", return_value=subprocess.CompletedProcess([],0))):
                try:
                    shardlure._install_pubkey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyInertKey fixture")
                except (OSError, ValueError, SystemExit):
                    pass
            self.assertEqual(victim.read_text(), "operator data\n")
            self.assertEqual(victim.stat().st_mode & 0o777, 0o644)

    def test_invalid_generated_units_are_not_published_or_started(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data, units = root / "data", root / "units"
            data.mkdir()
            units.mkdir()
            shardlure.installer_safety.InstallationState(data, units).begin()
            def command(args, **kwargs):
                return subprocess.CompletedProcess(args, 1 if args[0] == "systemd-analyze" else 0, "", "")
            with (mock.patch.object(shardlure, "DATA_DIR", data),
                  mock.patch.object(shardlure, "CONFIG_FILE", data / "shardlure.yaml"),
                  mock.patch.object(shardlure, "COWRIE_HOME", data / "cowrie"),
                  mock.patch.object(shardlure, "COWRIE_LOG", data / "cowrie/var/log/cowrie/cowrie.json"),
                  mock.patch.object(shardlure, "SYSTEMD_DIR", units),
                  mock.patch.object(shardlure, "BIN_DIR", root),
                  mock.patch.object(shardlure, "_tailscale_iface", return_value=""),
                  mock.patch.object(shardlure, "run", side_effect=command) as run):
                with self.assertRaises(subprocess.CalledProcessError):
                    shardlure.install_services(2222, 8080)
            self.assertFalse((units / "cowrie.service").exists())
            self.assertFalse((units / "shardlure-live.service").exists())
            self.assertFalse(any(c.args[0][0] == "systemctl" for c in run.call_args_list))

    def test_permission_updates_do_not_follow_a_replaced_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data"
            evidence = data / "evidence"
            evidence.mkdir(parents=True)
            sample = evidence / "sample"
            sample.write_text("inert captured bytes")
            sample.chmod(0o640)
            victim = root / "unrelated"
            victim.write_text("must remain unchanged")
            victim.chmod(0o644)
            chmod = Path.chmod
            def replace_then_chmod(path, mode, **kwargs):
                if path == sample and not sample.is_symlink():
                    sample.rename(root / "original-sample")
                    sample.symlink_to(victim)
                return chmod(path, mode, **kwargs)
            def account(name):
                return pwd.struct_passwd((name, "x", os.getuid(), os.getgid(), "", str(data), "/bin/false"))
            with (mock.patch.object(shardlure, "DATA_DIR", data),
                  mock.patch.object(shardlure, "CONFIG_FILE", data / "shardlure.yaml"),
                  mock.patch.object(shardlure, "COWRIE_HOME", data / "cowrie"),
                  mock.patch.object(shardlure, "validate_existing_accounts"),
                  mock.patch("pwd.getpwnam", side_effect=account),
                  mock.patch.object(shardlure.installer_safety, "validate_accounts", side_effect=lambda *a: {n: account(n) for n in ("shardlure", "cowrie")}),
                  mock.patch.object(shardlure, "run", return_value=subprocess.CompletedProcess([], 0)),
                  mock.patch.object(Path, "chmod", replace_then_chmod)):
                try:
                    shardlure.prepare_service_account()
                except (OSError, ValueError, SystemExit):
                    pass  # A detected replacement must refuse, never follow it.
            self.assertEqual(victim.stat().st_mode & 0o777, 0o644,
                             "pathname chmod followed a replacement into unrelated data")
            self.assertEqual(victim.read_text(), "must remain unchanged")
            if not sample.is_symlink():
                self.assertEqual(sample.stat().st_mode & 0o777, 0o600, "fixture never reached the permission update")

    def test_config_quotes_literal_paths_and_preserves_existing_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / 'data # literal: "quoted" \\ path'
            cfg = data / "shardlure.yaml"
            with (mock.patch.object(shardlure, "DATA_DIR", data),
                  mock.patch.object(shardlure, "CONFIG_FILE", cfg),
                  mock.patch.object(shardlure, "COWRIE_HOME", data / "cowrie"),
                  mock.patch.object(shardlure, "COWRIE_LOG", data / "cowrie/var/log/cowrie/cowrie.json")):
                shardlure.write_config(["192.0.2.10"], 2222, 22, 8080)
                raw = cfg.read_text().splitlines()[0].partition(": ")[2]
                self.assertTrue(raw.startswith('"'), "literal path was emitted as unsafe YAML plain text")
                self.assertEqual(json.loads(raw), str(data))
                original = cfg.read_bytes() + b"# operator customization\n"
                cfg.write_bytes(original)
                shardlure.write_config(["192.0.2.10"], 2222, 22, 8080)
                self.assertEqual(cfg.read_bytes(), original, "setup overwrote operator configuration")

    def test_marker_fsync_failure_does_not_publish_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data"
            data.mkdir()
            with (mock.patch.object(shardlure, "DATA_DIR", data),
                  mock.patch.object(shardlure, "SYSTEMD_DIR", root),
                  mock.patch.object(shardlure.os, "fsync", side_effect=OSError("injected sync failure"))):
                with self.assertRaises(OSError):
                    shardlure.record_installation()
            self.assertFalse((root / ".shardlure-installation.json").exists(),
                             "failed persistence published an ownership marker")

    def test_duplicate_uid_is_not_adopted_as_service_account(self) -> None:
        account = pwd.struct_passwd(("shardlure", "x", 42345, 42345, "", str(shardlure.DATA_DIR), "/usr/sbin/nologin"))
        alias = pwd.struct_passwd(("unrelated", "x", 42345, 42345, "", "/srv/unrelated", "/bin/sh"))
        def lookup(name):
            if name == "shardlure":
                return account
            raise KeyError(name)
        with (mock.patch("pwd.getpwnam", side_effect=lookup),
              mock.patch("pwd.getpwall", return_value=[account, alias]),
              mock.patch("grp.getgrgid", return_value=grp.struct_group(("shardlure", "x", 42345, []))),
              mock.patch.object(shardlure, "run") as run):
            with self.assertRaises(SystemExit):
                shardlure.validate_existing_accounts()
            run.assert_not_called()

    def test_unproven_nonpurging_uninstall_preserves_foreign_resources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "shardlure"
            binary.write_bytes(b"unrelated installed binary")
            with (mock.patch.object(shardlure, "DATA_DIR", root / "legacy-data"),
                  mock.patch.object(shardlure, "SYSTEMD_DIR", root),
                  mock.patch.object(shardlure, "BIN_DIR", root),
                  mock.patch.object(shardlure, "need_root"),
                  mock.patch.object(shardlure, "load_ports_from_config", return_value=(2222, 2200, 8080)),
                  mock.patch.object(shardlure, "restore_sshd") as restore,
                  mock.patch.object(shardlure, "remove_services") as remove,
                  mock.patch.object(shardlure, "remove_firewall_rules"),
                  mock.patch.object(sys, "argv", ["shardlure", "uninstall"])):
                with self.assertRaises(SystemExit):
                    shardlure.cmd_uninstall()
                restore.assert_not_called()
                remove.assert_not_called()
            self.assertEqual(binary.read_bytes(), b"unrelated installed binary")

    def test_purge_provenance_tracks_directory_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data"
            data.mkdir()
            units = root / "units"
            units.mkdir()
            with (mock.patch.object(shardlure, "DATA_DIR", data),
                  mock.patch.object(shardlure, "SYSTEMD_DIR", units)):
                shardlure.record_installation()
                shardlure.validate_purge_target()
                data.rename(root / "original-data")
                data.mkdir()
                with self.assertRaises(SystemExit):
                    shardlure.validate_purge_target()
                self.assertTrue((root / "original-data").is_dir())

    def test_unproven_purge_stops_before_ssh_or_service_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (mock.patch.object(shardlure, "DATA_DIR", root / "legacy-data"),
                  mock.patch.object(shardlure, "SYSTEMD_DIR", root),
                  mock.patch.object(shardlure, "need_root"),
                  mock.patch.object(shardlure, "load_ports_from_config", return_value=(2222,2200,8080)),
                  mock.patch.object(shardlure, "restore_sshd") as restore,
                  mock.patch.object(shardlure, "remove_services") as remove,
                  mock.patch.object(shardlure, "remove_firewall_rules"),
                  mock.patch.object(shardlure, "BIN_DIR", root),
                  mock.patch.object(sys, "argv", ["shardlure", "uninstall", "--purge"]),
                  mock.patch.object(shardlure, "run"),
                  mock.patch.object(shardlure.subprocess, "run", return_value=subprocess.CompletedProcess([],1))):
                with self.assertRaises(SystemExit):
                    shardlure.cmd_uninstall()
                restore.assert_not_called()
                remove.assert_not_called()

    def test_conflicting_service_account_is_rejected_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "data"
            data.mkdir()
            account = pwd.struct_passwd(("shardlure", "x", 123, 123, "", "/unrelated/home", "/usr/sbin/nologin"))
            with (mock.patch.object(shardlure, "DATA_DIR", data),
                  mock.patch.object(shardlure, "CONFIG_FILE", data / "config.yaml"),
                  mock.patch.object(shardlure, "COWRIE_HOME", data / "cowrie"),
                  mock.patch("pwd.getpwnam", return_value=account),
                  mock.patch("grp.getgrgid", return_value=grp.struct_group(("shardlure", "x", 123, []))),
                  mock.patch.object(shardlure, "run", return_value=subprocess.CompletedProcess([], 0)) as run):
                with self.assertRaises(SystemExit):
                    shardlure.prepare_service_account()
                self.assertFalse(run.called, "account conflict reached host mutation commands")

    def test_all_service_paths_are_literal_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / 'data "quote" $VALUE %n apostrophe\'s \\ back'
            data.mkdir()
            cowrie = data / "cowrie"
            cowrie.mkdir()
            executable = daemon_fixture(data)
            state = installation_fixture(root)
            with (
                mock.patch.object(shardlure, "DATA_DIR", data),
                mock.patch.object(shardlure, "COWRIE_HOME", cowrie),
                mock.patch.object(shardlure, "COWRIE_LOG", cowrie / "cowrie.json"),
                mock.patch.object(shardlure, "CONFIG_FILE", data / "config.yaml"),
                mock.patch.object(shardlure, "BIN_DIR", data),
                mock.patch.object(shardlure, "SYSTEMD_DIR", root),
                mock.patch.object(shardlure, "installation_state", return_value=state),
                mock.patch.object(shardlure, "_tailscale_iface", return_value=""),
                mock.patch.object(shardlure, "run", return_value=subprocess.CompletedProcess([], 0)),
            ):
                shardlure.install_services(2222, 8080)
            unit = (root / "shardlure-live.service").read_text()
            args = service_command(unit, "ExecStart")
            result = subprocess.run(args, capture_output=True, text=True, check=True)
            self.assertEqual(args[0], str(executable))
            self.assertEqual(result.stdout.splitlines(), ["live", "127.0.0.1:8080", "--cowrie=" + str(cowrie / "cowrie.json")])
            assignments = [shlex.split(line.partition("=")[2])[0].replace("%%", "%")
                           for line in unit.splitlines() if line.startswith("Environment=")]
            self.assertIn("SHARDLURE_CONFIG=" + str(data / "config.yaml"), assignments)

    def test_generated_units_verify_with_literal_adversarial_paths(self) -> None:
        # Regression (disposable-guest CI run 36099193385): WorkingDirectory= is
        # not a quote-aware systemd setting, so the quoted encoding shared with
        # Exec/Environment made systemd read it as a relative path and refuse
        # the whole cowrie.service. The literal-path test above mocks `run`,
        # so only the real verifier catches this.
        if not shutil.which("systemd-analyze"):
            self.skipTest("systemd-analyze unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / 'data "quote" $VALUE %n apostrophe\'s \\ back'
            venv = data / "cowrie" / "venv" / "bin"
            venv.mkdir(parents=True)
            for name in ("python", "twistd"):
                (venv / name).write_text("#!/bin/sh\n")
                (venv / name).chmod(0o755)
            # Own daemon binary: the verifier checks the executable exists, and
            # the unit must not depend on this host's /usr/local/bin.
            bindir = root / "bin"
            bindir.mkdir()
            daemon_fixture(bindir)
            with (
                mock.patch.object(shardlure, "BIN_DIR", bindir),
                mock.patch.object(shardlure, "DATA_DIR", data),
                mock.patch.object(shardlure, "COWRIE_HOME", data / "cowrie"),
                mock.patch.object(shardlure, "COWRIE_LOG", data / "cowrie/var/log/cowrie/cowrie.json"),
                mock.patch.object(shardlure, "CONFIG_FILE", data / "shardlure.yaml"),
                mock.patch.object(shardlure, "_tailscale_iface", return_value=""),
            ):
                units = shardlure.render_services(2222, 8080)
            for name, text in units.items():
                with self.subTest(unit=name):
                    check_service_unit(self, root, text)
            workdir = [line.partition("=")[2] for line in units["cowrie.service"].splitlines()
                       if line.startswith("WorkingDirectory=")]
            self.assertEqual([w.replace("%%", "%") for w in workdir], [str(data / "cowrie")])

    def test_bait_tool_runs_through_venv_interpreter(self) -> None:
        # Regression (guest CI run 36099193385): pip's generated fsctl script
        # starts with a /bin/sh trampoline that quotes the interpreter path
        # without escaping `"`, `$` or `\`, so every call failed "not found"
        # on the adversarial path and bait silently never loaded.
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / 'data "q" $VALUE %n a\'s \\ p' / "cowrie"
            (home / "venv/bin").mkdir(parents=True)
            (home / "src/cowrie/data").mkdir(parents=True)
            (home / "var/lib/cowrie").mkdir(parents=True)
            (home / "src/cowrie/data/fs.pickle").write_bytes(b"inert")
            (home / "venv/bin/fsctl").write_text("inert")
            calls = []
            with (mock.patch.object(shardlure, "COWRIE_HOME", home),
                  mock.patch.object(shardlure, "run", side_effect=lambda a, **k: calls.append(a) or subprocess.CompletedProcess(a, 0))):
                shardlure.plant_bait_files()
            self.assertTrue(calls)
            for args in calls:
                self.assertEqual(args[:2], [str(home / "venv/bin/python"), str(home / "venv/bin/fsctl")])

    def test_cowrie_cfg_paths_survive_extended_interpolation(self) -> None:
        # Cowrie (install/cowrie.commit) reads cowrie.cfg with
        # configparser.ExtendedInterpolation, where a bare `$` is a syntax
        # error: a data path containing one made every path lookup raise and
        # Cowrie could not start. Values must be written with `$` as `$$`.
        import configparser
        home = Path('/srv/data "q" $VALUE %n a\'s \\ p/cowrie')
        with mock.patch.object(shardlure, "COWRIE_HOME", home):
            text = shardlure.patch_cowrie_cfg("[honeypot]\nhostname = x\n", 2222)
        parser = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
        parser.read_string(text)
        self.assertEqual(parser.get("honeypot", "log_path"), f"{home}/var/log/cowrie")
        self.assertEqual(parser.get("honeypot", "etc_path"), f"{home}/etc")
        self.assertEqual(parser.get("shell", "filesystem"), f"{home}/src/cowrie/data/fs.pickle")
        self.assertEqual(parser.get("output_jsonlog", "logfile"), f"{home}/var/log/cowrie/cowrie.json")

    def test_download_cap_is_under_honeypot(self):
        # Cowrie reads download_limit_size only from [honeypot]
        # (wget.py/curl.py/tftp.py/ssh/channel.py/filetransfer.py at the pin);
        # under [output_jsonlog] it was ignored and downloads were unbounded.
        template = Path(__file__).resolve().parent.parent / "install" / "persona" / "cowrie-stealth.cfg"
        parser = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
        parser.read_string(template.read_text())
        self.assertEqual(parser.getint("honeypot", "download_limit_size"), 52428800)
        self.assertFalse(parser.has_option("output_jsonlog", "download_limit_size"))
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(shardlure, "COWRIE_HOME", Path(tmp)):
            text = shardlure.patch_cowrie_cfg("[honeypot]\nhostname = x\n", 2222)
        patched = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
        patched.read_string(text)
        self.assertEqual(patched.getint("honeypot", "download_limit_size"), 52428800)

    def test_apply_stealth_merge_lands_download_cap_in_honeypot(self):
        # The ARM/existing-install path (apply-stealth.sh) merges the template
        # over the live cowrie.cfg with inline Python. Run that exact merge on
        # the real template so the cap is proven to land in [honeypot] there
        # too, not only through patch_cowrie_cfg.
        root = Path(__file__).resolve().parent.parent
        script = (root / "scripts" / "apply-stealth.sh").read_text()
        heredoc = script[script.index("sudo python3 <<PY\n") + len("sudo python3 <<PY\n"):]
        heredoc = heredoc[:heredoc.index("\nPY\n")]
        funcs = heredoc[heredoc.index("def parse_ini("):heredoc.index("existing = cfg_path")]
        # The <<PY heredoc is unquoted, so on the box bash expands `$...` and
        # backticks before Python sees this code. exec() here skips that
        # expansion, so the test is only faithful while neither appears.
        self.assertNotRegex(funcs, r"[$`]")
        with tempfile.TemporaryDirectory() as tmp:
            ns = {"cowrie_home": Path(tmp)}
            exec(funcs, ns)
            template = (root / "install" / "persona" / "cowrie-stealth.cfg").read_text()
            # The live ARM cfg: a [honeypot] without the cap and the old,
            # ignored copy under [output_jsonlog].
            stale = "[honeypot]\nhostname = old\n\n[output_jsonlog]\nenabled = true\ndownload_limit_size = 52428800\n"
            merged = ns["merge"](stale, template)
        parser = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
        parser.read_string(merged)
        self.assertEqual(parser.getint("honeypot", "download_limit_size"), 52428800)

    def test_boot_offset_is_one_constant_everywhere(self):
        # The persona's 42d 3h17m uptime (Phase B Task 5). v3.1.1 picks a
        # random 1-90 day boot_offset per process unless [honeypot] sets one,
        # and every time source must agree with it: Cowrie's /proc/uptime,
        # uptime, w and last (boot_time()), the deploy-time files
        # gen-time-persona writes (motd "Uptime: 42 days"), and the anchor the
        # behavioural harness checks against.
        import importlib.util
        root = Path(__file__).resolve().parent.parent
        anchor = 42 * 86400 + 3 * 3600 + 17 * 60
        template = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
        template.read_string((root / "install" / "persona" / "cowrie-stealth.cfg").read_text())
        self.assertEqual(template.getint("honeypot", "boot_offset"), anchor)
        # A required key: a cfg without it still gets it (fresh install from
        # cowrie.cfg.dist, or a stealth template that lost the line).
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(shardlure, "COWRIE_HOME", Path(tmp)):
            text = shardlure.patch_cowrie_cfg("[honeypot]\nhostname = x\n", 2222)
        patched = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
        patched.read_string(text)
        self.assertEqual(patched.getint("honeypot", "boot_offset"), anchor)
        # ...and an operator's own value is kept, not duplicated.
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(shardlure, "COWRIE_HOME", Path(tmp)):
            text = shardlure.patch_cowrie_cfg("[honeypot]\nboot_offset = 864000\n", 2222)
        self.assertEqual(text.count("boot_offset"), 1)
        # gen-time-persona derives its anchor from the template, not a copy.
        spec = importlib.util.spec_from_file_location(
            "gen_time_persona_t5", root / "install" / "persona" / "gen-time-persona.py")
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)
        self.assertEqual(int(gen.UPTIME.total_seconds()), anchor)
        source = (root / "install" / "persona" / "gen-time-persona.py").read_text()
        self.assertNotIn("timedelta(days=42", source)
        # The harness's anchor and the apply-stealth.sh inline fallback.
        hspec = importlib.util.spec_from_file_location(
            "cowrie_behaviour_test_t5", root / "scripts" / "cowrie-behaviour-test.py")
        harness = importlib.util.module_from_spec(hspec)
        sys.modules[hspec.name] = harness  # dataclasses resolve through sys.modules
        try:
            hspec.loader.exec_module(harness)
        finally:
            del sys.modules[hspec.name]
        self.assertEqual(harness.UPTIME_ANCHOR, anchor)
        script = (root / "scripts" / "apply-stealth.sh").read_text()
        start = script.index('stealth = persona_cfg.read_text() if persona_cfg.exists() else """')
        body = script[script.index('"""', start) + 3:]
        body = body[:body.index('"""')]
        fallback = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
        fallback.read_string(body)
        self.assertEqual(fallback.getint("honeypot", "boot_offset"), anchor)

    def test_max_input_size_is_pinned_at_the_measured_16k_everywhere(self):
        # Phase B Task 8: [shell] max_input_size stays v3.1.1's 16384, pinned
        # explicitly (the cfg comment records the arm measurement: a larger
        # cap stalls every session up to the 10 s parse timeout and then
        # answers a syntax error). The template, the patch_cowrie_cfg
        # injection and the apply-stealth.sh inline fallback must agree, and
        # an operator's own value must be kept rather than duplicated.
        root = Path(__file__).resolve().parent.parent
        template = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
        template.read_string((root / "install" / "persona" / "cowrie-stealth.cfg").read_text())
        self.assertEqual(template.getint("shell", "max_input_size"), 16384)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(shardlure, "COWRIE_HOME", Path(tmp)):
            text = shardlure.patch_cowrie_cfg("[honeypot]\nhostname = x\n", 2222)
            kept = shardlure.patch_cowrie_cfg("[shell]\nmax_input_size = 32768\n", 2222)
        patched = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
        patched.read_string(text)
        self.assertEqual(patched.getint("shell", "max_input_size"), 16384)
        self.assertEqual(kept.count("max_input_size"), 1)
        self.assertIn("max_input_size = 32768", kept)
        script = (root / "scripts" / "apply-stealth.sh").read_text()
        start = script.index('stealth = persona_cfg.read_text() if persona_cfg.exists() else """')
        body = script[script.index('"""', start) + 3:]
        body = body[:body.index('"""')]
        fallback = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
        fallback.read_string(body)
        self.assertEqual(fallback.getint("shell", "max_input_size"), 16384)

    def test_operator_boot_offset_reaches_the_motd_and_short_ones_warn(self):
        # Review m-5: patch_cowrie_cfg keeps an operator's boot_offset, so
        # gen-time-persona must read the deployed cfg, not only the template.
        root = Path(__file__).resolve().parent.parent
        gen = root / "install" / "persona" / "gen-time-persona.py"
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / "etc").mkdir()
            (home / "honeyfs/etc").mkdir(parents=True)
            (home / "etc/cowrie.cfg").write_text("[honeypot]\nboot_offset = 864000\nlog_path = $$x\n")
            # A non-UTC host (arm is IST) must still get a UTC persona clock.
            env = dict(os.environ, TZ="Asia/Kolkata")
            subprocess.run([sys.executable, str(gen), str(home)], check=True,
                           capture_output=True, env=env)
            motd = (home / "honeyfs/etc/motd").read_text()
            stamp = re.search(r"System information as of (.+) UTC (\d{4})", motd)
            when = datetime.datetime.strptime(f"{stamp.group(1)} {stamp.group(2)}",
                                              "%a %b %d %H:%M:%S %Y")
            utcnow = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            self.assertLess(abs((utcnow - when).total_seconds()), 120)
            self.assertIn("Uptime:              10 days", motd)
            self.assertIn("Users logged in:     1", motd)
            (home / "etc/cowrie.cfg").write_text("[honeypot]\nhostname = x\n")
            subprocess.run([sys.executable, str(gen), str(home)], check=True, capture_output=True)
            self.assertIn("Uptime:              42 days", (home / "honeyfs/etc/motd").read_text())
        logs = []
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(shardlure, "COWRIE_HOME", Path(tmp)), \
                mock.patch.object(shardlure, "log", side_effect=logs.append):
            shardlure.patch_cowrie_cfg("[honeypot]\nboot_offset = 3600\n", 2222)
            self.assertTrue(any("boot_offset = 3600 is under 7 days" in m for m in logs), logs)
            logs.clear()
            shardlure.patch_cowrie_cfg("[honeypot]\nhostname = x\n", 2222)
            self.assertFalse(any("boot_offset" in m for m in logs), logs)

    def test_apply_stealth_fallback_template_caps_downloads(self):
        # apply-stealth.sh writes an inline fallback when cowrie-stealth.cfg
        # is missing; it must not be the one managed cfg left unbounded.
        script = (Path(__file__).resolve().parent.parent / "scripts" / "apply-stealth.sh").read_text()
        start = script.index('stealth = persona_cfg.read_text() if persona_cfg.exists() else """')
        body = script[script.index('"""', start) + 3:]
        body = body[:body.index('"""')]
        self.assertNotRegex(body, r"[$`]")
        parser = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
        parser.read_string(body)
        self.assertEqual(parser.getint("honeypot", "download_limit_size"), 52428800)

    def test_fresh_cowrie_source_keeps_build_generated_version(self) -> None:
        # Regression (guest CI run 36101105698): cowrie.service runs with
        # PYTHONPATH=<cowrie>/src so the anti-fingerprint patches applied to
        # src/ take effect. Pinned Cowrie's cowrie/__init__.py exits with
        # "Cowrie is not installed" unless src/cowrie/_version.py exists, and
        # that file is generated by the wheel build. Building in a temporary
        # copy left it there, so the real checkout crash-looped.
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / 'data "q" $VALUE %n a\'s \\ p'
            home = data / "cowrie"
            (home / "src/cowrie").mkdir(parents=True)
            (home / "src/cowrie/__init__.py").write_text("")
            (home / "etc").mkdir()
            (home / "etc/cowrie.cfg.dist").write_text("[honeypot]\nhostname = x\n")
            (home / "requirements.txt").write_text("")
            generated = "__version__ = '0.1.dev1+inert'\n"

            def fake_run(args, **kwargs):
                if "wheel" in args and "--wheel-dir" in args:
                    build = Path(kwargs["cwd"])
                    (build / "src/cowrie/_version.py").write_text(generated)
                    out = Path(args[args.index("--wheel-dir") + 1])
                    (out / "cowrie-0.1-py3-none-any.whl").write_bytes(b"inert")
                return subprocess.CompletedProcess(args, 0)

            with (mock.patch.object(shardlure, "DATA_DIR", data),
                  mock.patch.object(shardlure, "COWRIE_HOME", home),
                  mock.patch.object(shardlure, "read_cowrie_pin", return_value="0" * 40),
                  mock.patch.object(shardlure, "ensure_cowrie_checkout"),
                  mock.patch.object(shardlure, "run", side_effect=fake_run),
                  mock.patch.object(shardlure, "apply_stealth_persona"),
                  mock.patch.object(shardlure.installer_safety, "prepare_cowrie_tree"),
                  mock.patch.object(shardlure, "setup_authbind")):
                # ensure_cowrie_checkout is mocked; the checkout "appears" before it.
                with mock.patch.object(Path, "exists", autospec=True,
                                       side_effect=lambda p: False if p == home else Path.is_file(p) or Path.is_dir(p)):
                    shardlure.install_cowrie(22022)
            self.assertEqual((home / "src/cowrie/_version.py").read_text(), generated)

    def test_partial_cowrie_install_is_refused_not_silently_preserved(self) -> None:
        # Regression (whole-branch review): a first run that cloned Cowrie and
        # then failed (pip network blip, wheel build) left a checkout without a
        # venv or build-generated _version.py; a re-run saw the directory,
        # skipped every build step and published an unstartable honeypot.
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "data" / "cowrie"
            (home / "src/cowrie").mkdir(parents=True)
            calls = []
            with (mock.patch.object(shardlure, "DATA_DIR", home.parent),
                  mock.patch.object(shardlure, "COWRIE_HOME", home),
                  mock.patch.object(shardlure, "read_cowrie_pin", return_value="0" * 40),
                  mock.patch.object(shardlure, "ensure_cowrie_checkout"),
                  mock.patch.object(shardlure, "run", side_effect=lambda a, **k: calls.append(a) or subprocess.CompletedProcess(a, 0))):
                with self.assertRaises(SystemExit):
                    shardlure.install_cowrie(22022)
                self.assertEqual(calls, [])
                # A complete installation is still preserved untouched.
                (home / "venv/bin").mkdir(parents=True)
                (home / "venv/bin/python").write_text("")
                (home / "src/cowrie/_version.py").write_text("")
                (home / "etc").mkdir()
                (home / "etc/cowrie.cfg").write_text("[honeypot]\n")
                shardlure.install_cowrie(22022)
                self.assertEqual(calls, [])

    def test_systemd_controls_reject_before_unit_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (mock.patch.object(shardlure, "CONFIG_FILE", root / "bad\npath"),
                  mock.patch.object(shardlure, "SYSTEMD_DIR", root),
                  mock.patch.object(shardlure, "_tailscale_iface", return_value=""),
                  mock.patch.object(shardlure, "run")):
                with self.assertRaises(ValueError):
                    shardlure.install_services(2222, 8080)
            self.assertEqual(list(root.iterdir()), [])

    def test_tailscale_prestart_executes_resolved_path_and_waits_for_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable, env = tailscale_fixture(root)
            state = installation_fixture(root)
            # Only systemctl and interface discovery are stubbed; resolve the
            # executable from PATH and render the real service files.
            with (
                mock.patch.dict(os.environ, PATH=f"{executable.parent}:{env['PATH']}"),
                mock.patch.object(shardlure, "SYSTEMD_DIR", root),
                mock.patch.object(shardlure, "installation_state", return_value=state),
                mock.patch.object(shardlure, "BIN_DIR", root),
                mock.patch.object(shardlure, "_tailscale_iface", return_value="tailscale0"),
                mock.patch.object(shardlure, "run", return_value=subprocess.CompletedProcess([], 0)),
            ):
                (root / "shardlure").symlink_to("/usr/bin/true")
                shardlure.install_services(2222, 8080)
            unit = (root / "shardlure-live.service").read_text()
            check_service_unit(self, root, unit)
            for state, status, attempts in (("ready", 0, 1), ("delayed", 0, 3),
                                             ("empty", 1, 30), ("error", 1, 30)):
                with self.subTest(state=state):
                    calls = Path(env["TAILSCALE_CALLS"])
                    calls.unlink(missing_ok=True)
                    result = run_service_prestart(unit, dict(env, TAILSCALE_STATE=state))
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertEqual(calls.read_text().splitlines(), ["ip -4"] * attempts)

    def test_inactive_ufw_is_not_mistaken_for_active(self) -> None:
        fake_run = mock.Mock(return_value=subprocess.CompletedProcess([], 0, stdout="Status: inactive\n"))
        with mock.patch.object(shardlure.shutil, "which", return_value="/usr/sbin/ufw"), mock.patch.object(shardlure, "run", fake_run):
            self.assertFalse(shardlure.open_admin_firewall(2222))
        fake_run.assert_called_once_with(["ufw", "status"], capture_output=True, text=True)

    def test_failed_firewall_rule_aborts_before_moving_ssh(self) -> None:
        with (
            mock.patch.object(shardlure, "ensure_admin_ssh_keys"),
            mock.patch.object(shardlure, "open_admin_firewall", side_effect=subprocess.CalledProcessError(1, ["ufw"])),
            mock.patch.object(shardlure, "migrate_sshd") as migrate,
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                shardlure.migrate_ssh_safely(2222)
        migrate.assert_not_called()

    def test_dual_port_stage_keeps_existing_port_until_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            main = root / "sshd_config"
            dropin = root / "sshd_config.d/99-shardlure-admin.conf"
            socket = root / "ssh.socket.d/zz-shardlure-admin.conf"
            main.write_text("Port 2200\nInclude sshd_config.d/*.conf\n")
            state = installation_fixture(root)
            def fake_run(cmd, **kwargs):
                output = ""
                if cmd == ["systemctl", "show", "ssh.service", "--property=KillMode", "--value"]:
                    output = "process\n"
                if cmd[:2] == ["sshd", "-T"]:
                    output = "port 2200\n" if not dropin.exists() else dropin.read_text().lower()
                if "--property=Listen" in cmd:
                    values = re.findall(r'(?m)^ListenStream=.*:(\d+)"?$', socket.read_text()) if socket.exists() else ["2200"]
                    output = " ".join("127.0.0.1:" + p + " (Stream)" for p in values)
                if "--property=BindIPv6Only" in cmd:
                    output = "ipv6-only\n"
                return subprocess.CompletedProcess(cmd, 0, stdout=output)
            with (
                mock.patch.object(shardlure, "SSHD_CONFIG", main),
                mock.patch.object(shardlure, "installation_state", return_value=state),
                mock.patch.object(shardlure, "SSHD_DROPIN", dropin),
                mock.patch.object(shardlure, "SSH_SOCKET_DROPIN", socket),
                mock.patch.object(shardlure, "ssh_is_socket_activated", return_value=True),
                mock.patch.object(shardlure, "run", side_effect=fake_run),
                mock.patch.object(shardlure, "ensure_admin_ssh_keys"),
            ):
                shardlure.migrate_sshd(2222)
                self.assertIn("Port 2200\n", dropin.read_text())
                self.assertIn("Port 2222\n", dropin.read_text())
                # Normalize sockets without dropping the existing binding.
                self.assertIn("127.0.0.1:2200", socket.read_text())
                self.assertIn("127.0.0.1:2222", socket.read_text())
                shardlure.finalize_sshd_migration(2222)
                self.assertNotIn("Port 2200\n", dropin.read_text())
                self.assertIn("ListenStream=\n", socket.read_text())

    def test_install_services_runs_live_daemon_as_sandboxed_shardlure_user(self) -> None:
        """Removing User=shardlure or a listed sandbox boundary must fail this test."""
        with tempfile.TemporaryDirectory() as tmp:
            systemd_dir = Path(tmp) / "systemd"
            systemd_dir.mkdir()
            state = installation_fixture(Path(tmp), systemd_dir)
            fake_run = mock.Mock(
                return_value=subprocess.CompletedProcess(args=[], returncode=0)
            )


            with (
                mock.patch.object(shardlure, "SYSTEMD_DIR", systemd_dir),
                mock.patch.object(shardlure, "installation_state", return_value=state),
                mock.patch.object(shardlure, "_tailscale_iface", return_value="tailscale0"),
                mock.patch.object(shardlure, "run", fake_run),
                mock.patch.object(shardlure.shutil, "which", side_effect=lambda name: "/opt/bin/tailscale" if name == "tailscale" else None),
                mock.patch.object(shardlure, "COWRIE_HOME", Path("/srv/shardlure/cowrie")),
                mock.patch.object(shardlure, "COWRIE_LOG", Path("/srv/shardlure/cowrie/var/log/cowrie/cowrie.json")),
                mock.patch.object(shardlure, "CONFIG_FILE", Path("/etc/shardlure/shardlure.yaml")),
                mock.patch.object(shardlure, "DATA_DIR", Path("/srv/shardlure")),
                mock.patch.object(shardlure, "BIN_DIR", Path("/usr/local/bin")),
            ):
                shardlure.install_services(22, 8080)

            live = (systemd_dir / "shardlure-live.service").read_text(encoding="utf-8")
            self.assertIn("User=shardlure", live)
            self.assertIn("SupplementaryGroups=systemd-journal cowrie", live)
            self.assertIn("NoNewPrivileges=true", live)
            self.assertIn("ProtectSystem=strict", live)
            self.assertIn("/srv/shardlure/cowrie", service_values(live, "ReadOnlyPaths"))
            self.assertIn("/srv/shardlure", service_values(live, "ReadWritePaths"))
            self.assertIn("CapabilityBoundingSet=", live)
            self.assertIn("MemoryMax=1G", live)
            self.assertIn("TasksMax=256", live)
            self.assertIn("--tailscale", live)
            self.assertIn("Wants=network-online.target tailscaled.service", live)
            self.assertIn("After=network-online.target tailscaled.service", live)
            self.assertIn("ExecStartPre=/bin/sh -ec", live)
            self.assertEqual(live.count("ExecStart="), 1)
            self.unit_policy.assert_called_once_with("cowrie", runner=fake_run)
            self.assertEqual(
                [call.args[0] for call in fake_run.call_args_list if call.args[0][0] == "systemctl"],
                [
                    ["systemctl", "daemon-reload"],
                    ["systemctl", "enable", "cowrie.service", "shardlure-live.service"],
                    ["systemctl", "restart", "cowrie.service"],
                    ["systemctl", "restart", "shardlure-live.service"],
                    ["systemctl", "is-active", "--quiet", "cowrie.service", "shardlure-live.service"],
                ],
            )

    def test_service_without_tailscale_binds_loopback(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(shardlure, "SYSTEMD_DIR", Path(tmp)),
            mock.patch.object(shardlure, "BIN_DIR", Path(tmp)),
            mock.patch.object(shardlure, "installation_state", return_value=installation_fixture(Path(tmp))),
            mock.patch.object(shardlure, "_tailscale_iface", return_value=""),
            mock.patch.object(shardlure, "run", return_value=subprocess.CompletedProcess([], 0)),
        ):
            daemon_fixture(Path(tmp))
            shardlure.install_services(2222, 8080)
            live = (Path(tmp) / "shardlure-live.service").read_text()
            self.assertEqual(service_command(live, "ExecStart")[1:3], ["live", "127.0.0.1:8080"])
            self.assertNotIn("--tailscale", live)
            self.assertNotIn("ExecStartPre=", live)
            self.assertNotIn("tailscaled.service", live)
            started = subprocess.run(service_command(live, "ExecStart"),
                                     capture_output=True, text=True, check=True)
            self.assertEqual(started.stdout.splitlines(),
                             ["live", "127.0.0.1:8080", f"--cowrie={shardlure.COWRIE_LOG}"])

    def test_service_account_access_is_scoped_and_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "data"
            cowrie = data / "cowrie"
            cowrie.mkdir(parents=True)
            downloads = cowrie / "var/lib/cowrie/downloads"
            downloads.mkdir(parents=True)
            payload = downloads / "inert"
            payload.write_text("fixture")
            db = data / "shardlure.db"
            db.write_text("private fixture")
            config = data / "shardlure.yaml"
            config.write_text("data_dir: fixture")
            evidence = data / "evidence"
            evidence.mkdir()
            sample = evidence / "fixture"
            sample.write_text("inert")
            unrelated = data / "operator-notes"
            unrelated.write_text("leave alone")
            cp = subprocess.CompletedProcess(args=[], returncode=0, stdout="")
            def account(name):
                return pwd.struct_passwd((name, "x", os.getuid(), os.getgid(), "", str(data), "/bin/false"))
            with (
                mock.patch.object(shardlure, "DATA_DIR", data),
                mock.patch.object(shardlure, "COWRIE_HOME", cowrie),
                mock.patch.object(shardlure, "CONFIG_FILE", config),
                mock.patch.object(shardlure, "validate_existing_accounts"),
                mock.patch("pwd.getpwnam", side_effect=account),
                mock.patch.object(shardlure.installer_safety, "validate_accounts", side_effect=lambda *a: {n: account(n) for n in ("shardlure", "cowrie")}),
                mock.patch.object(shardlure, "run", return_value=cp) as run,
            ):
                shardlure.prepare_service_account()
                commands = [call.args[0] for call in run.call_args_list]
                self.assertIn(["usermod", "-a", "-G", "systemd-journal,cowrie", "shardlure"], commands)
                self.assertFalse(any(c[0] in ("chown", "chmod", "chgrp") for c in commands))
                self.assertEqual(db.stat().st_uid, os.getuid())
                self.assertEqual(db.stat().st_mode & 0o777, 0o600)
                self.assertFalse(any(str(unrelated) in c for c in commands))
                self.assertEqual(data.stat().st_mode & 0o777, 0o710)
                self.assertEqual(config.stat().st_mode & 0o777, 0o640)
                self.assertEqual(sample.stat().st_mode & 0o777, 0o600)
                self.assertEqual(evidence.stat().st_mode & 0o777, 0o700)
                self.assertEqual(downloads.stat().st_mode & 0o777, 0o770)
                self.assertEqual(payload.stat().st_mode & 0o777, 0o640)
                sample.unlink()
                sample.symlink_to(unrelated)
                run.reset_mock()
                with self.assertRaises(SystemExit):
                    shardlure.prepare_service_account()
                self.assertFalse(any(c.args[0][0] in ("useradd", "usermod", "chown", "chmod") for c in run.call_args_list), "validate paths before host mutations")

    def test_ssh_abort_restores_previous_configuration(self) -> None:
        rollback = mock.Mock()
        with (
            mock.patch.object(shardlure, "ensure_admin_ssh_keys"),
            mock.patch.object(shardlure, "open_admin_firewall"),
            mock.patch.object(shardlure, "migrate_sshd", return_value=rollback),
            mock.patch.object(shardlure, "verify_admin_ssh_gate", side_effect=KeyboardInterrupt),
            mock.patch.object(shardlure, "finalize_sshd_migration") as finalize,
        ):
            with self.assertRaises(KeyboardInterrupt):
                shardlure.migrate_ssh_safely(2222)
        rollback.assert_called_once_with()
        finalize.assert_not_called()

    def test_ssh_validation_failure_restores_exact_preexisting_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            main = Path(tmp) / "sshd_config"
            dropin = Path(tmp) / "99-shardlure-admin.conf"
            socket = Path(tmp) / "ssh.socket.conf"
            main.write_text("Include custom.conf\nPort 2200\n")
            dropin.write_text("# original policy\nPasswordAuthentication no\n")
            socket.write_text("[Socket]\nListenStream=\nListenStream=2200\n")
            originals = {p: p.read_bytes() for p in (main, dropin, socket)}
            state = installation_fixture(Path(tmp))
            validation = iter([1, 0])

            def fake_run(cmd, **_kwargs):
                if cmd == ["systemctl", "show", "ssh.service", "--property=KillMode", "--value"]:
                    return subprocess.CompletedProcess(cmd, 0, stdout="process\n")
                if cmd[:2] == ["sshd", "-T"]:
                    return subprocess.CompletedProcess(cmd, 0, stdout="port 2200\n")
                code = next(validation) if cmd[:2] == ["sshd", "-t"] else 0
                return subprocess.CompletedProcess(cmd, code, stdout="")

            with (
                mock.patch.object(shardlure, "SSHD_CONFIG", main),
                mock.patch.object(shardlure, "installation_state", return_value=state),
                mock.patch.object(shardlure, "SSHD_DROPIN", dropin),
                mock.patch.object(shardlure, "SSH_SOCKET_DROPIN", socket),
                mock.patch.object(shardlure, "ssh_is_socket_activated", return_value=False),
                mock.patch.object(shardlure, "run", side_effect=fake_run),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    shardlure.migrate_sshd(2222)
            self.assertEqual({p: p.read_bytes() for p in originals}, originals)

    def test_repeated_ssh_stage_keeps_existing_key_only_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            main = Path(tmp) / "sshd_config"
            dropin = Path(tmp) / "99-shardlure-admin.conf"
            main.write_text("Include sshd_config.d/*.conf\n")
            dropin.write_text("Port 2222\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n")
            state = installation_fixture(Path(tmp))
            def fake_run(cmd, **_kwargs):
                return subprocess.CompletedProcess(cmd, 0, stdout=dropin.read_text().lower())
            with (
                mock.patch.object(shardlure, "SSHD_CONFIG", main),
                mock.patch.object(shardlure, "installation_state", return_value=state),
                mock.patch.object(shardlure, "SSHD_DROPIN", dropin),
                mock.patch.object(shardlure, "SSH_SOCKET_DROPIN", Path(tmp) / "socket"),
                mock.patch.object(shardlure, "ssh_is_socket_activated", return_value=False),
                mock.patch.object(shardlure, "run", side_effect=fake_run),
            ):
                shardlure.migrate_sshd(2222)
            self.assertIn("PasswordAuthentication no", dropin.read_text())

    def test_socket_reload_restarts_listener_process_without_killing_sessions(self) -> None:
        cp = subprocess.CompletedProcess([], 0, stdout="process\n")
        with mock.patch.object(shardlure, "run", return_value=cp) as run:
            shardlure._reload_ssh(True)
        self.assertIn(mock.call(["systemctl", "restart", "ssh.socket", "ssh.service"]), run.call_args_list)

    def test_unsafe_socket_killmode_aborts_before_any_reload(self) -> None:
        cp = subprocess.CompletedProcess([], 0, stdout="control-group\n")
        with mock.patch.object(shardlure, "run", return_value=cp) as run:
            with self.assertRaises(SystemExit):
                shardlure._reload_ssh(True)
        self.assertFalse(any("restart" in c.args[0] for c in run.call_args_list))

    def test_ssh_verification_requires_public_key_only_instructions(self) -> None:
        with mock.patch("builtins.input", return_value="yes"), mock.patch("builtins.print") as output:
            shardlure.verify_admin_ssh_gate(2222)
        instructions = "\n".join(str(c.args[0]) for c in output.call_args_list)
        self.assertIn("PreferredAuthentications=publickey", instructions)
        self.assertIn("PasswordAuthentication=no", instructions)
        self.assertIn("KbdInteractiveAuthentication=no", instructions)
        self.assertIn("old SSH ports remain open", instructions)

    def test_new_admin_firewall_port_is_opened_before_sshd_reconfiguration(self) -> None:
        """Moving this allow after sshd reload would strand a UFW-protected host."""
        calls: list[str] = []

        def record(name: str, result: object = None):
            def inner(*_args: object, **_kwargs: object) -> object:
                calls.append(name)
                return result

            return inner

        with (
            mock.patch.object(shardlure, "ensure_admin_ssh_keys", record("keys")),
            mock.patch.object(shardlure, "open_admin_firewall", record("firewall", True)),
            mock.patch.object(shardlure, "migrate_sshd", record("dual-port")),
            mock.patch.object(shardlure, "verify_admin_ssh_gate", record("verify")),
            mock.patch.object(shardlure, "finalize_sshd_migration", record("commit")),
        ):
            shardlure.migrate_ssh_safely(2222)

        self.assertEqual(calls, ["keys", "firewall", "dual-port", "verify", "commit"])

    def test_open_admin_firewall_uses_fake_ufw_without_touching_host_rules(self) -> None:
        """Replacing the fake with real subprocesses would change host firewall state."""
        fake_run = mock.Mock(
            side_effect=[
                subprocess.CompletedProcess(args=[], returncode=0, stdout="Status: active\n"),
                subprocess.CompletedProcess(args=[], returncode=0),
            ]
        )
        with (
            mock.patch.object(shardlure.shutil, "which", return_value="/usr/sbin/ufw"),
            mock.patch.object(shardlure, "run", fake_run),
        ):
            self.assertTrue(shardlure.open_admin_firewall(2222))

        self.assertEqual(
            [call.args[0] for call in fake_run.call_args_list],
            [["ufw", "status"], ["ufw", "allow", "2222/tcp"]],
        )


def _fs_node(name, kind, children=None, target=None, uid=0, gid=0, size=4096, mode=0o40755):
    return [name, kind, uid, gid, size, mode, 0, children if children is not None else [],
            target, None]


def persona_fs_tree():
    """A small fs.pickle-shaped tree: / with usr/{bin,sbin,lib}, etc, home,
    and the usr-merge links bin -> usr/bin, sbin -> usr/sbin (root-relative,
    as the pinned pickle stores them)."""
    d = lambda n, c=None: _fs_node(n, shardlure._FS_DIR, c)  # noqa: E731
    f = lambda n, size=10: _fs_node(n, shardlure._FS_FILE, size=size, mode=0o100755)  # noqa: E731
    return d("/", [
        d("usr", [d("bin", [f("ls", 151344), f("echo"), f("python3.11", 6831736),
                            _fs_node("python3", shardlure._FS_LINK, target="usr/bin/python3.11",
                                     mode=0o120777)]),
                  d("sbin"), d("lib", [f("os-release", 267), d("python3.11", [f("os.py")])])]),
        d("etc", [d("alternatives")]),
        d("home", [d("phil"), d("ubuntu", [d(".aws", [f("credentials")])]),
                   d("deploy", [d(".ssh", [f("id_rsa")])])]),
        d("root"),
        _fs_node("bin", shardlure._FS_LINK, target="usr/bin", mode=0o120777),
        _fs_node("sbin", shardlure._FS_LINK, target="usr/sbin", mode=0o120777),
    ])


def fs_lookup(tree, path, depth=0):
    """Cowrie's HoneyPotFilesystem.getfile: follow links, a relative target
    resolved from / (shell/fs.py)."""
    if depth > 16:
        return None
    node = tree
    for part in [p for p in path.split("/") if p]:
        if node[shardlure._FS_TYPE] == shardlure._FS_LINK:
            node = fs_lookup(tree, "/" + node[shardlure._FS_TARGET].lstrip("/"), depth + 1)
        if node is None or node[shardlure._FS_TYPE] != shardlure._FS_DIR:
            return None
        node = next((c for c in node[shardlure._FS_CONTENTS] if c[0] == part), None)
        if node is None:
            return None
    if node[shardlure._FS_TYPE] == shardlure._FS_LINK:
        return fs_lookup(tree, "/" + node[shardlure._FS_TARGET].lstrip("/"), depth + 1)
    return node


class PersonaFsTests(unittest.TestCase):
    """plant_bait_files' pickle edits (payload-yield Phase B Task 7)."""

    def test_server_tools_exist_with_their_modes(self):
        tree = persona_fs_tree()
        self.assertEqual(shardlure.persona_fs_edit(tree), [])
        sudo = fs_lookup(tree, "/usr/bin/sudo")
        self.assertEqual((sudo[shardlure._FS_SIZE], sudo[shardlure._FS_MODE]), (232416, 0o104755))
        crontab = fs_lookup(tree, "/bin/crontab")
        self.assertEqual((crontab[shardlure._FS_GID], crontab[shardlure._FS_MODE]), (104, 0o102755))
        for path in ("/usr/bin/busybox", "/usr/bin/lspci", "/usr/bin/ping", "/usr/bin/git"):
            with self.subTest(path=path):
                self.assertEqual(fs_lookup(tree, path)[shardlure._FS_TYPE], shardlure._FS_FILE)

    def test_every_link_resolves_to_a_file(self):
        tree = persona_fs_tree()
        shardlure.persona_fs_edit(tree)
        for path, _ in shardlure.PERSONA_FS_LINKS:
            with self.subTest(link=path):
                node = fs_lookup(tree, path)
                self.assertIsNotNone(node, f"{path} dangles")
                self.assertEqual(node[shardlure._FS_TYPE], shardlure._FS_FILE)
        self.assertEqual(fs_lookup(tree, "/usr/sbin/reboot")[shardlure._FS_SIZE], 1119856)
        self.assertEqual(fs_lookup(tree, "/usr/bin/nc")[shardlure._FS_SIZE], 39560)

    def test_systemctl_node_has_a_silent_txtcmd(self):
        # Cowrie registers no systemctl command: without a txtcmd the new node
        # would answer `systemctl enable x` with "cannot execute binary file"
        # where the pickle used to say "command not found". Both usr-merged
        # spellings resolve to their own txtcmd path.
        txtcmds = Path(shardlure.ROOT) / "install/persona/txtcmds"
        for rel in ("usr/bin/systemctl", "bin/systemctl"):
            with self.subTest(rel=rel):
                self.assertEqual((txtcmds / rel).read_bytes(), b"")

    def test_python3_is_22_04s_3_10(self):
        tree = persona_fs_tree()
        shardlure.persona_fs_edit(tree)
        node = fs_lookup(tree, "/usr/bin/python3")
        self.assertEqual((node[shardlure._FS_NAME], node[shardlure._FS_SIZE]), ("python3.10", 5941864))
        self.assertIsNone(fs_lookup(tree, "/usr/bin/python3.11"))
        self.assertIsNotNone(fs_lookup(tree, "/usr/lib/python3.10/os.py"))
        self.assertIsNone(fs_lookup(tree, "/usr/lib/python3.11"))
        again = persona_fs_tree()
        shardlure.persona_fs_edit(again)
        shardlure.persona_fs_edit(again)
        self.assertEqual(tree, again)

    def test_no_node_is_newer_than_the_persona_image(self):
        for path, *_, ctime in shardlure.PERSONA_FS_FILES:
            with self.subTest(path=path):
                self.assertLessEqual(ctime, shardlure.PERSONA_IMAGE_TIME)
        # Review m-6: no cluster of nodes at one instant.
        times = [ctime for *_, ctime in shardlure.PERSONA_FS_FILES]
        self.assertLessEqual(max(times.count(t) for t in times), 2)

    def test_account_files_carry_the_persona_time(self):
        tree = persona_fs_tree()
        etc = fs_lookup(tree, "/etc")
        etc[shardlure._FS_CONTENTS].append(_fs_node("passwd", shardlure._FS_FILE, size=1, mode=0o100644))
        shardlure.persona_fs_edit(tree)
        self.assertEqual(fs_lookup(tree, "/etc/passwd")[shardlure._FS_CTIME],
                         shardlure.PERSONA_ACCOUNTS_TIME)

    def test_edit_is_idempotent(self):
        once = persona_fs_tree()
        shardlure.persona_fs_edit(once)
        twice = persona_fs_tree()
        shardlure.persona_fs_edit(twice)
        shardlure.persona_fs_edit(twice)
        self.assertEqual(once, twice)

    def test_missing_parent_is_reported_not_invented(self):
        tree = persona_fs_tree()
        tree[shardlure._FS_CONTENTS] = [c for c in tree[shardlure._FS_CONTENTS] if c[0] != "etc"]
        skipped = shardlure.persona_fs_edit(tree)
        self.assertIn("/etc/alternatives/nc", skipped)
        self.assertIsNone(fs_lookup(tree, "/etc"))

    def test_unreadable_pickle_is_a_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fs.pickle"
            path.write_bytes(b"inert")
            with mock.patch.object(shardlure, "log") as log:
                shardlure.apply_persona_fs(path)
            self.assertIn("persona filesystem nodes not applied", log.call_args[0][0])
            self.assertEqual(path.read_bytes(), b"inert")

    def test_pickle_round_trip_keeps_mode(self):
        import pickle
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fs.pickle"
            path.write_bytes(pickle.dumps(persona_fs_tree()))
            path.chmod(0o640)
            shardlure.apply_persona_fs(path)
            tree = pickle.loads(path.read_bytes())
            self.assertEqual(stat_mode(path), 0o640)
            self.assertIsNotNone(fs_lookup(tree, "/usr/bin/sudo"))
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["fs.pickle"])

    def test_honeyfs_files_list_their_own_size(self):
        tree = persona_fs_tree()
        sizes = {"/usr/lib/os-release": 386, "/root/notes": 5}
        self.assertEqual(shardlure.persona_fs_edit(tree, sizes, now=1234.0), [])
        self.assertEqual(fs_lookup(tree, "/usr/lib/os-release")[shardlure._FS_SIZE], 386)
        created = fs_lookup(tree, "/root/notes")
        self.assertEqual((created[shardlure._FS_TYPE], created[shardlure._FS_SIZE],
                          created[shardlure._FS_CTIME]), (shardlure._FS_FILE, 5, 1234.0))
        self.assertEqual(shardlure.persona_fs_edit(tree, {"/nope/x": 1}), ["/nope/x"])

    def test_ls_is_the_22_04_build(self):
        # `ls -lh $(which ls)`: 135K on a real 22.04 box (Task 1 ruling).
        tree = persona_fs_tree()
        shardlure.persona_fs_edit(tree)
        self.assertEqual(fs_lookup(tree, "/bin/ls")[shardlure._FS_SIZE], 138216)

    def test_honeyfs_bytes_are_embedded(self):
        # Review m-4: the pickle's own copy is what Cowrie serves when
        # contents_path is unset; it must not keep phil.
        tree = persona_fs_tree()
        shardlure.persona_fs_edit(tree, {"/usr/lib/os-release": b"ID=ubuntu\n"})
        node = fs_lookup(tree, "/usr/lib/os-release")
        self.assertEqual((node[shardlure._FS_CONTENTS], node[shardlure._FS_SIZE]), (b"ID=ubuntu\n", 10))

    def test_honeyfs_sizes_skip_proc_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "proc").mkdir()
            (root / "proc/uptime").write_text("1.00 2.00\n")
            (root / "etc").mkdir()
            (root / "etc/hostname").write_text("prod-app-server-01\n")
            (root / "etc/link").symlink_to("hostname")
            self.assertEqual(shardlure.honeyfs_files(root), {"/etc/hostname": b"prod-app-server-01\n"})

    def test_os_release_lives_behind_its_usr_lib_symlink(self):
        # 22.04's /etc/os-release is a symlink to ../usr/lib/os-release, and
        # the pickle keeps that link; an overlay at etc/os-release was never
        # served (Cowrie overlays only regular-file nodes). The file goes
        # where the link points, with the pickle's node sized to match.
        honeyfs = Path(shardlure.ROOT) / "install/persona/honeyfs"
        expected = Path(shardlure.ROOT) / "scripts/behaviour/expected"
        self.assertFalse((honeyfs / "etc/os-release").exists())
        text = (honeyfs / "usr/lib/os-release").read_text()
        self.assertEqual(text, (expected / "cat-os-release.out").read_text())
        self.assertEqual(len(text.encode()), 386)
        self.assertEqual((expected / "os-release-size.out").read_text(), "-rw-r--r-- 386\n386\n")
        self.assertIn((expected / "os-release-pretty.out").read_text(), text)

    def test_phil_is_gone_and_the_persona_users_own_their_homes(self):
        tree = persona_fs_tree()
        sizes = {"/home/ubuntu/.bash_history": 355, "/home/deploy/.ssh/id_rsa": 615,
                 "/home/ubuntu/.aws/credentials": 170}
        self.assertEqual(shardlure.persona_fs_edit(tree, sizes), [])
        self.assertIsNone(fs_lookup(tree, "/home/phil"))
        F = shardlure  # noqa: N806
        for home, uid in (("/home/ubuntu", 1000), ("/home/deploy", 1001)):
            with self.subTest(home=home):
                node = fs_lookup(tree, home)
                self.assertEqual((node[F._FS_UID], node[F._FS_GID], node[F._FS_MODE]),
                                 (uid, uid, 0o40750))
        hist = fs_lookup(tree, "/home/ubuntu/.bash_history")
        self.assertEqual((hist[F._FS_UID], hist[F._FS_MODE], hist[F._FS_SIZE]), (1000, 0o100600, 355))
        self.assertEqual(fs_lookup(tree, "/home/deploy/.ssh")[F._FS_MODE], 0o40700)
        key = fs_lookup(tree, "/home/deploy/.ssh/id_rsa")
        self.assertEqual((key[F._FS_UID], key[F._FS_MODE]), (1001, 0o100600))
        self.assertEqual(fs_lookup(tree, "/home/ubuntu/.aws/credentials")[F._FS_MODE], 0o100600)

    def test_bait_data_files_are_not_executable(self):
        # fsctl gives a touched file its parent directory's mode (0755).
        tree = persona_fs_tree()
        shardlure.persona_fs_edit(tree, {"/usr/lib/os-release": 386, "/root/.env": 9})
        self.assertEqual(fs_lookup(tree, "/usr/lib/os-release")[shardlure._FS_MODE], 0o100644)
        self.assertEqual(fs_lookup(tree, "/root/.env")[shardlure._FS_MODE], 0o100644)


class _ReducePayload:
    """Pickles as `posix.system(<cmd>)`: what a compromised cowrie account
    would plant in fs.pickle for root's next persona-fs or plant-bait."""

    def __init__(self, cmd: str) -> None:
        self.cmd = cmd

    def __reduce__(self):
        return (os.system, (self.cmd,))


class FsPickleLoaderTests(unittest.TestCase):
    """Task 7 re-review N-2: root never unpickles fs.pickle with pickle.load."""

    def test_reduce_payload_is_refused_and_runs_nothing(self):
        import pickle
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "ran"
            tree = persona_fs_tree()
            # Hidden inside an otherwise valid tree, as a planted file would be.
            tree[shardlure._FS_CONTENTS].append(_ReducePayload(f"touch {shlex.quote(str(marker))}"))
            data = pickle.dumps(tree)
            with self.assertRaises(shardlure.FsPickleRefused) as caught:
                shardlure.load_fs_pickle(data)
            self.assertIn("system", str(caught.exception))
            self.assertFalse(marker.exists(), "the pickle's payload ran")
            path = Path(tmp) / "fs.pickle"
            path.write_bytes(data)
            with mock.patch.object(shardlure, "log") as log:
                self.assertFalse(shardlure.apply_persona_fs(path))
            self.assertFalse(marker.exists(), "the pickle's payload ran")
            self.assertIn("refusing a pickle that references", log.call_args[0][0])
            self.assertEqual(path.read_bytes(), data)
            # The same file through the installed CLI: refused, rc 1.
            home = Path(tmp) / "cowrie"
            (home / "src/cowrie/data").mkdir(parents=True)
            shutil.copy2(path, home / "src/cowrie/data/fs.pickle")
            with mock.patch.object(shardlure, "log"):
                self.assertEqual(shardlure.cmd_persona_fs(home), 1)
            self.assertFalse(marker.exists(), "the pickle's payload ran")

    def test_every_global_and_persistent_id_is_refused(self):
        import pickle
        for data in (pickle.dumps(Path("/x")), pickle.dumps(len),
                     b"\x80\x02P0\n.", pickle.dumps([1, {"a": 1}]), pickle.dumps([True]),
                     pickle.dumps((1, 2)), b"not a pickle"):
            with self.subTest(data=data[:40]):
                with self.assertRaises(shardlure.FsPickleRefused):
                    shardlure.load_fs_pickle(data)

    def test_a_cowrie_tree_loads_in_every_bytes_protocol(self):
        # Protocols 0-2 spell bytes as a _codecs.encode call, a global, and
        # stay refused; Cowrie and fsctl write the default protocol (5 on the
        # pin's pickle) and persona-fs keeps it.
        import pickle
        tree = persona_fs_tree()
        shardlure.persona_fs_edit(tree, {"/etc/hostname": b"prod\n"}, now=1.5)
        for protocol in range(3, pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                self.assertEqual(shardlure.load_fs_pickle(pickle.dumps(tree, protocol)), tree)

    def test_unknown_persona_fs_option_is_a_usage_error(self):
        for argv in (["--bogus"], ["-h"], ["a", "b"]):
            with self.subTest(argv=argv):
                proc = subprocess.run([sys.executable, str(Path(shardlure.__file__)), "persona-fs", *argv],
                                      capture_output=True, text=True, timeout=30)
                self.assertEqual(proc.returncode, 1)
                self.assertIn("usage:", proc.stderr)
                self.assertNotIn("fs.pickle under", proc.stdout)

    def test_plant_bait_runs_fsctl_as_the_cowrie_account_over_its_tree(self):
        # Root running fsctl from a venv the Cowrie account owns would
        # execute what that account planted; the tool runs as that account.
        if os.geteuid() == 0:
            self.skipTest("needs a non-root owner for the fixture tree")
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "cowrie"
            (home / "venv/bin").mkdir(parents=True)
            (home / "src/cowrie/data").mkdir(parents=True)
            (home / "var/lib/cowrie").mkdir(parents=True)
            (home / "src/cowrie/data/fs.pickle").write_bytes(b"inert")
            (home / "venv/bin/fsctl").write_text("inert")
            calls = []
            with (mock.patch.object(shardlure, "COWRIE_HOME", home),
                  mock.patch.object(shardlure.os, "geteuid", return_value=0),
                  mock.patch.object(shardlure, "log"),
                  mock.patch.object(shardlure, "run", side_effect=lambda a, **k: calls.append(a) or subprocess.CompletedProcess(a, 0))):
                shardlure.plant_bait_files()
            self.assertTrue(calls)
            for args in calls:
                self.assertEqual(args[:4], ["runuser", "-u", shardlure.COWRIE_USER, "--"])
        with mock.patch.object(shardlure.os, "geteuid", return_value=0):
            self.assertEqual(shardlure.cowrie_owned_prefix(Path("/usr/bin"), Path("/nonexistent")), [])
        self.assertEqual(shardlure.cowrie_owned_prefix(Path(tempfile.gettempdir())), [])


def prestart_commands(unit: str) -> list[tuple[str, list[str]]]:
    """(prefix, argv) of every ExecStartPre= line, in unit order."""
    out = []
    for line in unit.splitlines():
        if line.startswith("ExecStartPre="):
            value = line.partition("=")[2]
            prefix = value[:len(value) - len(value.lstrip("-+!@:"))]
            words = shlex.split(value[len(prefix):])
            out.append((prefix, [w.replace("%%", "%").replace("$$", "$") for w in words]))
    return out


def regen_tree(root: Path) -> Path:
    """A deployed Cowrie tree as the per-start regeneration finds it: the
    regeneration copy, a venv python, a cfg, honeyfs and txtcmd dirs, and the
    pickle the cfg names."""
    import pickle
    home = root / 'data "q" $VALUE %n a\'s' / "cowrie"
    for d in ("venv/bin", "etc", "honeyfs/etc", "honeyfs/proc", "share/cowrie/txtcmds/usr/bin",
              "src/cowrie/data", "var/lib/cowrie"):
        (home / d).mkdir(parents=True, exist_ok=True)
    (home / "venv/bin/python").symlink_to(sys.executable)
    (home / "etc/cowrie.cfg").write_text(
        "[honeypot]\nboot_offset = 3640620\n[shell]\nfilesystem = "
        + shardlure.cowrie_cfg_value(home / "src/cowrie/data/fs.pickle") + "\n")
    (home / "honeyfs/etc/motd").write_text("stale\n")
    (home / "src/cowrie/data/fs.pickle").write_bytes(pickle.dumps(persona_fs_tree()))
    with mock.patch.object(shardlure, "COWRIE_HOME", home):
        shardlure.deploy_persona_regen()
    return home


class PersonaRegenTests(unittest.TestCase):
    """Task 8: cowrie.service regenerates the time persona and the persona
    filesystem before every start, as the Cowrie account, fail-safe."""

    def render(self, home: Path) -> str:
        with (mock.patch.object(shardlure, "DATA_DIR", home.parent),
              mock.patch.object(shardlure, "COWRIE_HOME", home),
              mock.patch.object(shardlure, "COWRIE_LOG", home / "var/log/cowrie/cowrie.json"),
              mock.patch.object(shardlure, "CONFIG_FILE", home.parent / "shardlure.yaml"),
              mock.patch.object(shardlure, "_tailscale_iface", return_value="")):
            return shardlure.render_services(2222, 8080)["cowrie.service"]

    def test_unit_regenerates_as_the_cowrie_account_before_starting(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = regen_tree(Path(tmp))
            unit = self.render(home)
            pre = prestart_commands(unit)
            self.assertEqual(len(pre), 2)
            for prefix, argv in pre:
                with self.subTest(argv=argv[-3:]):
                    # `-` only: no `+`/`!`/`!!`, so User= applies and a
                    # failure never keeps Cowrie from starting.
                    self.assertEqual(prefix, "-")
                    self.assertEqual(argv[:2], ["/bin/sh", "-c"])
            self.assertEqual(pre[0][1][4:], [str(home / "venv/bin/python"),
                                             str(home / "shardlure-persona/gen-time-persona.py"), str(home)])
            self.assertEqual(pre[1][1][4:], [str(home / "venv/bin/python"),
                                             str(home / "shardlure-persona/shardlure.py"), "persona-fs", str(home)])
            self.assertIn(f"User={shardlure.COWRIE_USER}\n", unit)
            self.assertLess(unit.index("ExecStartPre="), unit.index("ExecStart="))
            check_service_unit(self, Path(tmp), unit)

    def test_prestart_rewrites_motd_and_sizes_its_node(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = regen_tree(Path(tmp))
            env = {"PATH": "/usr/bin:/bin", "TZ": "UTC", "PYTHONPATH": str(home / "src")}
            for _, argv in prestart_commands(self.render(home)):
                proc = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=60)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            motd = (home / "honeyfs/etc/motd").read_bytes()
            self.assertIn(b"System information as of", motd)
            self.assertIn(b"Last login:", motd)
            tree = shardlure.load_fs_pickle((home / "src/cowrie/data/fs.pickle").read_bytes())
            node = fs_lookup(tree, "/etc/motd")
            self.assertEqual((node[shardlure._FS_SIZE], node[shardlure._FS_CONTENTS]), (len(motd), motd))
            self.assertIsNotNone(fs_lookup(tree, "/usr/bin/sudo"))

    def test_prestart_without_the_copy_is_a_silent_no_op(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = regen_tree(Path(tmp))
            shutil.rmtree(home / shardlure.PERSONA_REGEN_DIR)
            for _, argv in prestart_commands(self.render(home)):
                proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
                self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, "", ""))
            self.assertEqual((home / "honeyfs/etc/motd").read_text(), "stale\n")

    def test_a_failed_step_is_logged_and_the_next_still_runs(self):
        if os.geteuid() == 0:
            self.skipTest("root writes a read-only file")
        with tempfile.TemporaryDirectory() as tmp:
            home = regen_tree(Path(tmp))
            (home / "honeyfs/proc/uptime").write_text("0 0\n")
            (home / "honeyfs/proc/uptime").chmod(0o444)
            first, second = prestart_commands(self.render(home))
            proc = subprocess.run(first[1], capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 1)
            self.assertIn("honeyfs/proc/uptime", proc.stderr)
            self.assertIn("Cowrie starts with its existing persona files", proc.stderr)
            # Every other file was still refreshed.
            self.assertIn("System information as of", (home / "honeyfs/etc/motd").read_text())
            self.assertEqual(subprocess.run(second[1], capture_output=True, timeout=60).returncode, 0)

    def test_regen_copy_is_the_scripts_the_steps_need(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = regen_tree(Path(tmp))
            names = sorted(p.name for p in (home / shardlure.PERSONA_REGEN_DIR).iterdir())
            self.assertEqual(names, sorted(shardlure.PERSONA_REGEN_FILES))
            # apply-stealth.sh deploys the same list.
            script = (Path(shardlure.ROOT) / "scripts/apply-stealth.sh").read_text()
            for name in shardlure.PERSONA_REGEN_FILES:
                self.assertIn(name, script)
            self.assertIn(f'REGEN_DST="$COWRIE_HOME/{shardlure.PERSONA_REGEN_DIR}"', script)

    def test_install_sh_renders_the_same_prestart(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / 'data "q" $VALUE %n a\'s' / "cowrie"
            proc = subprocess.run(
                ["bash", "-c", 'source "$INSTALLER"; COWRIE_HOME="$TEST_HOME"; '
                 'COWRIE_EXEC="ExecStart=/bin/true"; render_cowrie_service'],
                env=dict(os.environ, SHARDLURE_INSTALL_SOURCE_ONLY="1", TEST_HOME=str(home),
                         INSTALLER=str(Path(shardlure.ROOT) / "scripts/install.sh")),
                capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            lines = [line + "\n" for line in proc.stdout.splitlines() if line.startswith("ExecStartPre=")]
            self.assertEqual("".join(lines), shardlure.persona_regen_prestart(home))
            self.assertIn("User=cowrie\n", proc.stdout)
            self.assertLess(proc.stdout.index("ExecStartPre="), proc.stdout.index("ExecStart="))

    def test_plant_bait_hands_the_tree_back_to_cowrie(self):
        calls = []
        with (mock.patch.object(shardlure, "need_root"),
              mock.patch.object(shardlure, "plant_bait_files", side_effect=lambda: calls.append("plant")),
              mock.patch.object(shardlure.installer_safety, "prepare_cowrie_tree",
                                side_effect=lambda d, u: calls.append(("prepare", d, u))),
              mock.patch.object(shardlure, "run", side_effect=lambda a, **k: calls.append(a) or subprocess.CompletedProcess(a, 0)),
              mock.patch.object(shardlure, "log"),
              mock.patch.object(sys, "argv", ["shardlure.py", "plant-bait"])):
            shardlure.main()
        self.assertEqual(calls, ["plant", ("prepare", shardlure.DATA_DIR, shardlure.COWRIE_USER),
                                 ["systemctl", "restart", "cowrie.service"]])


class CowriePythonPreflightTests(unittest.TestCase):
    """Task 8: v3.1.1 needs Python >= 3.11 (22.04 ships 3.10); both installers
    refuse an older interpreter before changing anything."""

    def test_shardlure_refuses_python_3_10(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
            shardlure.require_cowrie_python((3, 10, 12), "/usr/bin/python3")
        self.assertEqual(caught.exception.code, 1)
        message = err.getvalue()
        for part in ("needs Python 3.11 or newer", "Python 3.10.12 (/usr/bin/python3)",
                     "Ubuntu 22.04 ships 3.10", "Nothing was changed"):
            self.assertIn(part, message)

    def test_shardlure_accepts_python_3_11_and_newer(self):
        for version in ((3, 11, 0), (3, 12, 3), (3, 14, 0), (4, 0, 0)):
            with self.subTest(version=version):
                shardlure.require_cowrie_python(version, "/usr/bin/python3")
        shardlure.require_cowrie_python()  # the interpreter running these tests

    def test_run_checks_python_before_changing_anything(self):
        calls = []
        def refuse():
            calls.append("python")
            raise SystemExit(1)
        with (mock.patch.object(shardlure, "need_root", side_effect=lambda: calls.append("root")),
              mock.patch.object(shardlure, "require_cowrie_python", side_effect=refuse),
              mock.patch.object(shardlure, "install_deps", side_effect=lambda: calls.append("deps")),
              mock.patch.object(shardlure, "validate_existing_accounts", side_effect=lambda: calls.append("accounts")),
              mock.patch.object(shardlure, "validate_installation", side_effect=lambda: calls.append("install"))):
            with self.assertRaises(SystemExit):
                shardlure.cmd_run()
        self.assertEqual(calls, ["root", "python"])
        with mock.patch.object(shardlure, "require_cowrie_python", side_effect=refuse), \
                mock.patch.object(shardlure, "ensure_cowrie_checkout") as checkout:
            with self.assertRaises(SystemExit):
                shardlure.install_cowrie(2222)
        checkout.assert_not_called()

    def run_install_sh(self, python_stub: str | None, cowrie: str = "1"):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.environ["PATH"]
            if python_stub is not None:
                stub = Path(tmp) / "python3"
                stub.write_text(python_stub)
                stub.chmod(0o755)
                path = f"{tmp}:{path}"
            return subprocess.run(
                ["bash", "-c", f'source "$INSTALLER"; COWRIE={cowrie}; require_cowrie_python; echo passed'],
                env=dict(os.environ, SHARDLURE_INSTALL_SOURCE_ONLY="1", PATH=path,
                         INSTALLER=str(Path(shardlure.ROOT) / "scripts/install.sh")),
                capture_output=True, text=True, timeout=30)

    def test_install_sh_refuses_python_3_10(self):
        # The stub answers as 22.04's python3 does to the preflight's program:
        # its version, then exit 1 (sys.exit(True)).
        proc = self.run_install_sh("#!/bin/sh\necho 3.10.12\nexit 1\n")
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn("passed", proc.stdout)
        for part in ("needs Python 3.11 or newer", "python3 is 3.10.12", "Ubuntu 22.04 ships 3.10",
                     "--no-cowrie", "Nothing was changed"):
            self.assertIn(part, proc.stderr)

    def test_install_sh_accepts_python_3_11_and_skips_without_cowrie(self):
        proc = self.run_install_sh(None)  # the real python3 (>= 3.11 here)
        self.assertEqual((proc.returncode, proc.stdout), (0, "passed\n"), proc.stderr)
        proc = self.run_install_sh("#!/bin/sh\necho 3.11.0\nexit 0\n")
        self.assertEqual((proc.returncode, proc.stdout), (0, "passed\n"), proc.stderr)
        proc = self.run_install_sh("#!/bin/sh\nexit 99\n", cowrie="0")
        self.assertEqual((proc.returncode, proc.stdout), (0, "passed\n"), proc.stderr)

    def test_install_sh_preflight_runs_the_check_before_any_change(self):
        script = (Path(shardlure.ROOT) / "scripts/install.sh").read_text()
        body = script[script.index("preflight_installation() {"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("\n  require_cowrie_python\n", body)
        main = script[script.index("# -- parse CLI overrides"):]
        self.assertLess(main.index("\npreflight_installation\n"), main.index("apt-get"))


class ApplyStealthPersonaFsTests(unittest.TestCase):
    """Task 7 review I-1: the existing-box path (apply-stealth.sh) applies the
    same pickle edits as a fresh install."""

    def test_apply_stealth_applies_the_persona_filesystem(self):
        import pickle
        root = Path(shardlure.ROOT)
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            home = tmp / "cowrie"
            (home / "src/cowrie/data").mkdir(parents=True)
            (home / "etc").mkdir()
            (home / "var/lib/cowrie").mkdir(parents=True)
            pickle_path = home / "src/cowrie/data/fs.pickle"
            pickle_path.write_bytes(pickle.dumps(persona_fs_tree()))
            # A copy of the persona whose patch orchestrator does nothing:
            # this test is about the filesystem step, not Cowrie's source.
            persona = tmp / "persona"
            shutil.copytree(root / "install/persona", persona,
                            ignore=shutil.ignore_patterns("__pycache__"))
            (persona / "apply-patches.py").write_text("raise SystemExit(0)\n")
            # The script runs privileged steps through sudo and restarts the
            # service; stand those in, keep everything else real.
            stubs = tmp / "bin"
            stubs.mkdir()
            for name, body in (("sudo", 'exec "$@"'), ("chown", "exit 0"),
                               ("systemctl", "echo active")):
                (stubs / name).write_text(f"#!/bin/sh\n{body}\n")
                (stubs / name).chmod(0o755)
            env = dict(os.environ, PATH=f"{stubs}:{os.environ['PATH']}",
                       COWRIE_HOME=str(home), PERSONA_DIR=str(persona))
            proc = subprocess.run(["bash", str(root / "scripts/apply-stealth.sh")],
                                  env=env, capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("applying persona filesystem nodes", proc.stdout)
            tree = pickle.loads(pickle_path.read_bytes())
            self.assertIsNone(fs_lookup(tree, "/home/phil"))
            for path in ("/usr/bin/sudo", "/usr/bin/crontab", "/usr/bin/ping", "/usr/bin/nc"):
                with self.subTest(path=path):
                    self.assertIsNotNone(fs_lookup(tree, path))
            ubuntu = fs_lookup(tree, "/home/ubuntu")
            self.assertEqual((ubuntu[shardlure._FS_UID], ubuntu[shardlure._FS_MODE]),
                             (1000, 0o40750))
            served = (home / "honeyfs/etc/passwd").read_text()
            self.assertNotIn("phil", served)
            self.assertIn("deploy:x:1001:1001:", served)
            # The per-start regeneration copy (Task 8) lands in the tree.
            self.assertEqual(sorted(p.name for p in (home / shardlure.PERSONA_REGEN_DIR).iterdir()),
                             sorted(shardlure.PERSONA_REGEN_FILES))

    def test_persona_fs_finds_the_pickle_the_cfg_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "cowrie $x"
            (home / "etc").mkdir(parents=True)
            (home / "custom").mkdir()
            (home / "custom/fs.pickle").write_bytes(b"x")
            (home / "etc/cowrie.cfg").write_text(
                "[shell]\nfilesystem = " + shardlure.cowrie_cfg_value(home / "custom/fs.pickle") + "\n")
            self.assertEqual(shardlure.cowrie_fs_pickles(home), [home / "custom/fs.pickle"])
            self.assertEqual(shardlure.cowrie_fs_pickles(Path(tmp) / "none"), [])


class PersonaUsersTests(unittest.TestCase):
    """honeyfs/etc/{passwd,group,shadow,gshadow}: the 22.04 cloud image's
    accounts, cloud-init's ubuntu and the persona's deploy, no phil."""

    ETC = Path(shardlure.ROOT) / "install/persona/honeyfs/etc"

    def rows(self, name):
        text = (self.ETC / name).read_text(encoding="ascii")  # Cowrie reads ASCII
        return [line.split(":") for line in text.splitlines()]

    def test_no_stock_cowrie_user(self):
        for name in ("passwd", "group", "shadow", "gshadow"):
            with self.subTest(file=name):
                self.assertNotIn("phil", (self.ETC / name).read_text())

    def test_persona_users_match_their_homes(self):
        users = {r[0]: r for r in self.rows("passwd")}
        for home, uid, gid in shardlure.PERSONA_HOMES:
            name = home.rsplit("/", 1)[1]
            with self.subTest(user=name):
                self.assertEqual(users[name][2:4], [str(uid), str(gid)])
                self.assertEqual(users[name][5:], [home, "/bin/bash"])
        expected = (Path(shardlure.ROOT) / "scripts/behaviour/expected/home-users.out").read_text()
        for name in ("ubuntu", "deploy"):
            self.assertIn(":".join(users[name]) + "\n", expected)

    def test_password_login_users_are_not_locked(self):
        # Review m-5: the userdb admits ubuntu and deploy by password, so a
        # locked `!` in shadow contradicts the login the attacker just made.
        # Their hashes are yescrypt of random, discarded passwords.
        shadow = {r[0]: r[1] for r in self.rows("shadow")}
        for user in ("root", "ubuntu", "deploy"):
            with self.subTest(user=user):
                self.assertTrue(shadow[user].startswith("$y$j9T$"), shadow[user])
        self.assertEqual(len({shadow[u] for u in ("root", "ubuntu", "deploy")}), 3)

    def test_files_agree_with_each_other(self):
        passwd, shadow = self.rows("passwd"), self.rows("shadow")
        group, gshadow = self.rows("group"), self.rows("gshadow")
        self.assertTrue(all(len(r) == 7 for r in passwd))
        self.assertEqual([r[0] for r in passwd], [r[0] for r in shadow])
        self.assertEqual([r[0] for r in group], [r[0] for r in gshadow])
        self.assertEqual({r[0]: r[3] for r in group}, {r[0]: r[3] for r in gshadow})
        gids = {r[0]: int(r[2]) for r in group}
        self.assertTrue({int(r[3]) for r in passwd} <= set(gids.values()))
        crontab = next(gid for path, _, _, gid, _ in shardlure.PERSONA_FS_FILES
                       if path == "/usr/bin/crontab")
        self.assertEqual(gids["crontab"], crontab)
        # cloud-init's default_user groups.
        for g in ("adm", "sudo", "lxd", "netdev"):
            self.assertIn("ubuntu", {r[0]: r[3] for r in group}[g].split(","))


class PersonaTxtcmdTests(unittest.TestCase):
    """txtcmds (payload-yield Phase B Task 7)."""

    TXTCMDS = Path(shardlure.ROOT) / "install/persona/txtcmds"

    def test_df_answers_on_both_usr_merged_paths(self):
        # PATH finds /usr/bin/df first; the stub used to sit at bin/df only,
        # so `df -h` ran the pickle's ELF node ("cannot execute binary file").
        self.assertEqual((self.TXTCMDS / "usr/bin/df").read_bytes(),
                         (self.TXTCMDS / "bin/df").read_bytes())

    def test_df_is_the_h_form_with_root_on_line_two(self):
        # Task 1 ruling: `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'` is
        # 95G, the root fs's 99014048 1K-blocks under df's ceiling rounding
        # (94.43 GiB, the motd's "94.43GB").
        lines = (self.TXTCMDS / "usr/bin/df").read_text().splitlines()
        self.assertEqual(lines[0], "Filesystem      Size  Used Avail Use% Mounted on")
        self.assertEqual(lines[1].split(), ["/dev/sda1", "95G", "58G", "32G", "65%", "/"])
        self.assertEqual(-(-99014048 // (1024 * 1024)), 95)
        expected = Path(shardlure.ROOT) / "scripts/behaviour/expected"
        self.assertEqual((expected / "df-h-awk.out").read_text(), "95G\n")
        self.assertEqual((expected / "bin-df-h.out").read_text().splitlines(), lines[:2])

    def test_retired_txtcmds_are_not_shipped_and_both_writers_remove_them(self):
        stealth = (Path(shardlure.ROOT) / "scripts/apply-stealth.sh").read_text()
        for rel in shardlure.RETIRED_TXTCMDS:
            with self.subTest(rel=rel):
                self.assertFalse((self.TXTCMDS / rel).exists())
                self.assertIn(f'sudo rm -f "$TXTCMDS_DST/{rel}"', stealth)

    def test_deploy_removes_a_retired_stub_left_by_an_older_deploy(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "cowrie"
            stale = home / "share/cowrie/txtcmds/bin/uname"
            stale.parent.mkdir(parents=True)
            stale.write_text("Linux static\n")
            with mock.patch.object(shardlure, "COWRIE_HOME", home), \
                    mock.patch.object(shardlure, "log"):
                shardlure.deploy_txtcmds()
            self.assertFalse(stale.exists())
            self.assertTrue((home / "share/cowrie/txtcmds/usr/bin/df").is_file())


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o7777


if __name__ == "__main__":
    unittest.main()
