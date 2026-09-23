from __future__ import annotations

import contextlib
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


EXPECTED_PIN = "65ded95b2d2b6555be8e4eb95315036a4db361f9"


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


if __name__ == "__main__":
    unittest.main()
