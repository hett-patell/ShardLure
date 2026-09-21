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
            def fake_run(cmd, **kwargs):
                output = ""
                if cmd == ["systemctl", "show", "ssh.service", "--property=KillMode", "--value"]:
                    output = "process\n"
                if cmd == ["sshd", "-T"]:
                    output = "port 2200\n" if not dropin.exists() else dropin.read_text().lower()
                return subprocess.CompletedProcess(cmd, 0, stdout=output)
            with (
                mock.patch.object(shardlure, "SSHD_CONFIG", main),
                mock.patch.object(shardlure, "SSHD_DROPIN", dropin),
                mock.patch.object(shardlure, "SSH_SOCKET_DROPIN", socket),
                mock.patch.object(shardlure, "ssh_is_socket_activated", return_value=True),
                mock.patch.object(shardlure, "run", side_effect=fake_run),
                mock.patch.object(shardlure, "ensure_admin_ssh_keys"),
            ):
                shardlure.migrate_sshd(2222)
                self.assertIn("Port 2200\n", dropin.read_text())
                self.assertIn("Port 2222\n", dropin.read_text())
                # The staging socket does not clear inherited listeners.
                self.assertNotIn("ListenStream=\n", socket.read_text())
                shardlure.finalize_sshd_migration(2222)
                self.assertNotIn("Port 2200\n", dropin.read_text())
                self.assertIn("ListenStream=\n", socket.read_text())

    def test_install_services_runs_live_daemon_as_sandboxed_shardlure_user(self) -> None:
        """Removing User=shardlure or a listed sandbox boundary must fail this test."""
        with tempfile.TemporaryDirectory() as tmp:
            systemd_dir = Path(tmp) / "systemd"
            systemd_dir.mkdir()
            fake_run = mock.Mock(
                return_value=subprocess.CompletedProcess(args=[], returncode=0)
            )


            with (
                mock.patch.object(shardlure, "SYSTEMD_DIR", systemd_dir),
                mock.patch.object(shardlure, "_tailscale_iface", return_value="tailscale0"),
                mock.patch.object(shardlure, "run", fake_run),
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
            self.assertIn("ReadOnlyPaths=/srv/shardlure/cowrie", live)
            self.assertIn("ReadWritePaths=/srv/shardlure", live)
            self.assertIn("CapabilityBoundingSet=", live)
            self.assertIn("MemoryMax=1G", live)
            self.assertIn("TasksMax=256", live)
            self.assertIn("--tailscale", live)
            self.assertIn("Wants=network-online.target tailscaled.service", live)
            self.assertIn("After=network-online.target tailscaled.service", live)
            self.assertIn("ExecStartPre=/bin/sh -ec", live)
            self.assertIn("tailscale ip -4", live)
            self.assertEqual(live.count("ExecStart="), 1)
            self.assertEqual(
                [call.args[0] for call in fake_run.call_args_list],
                [
                    ["systemctl", "daemon-reload"],
                    ["systemctl", "enable", "cowrie.service", "shardlure-live.service"],
                    ["systemctl", "restart", "cowrie.service"],
                    ["systemctl", "restart", "shardlure-live.service"],
                ],
            )

    def test_service_without_tailscale_binds_loopback(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(shardlure, "SYSTEMD_DIR", Path(tmp)),
            mock.patch.object(shardlure, "_tailscale_iface", return_value=""),
            mock.patch.object(shardlure, "run", return_value=subprocess.CompletedProcess([], 0)),
        ):
            shardlure.install_services(2222, 8080)
            live = (Path(tmp) / "shardlure-live.service").read_text()
            self.assertIn(" live 127.0.0.1:8080 --cowrie=", live)
            self.assertNotIn("--tailscale", live)

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
            with (
                mock.patch.object(shardlure, "DATA_DIR", data),
                mock.patch.object(shardlure, "COWRIE_HOME", cowrie),
                mock.patch.object(shardlure, "CONFIG_FILE", config),
                mock.patch.object(shardlure, "run", return_value=cp) as run,
            ):
                shardlure.prepare_service_account()
                commands = [call.args[0] for call in run.call_args_list]
                self.assertIn(["usermod", "-a", "-G", "systemd-journal,cowrie", "shardlure"], commands)
                self.assertIn(["chown", "--", "shardlure:shardlure", str(db)], commands)
                self.assertIn(["chown", "--", "root:shardlure", str(config)], commands)
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
                self.assertFalse(run.called, "validate the complete path set before host mutations")

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
            validation = iter([1, 0])

            def fake_run(cmd, **_kwargs):
                if cmd == ["systemctl", "show", "ssh.service", "--property=KillMode", "--value"]:
                    return subprocess.CompletedProcess(cmd, 0, stdout="process\n")
                if cmd == ["sshd", "-T"]:
                    return subprocess.CompletedProcess(cmd, 0, stdout="port 2200\n")
                code = next(validation) if cmd == ["sshd", "-t"] else 0
                return subprocess.CompletedProcess(cmd, code, stdout="")

            with (
                mock.patch.object(shardlure, "SSHD_CONFIG", main),
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
            def fake_run(cmd, **_kwargs):
                return subprocess.CompletedProcess(cmd, 0, stdout=dropin.read_text().lower())
            with (
                mock.patch.object(shardlure, "SSHD_CONFIG", main),
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
