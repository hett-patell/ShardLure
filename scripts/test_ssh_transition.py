"""SSH transaction unit fixtures never execute a host SSH/systemd command."""
import contextlib
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import shardlure


class SSHRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.mask = os.umask(0o077)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = self.root / "sshd_config"
        self.dropin = self.root / "sshd_config.d/99-shardlure-admin.conf"
        self.socket = self.root / "ssh.socket.d/zz-shardlure-admin.conf"
        self.backup = self.root / "sshd_config.shardlure-bak"
        self.dropin.parent.mkdir()
        self.socket.parent.mkdir()
        self.config.write_text("Port 2200\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n")
        self.config.chmod(0o640)
        self.data = self.root / "data"
        self.data.mkdir()
        self.units = self.root / "units"
        self.units.mkdir()
        self.state = shardlure.installer_safety.InstallationState(self.data, self.units)
        self.state.begin()
        self.failure = None
        self.before = None
        self.calls = []
        self.stack = contextlib.ExitStack()
        for key, value in (("SSHD_CONFIG", self.config), ("SSHD_DROPIN", self.dropin),
                           ("SSH_SOCKET_DROPIN", self.socket), ("DATA_DIR", self.data),
                           ("SYSTEMD_DIR", self.units)):
            self.stack.enter_context(mock.patch.object(shardlure, key, value))
        # The old restore wrapper hard-codes paths instead of using its globals.
        mapping = {"/etc/ssh/sshd_config": self.config,
                   "/etc/ssh/sshd_config.d/99-shardlure-admin.conf": self.dropin,
                   "/etc/ssh/sshd_config.shardlure-bak": self.backup,
                   "/etc/systemd/system/ssh.socket.d/zz-shardlure-admin.conf": self.socket}
        self.stack.enter_context(mock.patch.object(shardlure, "Path", side_effect=lambda p: mapping.get(str(p), Path(p))))
        self.stack.enter_context(mock.patch.object(shardlure, "run", side_effect=self.command))
        self.stack.enter_context(mock.patch.object(shardlure, "ssh_is_socket_activated", return_value=True))
        self.verify = self.stack.enter_context(mock.patch.object(shardlure, "verify_admin_ssh_gate"))
        self.stack.enter_context(mock.patch.object(shardlure, "ensure_admin_ssh_keys"))
        shardlure.migrate_sshd(2222)
        shardlure.finalize_sshd_migration(2222)
        self.before = self.snapshot()

    def tearDown(self):
        self.stack.close()
        self.temp.cleanup()
        os.umask(self.mask)

    def snapshot(self):
        return {str(p): (p.read_bytes(), p.stat().st_mode & 0o777) if p.exists() else None
                for p in (self.config, self.dropin, self.socket)}

    def command(self, args, **kwargs):
        self.calls.append(args)
        changed = self.before is not None and self.snapshot() != self.before
        fail = changed and ((self.failure == "validate" and args[:2] == ["sshd", "-t"]) or
                            (self.failure == "socket" and args[:2] == ["systemctl", "restart"] and "ssh.socket" in args) or
                            (self.failure == "service" and args[0] == "systemctl" and
                             (args[1] == "reload" or (args[1] == "restart" and "ssh.service" in args))))
        output = ""
        if args[:2] == ["sshd", "-T"]:
            text = self.config.read_text() + (self.dropin.read_text() if self.dropin.exists() else "")
            ports = re.findall(r"(?im)^port\s+(\d+)\s*$", text)
            output = "".join("port " + p + "\n" for p in ports)
            output += "pubkeyauthentication yes\npasswordauthentication no\nkbdinteractiveauthentication no\n"
            output += "listenaddress 127.0.0.1:" + (ports[0] if ports else "2200") + "\n"
        elif args[0] == "systemctl":
            if "--property=KillMode" in args:
                output = "process\n"
            elif "--property=Listen" in args:
                ports = re.findall(r'(?m)^ListenStream=.*:(\d+)"?$', self.socket.read_text()) if self.socket.exists() else ["2200"]
                output = " ".join("127.0.0.1:"+p+" (Stream)" for p in ports) + "\n"
            elif "--property=BindIPv6Only" in args:
                output = "ipv6-only\n"
            elif args[1] == "is-active":
                output = "inactive\n" if "cowrie.service" in args else "active\n"
            elif args[1] == "is-enabled":
                output = "enabled\n"
        return subprocess.CompletedProcess(args, 1 if fail else 0, output, "injected failure" if fail else "")

    def assert_failed_restore_preserves_state(self, failure):
        self.failure = failure
        with self.assertRaises((SystemExit, subprocess.CalledProcessError, RuntimeError, ValueError)):
            shardlure.restore_sshd()
        self.assertEqual(self.snapshot(), self.before, "failed restore changed the working SSH state")
        self.assertTrue(self.backup.exists(), "recovery material was deleted after a failed transition")

    def test_validation_failure_rolls_back_exact_files_and_modes(self):
        self.assert_failed_restore_preserves_state("validate")

    def test_socket_restart_failure_rolls_back_and_retains_backup(self):
        self.assert_failed_restore_preserves_state("socket")

    def test_service_activation_failure_rolls_back_and_retains_backup(self):
        self.assert_failed_restore_preserves_state("service")

    def test_unverified_restoration_never_retires_working_listener(self):
        self.verify.side_effect = RuntimeError("independent login failed")
        with self.assertRaises((SystemExit, RuntimeError)):
            shardlure.restore_sshd()
        self.assertEqual(self.snapshot(), self.before)
        self.assertTrue(self.backup.exists())

    def test_effective_policy_is_checked_for_the_operator_context(self):
        self.calls.clear()
        shardlure.restore_sshd()
        checks = [args for args in self.calls if args[:2] == ["sshd", "-T"]]
        self.assertTrue(checks, "effective restored policy was not checked")
        self.assertTrue(all("-C" in args for args in checks), "Match rules were checked without operator context")


if __name__ == "__main__":
    unittest.main()
