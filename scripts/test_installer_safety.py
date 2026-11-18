"""Filesystem/ownership tests use only private temporary directories."""
import os
import tempfile
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from scripts import installer_safety as safety


class InstallerSafetyTests(unittest.TestCase):
    def setUp(self):
        self.umask = os.umask(0o077)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.units = self.root / "units"
        self.data.mkdir(mode=0o700)
        self.units.mkdir(mode=0o700)
        self.state = safety.InstallationState(self.data, self.units)

    def tearDown(self):
        self.temp.cleanup()
        os.umask(self.umask)

    def test_reused_directory_inode_cannot_adopt_unrelated_data(self):
        self.state.begin()
        before = safety.data_identity(self.data)
        self.data.rename(self.root / "original")
        self.data.mkdir()
        sentinel = self.data / "unrelated"
        sentinel.write_text("keep")
        # Filesystems can recycle a removed inode. The private installation
        # stamp must still be present, independently of the dev/inode pair.
        with mock.patch.object(safety, "data_identity", return_value=before):
            with self.assertRaises(safety.SafetyError):
                self.state.load()
        self.assertEqual(sentinel.read_text(), "keep")

    def test_nested_mount_is_rejected_before_permission_changes(self):
        evidence = self.data / "evidence"
        evidence.mkdir()
        sentinel = evidence / "outside-volume"
        sentinel.write_text("keep")
        sentinel.chmod(0o644)
        inode = evidence.stat().st_ino
        # Model a nested bind mount (same device, different mount identity).
        def mount(fd):
            return 2 if os.fstat(fd).st_ino == inode else 1
        with mock.patch.object(safety, "mount_id", side_effect=mount, create=True):
            with safety.PermissionPlan(self.data) as plan:
                with self.assertRaises(safety.SafetyError):
                    plan.collect("evidence", "private", recursive=True)
        self.assertEqual(sentinel.stat().st_mode & 0o777, 0o644)

    def test_resource_customization_prevents_uninstall(self):
        self.state.begin()
        unit = self.units / "shardlure-live.service"
        self.state.publish(unit, b"[Service]\nExecStart=/usr/bin/true\n", 0o600)
        unit.write_bytes(b"operator-customized unit")
        with self.assertRaises(safety.SafetyError):
            self.state.remove(unit)
        self.assertEqual(unit.read_bytes(), b"operator-customized unit")

    def test_share_units_are_publishable_but_arbitrary_names_are_not(self):
        """The share cadence is part of the administrative surface, by name.

        The allow-list is what stops the installer (running as root) from
        publishing an arbitrary unit into /etc/systemd/system. The five share
        units are installed unconditionally but enabled only with
        --share-timer, so they must be accepted here and nothing else may be.
        """
        self.state.begin()
        source = self.root / "unit.in"
        source.write_text("[Service]\nExecStart=/usr/bin/true\n")
        for unit in safety.SHARE_UNITS:
            with self.subTest(unit=unit):
                safety.main([
                    "publish", "--data-dir", str(self.data), "--systemd-dir", str(self.units),
                    "--bin-dir", str(self.root / "bin"), "--cowrie", "0",
                    "--path", str(self.units / unit), "--source", str(source), "--mode", "600",
                ])
                self.assertTrue((self.units / unit).exists())
        with self.assertRaises(safety.SafetyError):
            safety.main([
                "publish", "--data-dir", str(self.data), "--systemd-dir", str(self.units),
                "--bin-dir", str(self.root / "bin"), "--cowrie", "0",
                "--path", str(self.units / "attacker.service"), "--source", str(source),
                "--mode", "600",
            ])

    def test_share_services_are_checked_against_the_install_account(self):
        seen = []

        def manager(args, **kwargs):
            seen.append(args[2])
            return subprocess.CompletedProcess(args, 0, "User=shardlure\nGroup=shardlure\n", "")

        for unit in safety.SHARE_UNITS:
            (self.units / unit).write_text("[Service]\n")
        safety.verify_unit_accounts(None, runner=manager, systemd_dir=self.units)
        for unit in (u for u in safety.SHARE_UNITS if u.endswith(".service")):
            self.assertIn(unit, seen)

        # A host that has not installed them (the `run` wrapper writes only the
        # live unit) must not be refused for units that do not exist.
        empty = self.root / "empty-units"
        empty.mkdir()
        seen.clear()
        safety.verify_unit_accounts(None, runner=manager, systemd_dir=empty)
        self.assertFalse([u for u in seen if "shardlure-share" in u], seen)

    def test_descriptor_permission_update_rejects_parent_replacement(self):
        evidence = self.data / "evidence"
        evidence.mkdir()
        captured = evidence / "sample"
        captured.write_text("inert")
        outside = self.root / "outside"
        outside.mkdir()
        victim = outside / "sample"
        victim.write_text("unrelated")
        victim.chmod(0o644)
        with safety.PermissionPlan(self.data) as plan:
            plan.collect("evidence", "private", recursive=True)
            native = os.fchown
            def replace(fd, uid, gid):
                if os.fstat(fd).st_ino == captured.stat().st_ino:
                    evidence.rename(self.data / "original")
                    evidence.symlink_to(outside, target_is_directory=True)
                native(fd, uid, gid)
            with mock.patch.object(os, "fchown", side_effect=replace):
                with self.assertRaises((OSError, safety.SafetyError)):
                    plan.apply(lambda role, info: (os.getuid(), os.getgid(), 0o600))
        self.assertEqual(victim.read_text(), "unrelated")
        self.assertEqual(victim.stat().st_mode & 0o777, 0o644)

    def test_failed_maintenance_restores_data_access(self):
        self.state.begin()
        self.data.chmod(0o750)
        self.state.seal()
        self.assertEqual(self.data.stat().st_mode & 0o777, 0o710)
        self.state.unseal()
        self.assertEqual(self.data.stat().st_mode & 0o777, 0o750)

    def test_effective_unit_cannot_silently_run_as_root(self):
        def manager(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, "User=root\nGroup=root\n", "")
        with self.assertRaises(safety.SafetyError):
            safety.verify_unit_accounts(None, runner=manager)

    def test_active_installation_refuses_before_creating_data(self):
        data = self.root / "not-created"
        def manager(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, "active\n", "")
        with mock.patch.object(safety, "validate_accounts", return_value={}):
            with self.assertRaises(safety.SafetyError):
                safety.preflight(data, self.units, self.root / "bin", None, runner=manager)
        self.assertFalse(data.exists())
        self.assertEqual(list(self.units.iterdir()), [])

    def test_purge_preserves_replacement_in_private_recovery(self):
        self.state.begin()
        (self.data / "collected").write_text("original")
        foreign = self.root / "foreign"
        foreign.mkdir()
        (foreign / "keep").write_text("unrelated")
        rename = os.rename
        def replace(src, dst, **kwargs):
            if src == self.data.name and dst == "data":
                parent = kwargs["src_dir_fd"]
                rename(src, "original-data", src_dir_fd=parent, dst_dir_fd=parent)
                rename("foreign", src, src_dir_fd=parent, dst_dir_fd=parent)
            return rename(src, dst, **kwargs)
        with mock.patch.object(os, "rename", side_effect=replace):
            with self.assertRaises(safety.SafetyError):
                self.state.purge()
        self.assertEqual((self.root / "original-data/collected").read_text(), "original")
        held = list(self.root.glob(".shardlure-purge-*/data/keep"))
        self.assertEqual(len(held), 1)
        self.assertEqual(held[0].read_text(), "unrelated")

    def test_verified_purge_leaves_unrelated_siblings_and_allows_reinstall(self):
        self.state.begin()
        outside = self.root / "outside"
        outside.write_text("keep")
        (self.data / "collected").write_text("inert")
        self.state.purge()
        self.assertFalse(self.data.exists())
        self.assertFalse(self.state.marker.exists())
        self.assertEqual(outside.read_text(), "keep")
        self.data.mkdir()
        self.state.begin()
        self.state.load()

    def test_guest_guard_refuses_normal_hosts_before_reading_marker(self):
        from scripts.integration import test_installation
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(test_installation, "MARKER") as marker:
            with self.assertRaises(RuntimeError):
                test_installation.check_guest()
            marker.lstat.assert_not_called()


if __name__ == "__main__":
    unittest.main()
