#!/usr/bin/env python3
"""Real Ubuntu installer acceptance. Refuses normal and self-hosted machines."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MARKER = Path("/run/shardlure-integration/disposable.json")


def check_guest():
    expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux"}
    if any(os.environ.get(k) != v for k, v in expected.items()) or os.geteuid() != 0:
        raise RuntimeError("requires an explicitly provisioned disposable hosted Ubuntu guest")
    if os.uname().machine != "x86_64" or Path("/proc/1/comm").read_text().strip() != "systemd":
        raise RuntimeError("requires the disposable amd64 VM's real systemd")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    if release.get("ID", "").strip('"') != "ubuntu" or release.get("VERSION_ID", "").strip('"') != "24.04":
        raise RuntimeError("requires the provisioned Ubuntu 24.04 guest")
    info = MARKER.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        raise RuntimeError("invalid disposable-guest marker")
    marker = json.loads(MARKER.read_text())
    if marker != {"run": os.environ["GITHUB_RUN_ID"], "repo": os.environ["GITHUB_REPOSITORY"], "commit": os.environ["GITHUB_SHA"]}:
        raise RuntimeError("guest marker does not match this workflow run")


def run(args, *, timeout=120, check=True, **kwargs):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=timeout, **kwargs)
    if check and result.returncode:
        # Test keys, telemetry and environment are never included in a report.
        raise RuntimeError(f"{Path(str(args[0])).name} failed ({result.returncode}): {result.stderr[-1600:]}\nlast progress: {result.stdout[-1200:]}")
    return result


class Acceptance:
    def __init__(self, binary: Path, report: Path):
        self.binary = binary.resolve()
        self.report = report.resolve()
        self.steps = []
        self.work = Path(tempfile.mkdtemp(prefix="shardlure-acceptance-", dir="/srv"))
        self.work.chmod(0o755)
        self.secret = self.work / "private"
        self.secret.mkdir(mode=0o700)
        self.operator = "sl-acceptance-operator"
        self.admin = 22022
        self.new_admin = 22023
        self.dashboard = 18085
        self.master = None
        self.control = self.secret / "control"
        self.key = self.secret / "operator-key"
        self.data = self.work / 'data "quoted" $VALUE %n apostrophe\'s \\ path'
        sys.path.insert(0, str(ROOT))
        from scripts import shardlure
        self.installer = shardlure

    def record(self, name, **details):
        self.steps.append({"step": name, "passed": True, **details})
        print(json.dumps(self.steps[-1]), flush=True)
        self.write_report()

    def write_report(self, failure=None):
        self.report.write_text(json.dumps({"commit": os.environ["GITHUB_SHA"], "disposable_hosted_guest": True,
                                          "passed": failure is None, "steps": self.steps,
                                          "failure": failure}, indent=2))
        self.report.chmod(0o644)  # Contains no keys, database, raw config or telemetry.

    def configure_ssh(self):
        # Hosted images deliberately make this tool prefix world-writable for
        # convenience. Provision a production-like trusted prefix only inside
        # this marker-verified disposable VM; never relax the installer guard.
        prefix = Path("/usr/local/bin")
        info = prefix.lstat()
        assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0
        prefix.chmod(0o755)
        self.record("guest-only root-owned installation prefix provisioned")
        for user in ("shardlure", "cowrie", self.operator):
            try:
                pwd.getpwnam(user)
            except KeyError:
                continue
            raise RuntimeError("guest is not fresh: reserved test account exists")
        run(["useradd", "--create-home", "--shell", "/bin/bash", self.operator])
        self.op = pwd.getpwnam(self.operator)
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.key])
        ssh = Path(self.op.pw_dir) / ".ssh"
        ssh.mkdir(mode=0o700)
        os.chown(ssh, self.op.pw_uid, self.op.pw_gid)
        authorized = ssh / "authorized_keys"
        authorized.write_bytes(self.key.with_suffix(".pub").read_bytes())
        authorized.chmod(0o600)
        os.chown(authorized, self.op.pw_uid, self.op.pw_gid)
        run(["ssh-keygen", "-A"])
        Path("/run/sshd").mkdir(exist_ok=True)
        Path("/etc/ssh/sshd_config").write_text(
            f"Port {self.admin}\nListenAddress 127.0.0.1\nUsePAM yes\n"
            "PubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
            f"PermitRootLogin no\nAllowUsers {self.operator}\n"
            "Include /etc/ssh/sshd_config.d/*.conf\n"
            f"Match User {self.operator} Address 127.0.0.1\n    PubkeyAuthentication yes\n")
        socket = Path("/etc/systemd/system/ssh.socket.d/10-shardlure-acceptance.conf")
        socket.parent.mkdir(parents=True, exist_ok=True)
        socket.write_text(f"[Socket]\nListenStream=\nListenStream=127.0.0.1:{self.admin}\nBindIPv6Only=ipv6-only\n")
        run(["sshd", "-t"])
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "restart", "ssh.socket", "ssh.service"])
        self.login(self.admin)
        self.master = subprocess.Popen(self.ssh_args(self.admin) + ["-M", "-N", "-S", str(self.control),
                                                                  "-o", "ControlMaster=yes", f"{self.operator}@127.0.0.1"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            if self.control.exists():
                break
            time.sleep(0.1)
        self.control_alive()
        self.record("real SSH control connection established", custom_admin_port=self.admin)

    def ssh_args(self, port):
        return ["ssh", "-i", str(self.key), "-p", str(port), "-o", "BatchMode=yes",
                "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey",
                "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
                "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={self.secret / 'known_hosts'}",
                "-o", "ConnectTimeout=5"]

    def login(self, port, **_):
        result = run(self.ssh_args(port) + ["-o", "ControlMaster=no", "-o", "ControlPath=none",
                                           f"{self.operator}@127.0.0.1", "id -u"], timeout=20)
        assert result.stdout.strip() == str(self.op.pw_uid), "independent SSH login did not execute as the operator"

    def control_alive(self):
        assert self.master is not None and self.master.poll() is None
        run(["ssh", "-S", self.control, "-O", "check", f"{self.operator}@127.0.0.1"])

    @contextlib.contextmanager
    def wrapper(self, data):
        s = self.installer
        with contextlib.ExitStack() as stack:
            for name, value in (("DATA_DIR", data), ("CONFIG_FILE", data / "shardlure.yaml"),
                                ("COWRIE_HOME", data / "cowrie"), ("COWRIE_LOG", data / "cowrie/var/log/cowrie/cowrie.json")):
                stack.enter_context(mock.patch.object(s, name, value))
            stack.enter_context(mock.patch.dict(os.environ, SUDO_USER=self.operator,
                SSH_CONNECTION=f"127.0.0.1 40000 127.0.0.1 {self.admin}"))
            stack.enter_context(mock.patch.object(s, "verify_admin_ssh_gate", side_effect=self.login))
            stack.enter_context(mock.patch.object(s, "open_admin_firewall", return_value=False))
            stack.enter_context(mock.patch.object(s, "open_firewall"))
            stack.enter_context(mock.patch.object(s, "remove_firewall_rules"))
            yield s

    def await_ready(self, timeout=180):
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            try:
                connection = http.client.HTTPConnection("127.0.0.1", self.dashboard, timeout=3)
                connection.request("GET", "/readyz")
                response = connection.getresponse()
                response.read()
                connection.close()
                if response.status == 200:
                    return
            except OSError:
                pass
            time.sleep(1)
        raise RuntimeError("installed native daemon never became ready")

    def release_fixture(self):
        root = self.work / "release-fixture"
        root.mkdir(mode=0o755)
        helper = ROOT / "scripts/installer_safety.py"
        sums = root / "SHA256SUMS"
        sums.write_text(hashlib.sha256(self.binary.read_bytes()).hexdigest() + "  shardlure-linux-amd64\n" +
                        hashlib.sha256(helper.read_bytes()).hexdigest() + "  installer_safety.py\n")
        wrapper = root / "curl"
        wrapper.write_text("#!/usr/bin/python3\nimport pathlib,sys\n" +
            f"sources={{'shardlure-linux-amd64':{str(self.binary)!r},'SHA256SUMS':{str(sums)!r},'installer_safety.py':{str(helper)!r},'cowrie.commit':{str(ROOT / 'install/cowrie.commit')!r},'sftp-capture-permissions.py':{str(ROOT / 'install/persona/patches/sftp-capture-permissions.py')!r}}}\n" +
            "args=sys.argv[1:]; urls=[v for v in args if v.startswith('https://')]; assert len(urls)==1\n" +
            "name=urls[0].rsplit('/',1)[-1]; assert name in sources, 'unexpected download refused'\n" +
            "destination=args[args.index('-o')+1]; pathlib.Path(destination).write_bytes(pathlib.Path(sources[name]).read_bytes())\n")
        wrapper.chmod(0o755)
        return root

    def shell_install(self, data, cowrie):
        self.current_data, self.current_cowrie = data, cowrie
        env = dict(os.environ, PATH=str(self.release_bin)+":"+os.environ["PATH"],
                   ADMIN_PORT=str(self.new_admin if cowrie else self.admin))
        args = ["bash", ROOT / "scripts/install.sh", "--tag", "v-integration-fixture", "--data-dir", data,
                "--dash-port", str(self.dashboard), "--honeypot-port", str(self.admin)]
        if not cowrie:
            args.append("--no-cowrie")
        run(args, env=env, timeout=1200)
        self.await_ready()

    def no_cowrie(self):
        data = self.work / "no-cowrie-data"
        self.shell_install(data, False)
        try:
            pwd.getpwnam("cowrie")
        except KeyError:
            pass
        else:
            raise AssertionError("--no-cowrie created a Cowrie account")
        self.record("release installer no-Cowrie mode runs the real live daemon")
        with self.wrapper(data) as s:
            with mock.patch.object(sys, "argv", ["shardlure", "uninstall", "--purge"]):
                s.cmd_uninstall()
        account = pwd.getpwnam("shardlure")
        assert account.pw_dir == str(data) and not data.exists()
        run(["userdel", "shardlure"])
        run(["groupdel", "shardlure"], check=False)
        self.record("cross-installer owned purge preserves administrative SSH")
        self.login(self.admin)

    def python_install(self):
        with self.wrapper(self.data) as s:
            publish = lambda: s.installation_state().publish(Path("/usr/local/bin/shardlure"), self.binary.read_bytes(), 0o755)
            actual_services = s.install_services
            def private_services(honeypot, dashboard):
                # Only network exposure is overridden: all generated unit,
                # account, config parsing and real Cowrie behavior remain real.
                cfg = self.data / "cowrie/etc/cowrie.cfg"
                cfg.write_text(cfg.read_text().replace("interface=0.0.0.0", "interface=127.0.0.1"))
                actual_services(honeypot, dashboard)
            with (mock.patch.object(s, "intro"), mock.patch.object(s, "install_deps"),
                  mock.patch.object(s, "prompt_config", return_value=(self.admin, self.new_admin, self.dashboard)),
                  mock.patch.object(s, "collect_admin_ips", return_value=["127.0.0.1"]),
                  mock.patch.object(s, "build_shardlure", side_effect=publish),
                  mock.patch.object(s, "install_services", side_effect=private_services)):
                s.cmd_run()
        self.await_ready()
        self.control_alive()
        self.login(self.new_admin)
        self.record("Python installer fresh setup", custom_literal_paths=True, real_cowrie=True)

    def permissions_and_ingest(self):
        service, cowrie = pwd.getpwnam("shardlure"), pwd.getpwnam("cowrie")
        for file in (self.data / "shardlure.db", self.data / "shardlure.db-wal", self.data / "shardlure.db-shm"):
            assert file.exists() and file.stat().st_uid == service.pw_uid and stat.S_IMODE(file.stat().st_mode) == 0o600
        assert run(["runuser", "-u", "cowrie", "--", "test", "-r", self.data / "shardlure.db"], check=False).returncode != 0
        run(["runuser", "-u", "cowrie", "--", "test", "-x", self.data])
        run(["runuser", "-u", "shardlure", "--", "test", "-w", self.data / "evidence"])
        self.installer.installer_safety.ensure_authbind(22, "cowrie")
        run(["runuser", "-u", "cowrie", "--", "authbind", "--deep", "python3", "-c",
             "import socket;s=socket.socket();s.bind(('127.0.0.1',22));s.close()"])
        self.record("real account traversal, private DB/WAL/SHM and authbind access")
        code = "import datetime,json,pathlib; p=pathlib.Path(__import__('sys').argv[1]); e={'eventid':'cowrie.command.input','timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(),'src_ip':'192.0.2.50','session':'inert-integration','input':'printf inert'}; f=p.open('a'); f.write(json.dumps(e)+chr(10)); f.close()"
        log = self.data / "cowrie/var/log/cowrie/cowrie.json"
        run(["runuser", "-u", "cowrie", "--", "python3", "-c", code, log])
        import sqlite3
        deadline = time.monotonic()+30
        while time.monotonic()<deadline:
            with sqlite3.connect(f"file:{self.data}/shardlure.db?mode=ro", uri=True) as db:
                if db.execute("select count(*) from events where session_id='inert-integration'").fetchone()[0] == 1:
                    break
            time.sleep(1)
        else:
            raise AssertionError("native live ingestion did not consume the Cowrie fixture")
        self.record("native live ingestion under dedicated service account")

    def failure_and_restore(self):
        import sqlite3
        with self.wrapper(self.data) as s:
            self.control_alive()
            s.validate_existing_accounts()
            original = (self.data / "shardlure.yaml").read_bytes()
            try:
                s.validate_installation()
            except SystemExit:
                pass
            else:
                raise AssertionError("active service was silently adopted")
            assert (self.data / "shardlure.yaml").read_bytes() == original
            self.record("active installation refused without data/config mutation")
            paths = (s.SSHD_CONFIG, s.SSHD_DROPIN, s.SSH_SOCKET_DROPIN)
            before = {p: p.read_bytes() if p.exists() else None for p in paths}
            native_run = s.run
            fired = False
            def fail_activation(args, **kwargs):
                nonlocal fired
                changed = any((p.read_bytes() if p.exists() else None) != v for p,v in before.items())
                if not fired and changed and args[:2] == ["systemctl", "restart"] and "ssh.socket" in args:
                    fired = True
                    return subprocess.CompletedProcess(args, 1, "", "injected activation failure")
                return native_run(args, **kwargs)
            try:
                with mock.patch.object(s, "run", side_effect=fail_activation):
                    s.restore_sshd()
            except (RuntimeError, ValueError, subprocess.CalledProcessError):
                pass
            else:
                raise AssertionError("injected SSH activation failure was ignored")
            assert fired
            assert {p:p.read_bytes() if p.exists() else None for p in paths} == before
            self.login(self.new_admin)
            self.control_alive()
            assert run(["systemctl", "is-active", "cowrie.service"]).stdout.strip()=="active"
            self.record("failed SSH restore rolls back files/listeners and restarts owned Cowrie")
            with sqlite3.connect(f"file:{self.data}/shardlure.db?mode=ro", uri=True) as db:
                events=db.execute("select count(*) from events").fetchone()[0]
            with mock.patch.object(sys, "argv", ["shardlure", "uninstall"]):
                s.cmd_uninstall()
            self.login(self.admin)
            self.control_alive()
            with sqlite3.connect(f"file:{self.data}/shardlure.db?mode=ro", uri=True) as db:
                assert db.execute("select count(*) from events").fetchone()[0]>=events
            assert (self.data / "shardlure.yaml").read_bytes()==original
            self.record("verified non-purging uninstall restores custom admin port and retains collection")

    def shell_adoption(self):
        with self.wrapper(self.data) as s:
            s.migrate_ssh_safely(self.new_admin)
        self.shell_install(self.data, True)
        self.record("release installer adopts the stopped, provenance-owned customized installation")
        self.control_alive()
        self.login(self.new_admin)

    def execute(self):
        try:
            assert os.environ["GITHUB_SHA"][:7] in run([self.binary, "version"]).stdout
            self.configure_ssh()
            self.release_bin = self.release_fixture()
            self.no_cowrie()
            self.python_install()
            self.permissions_and_ingest()
            self.failure_and_restore()
            self.shell_adoption()
            self.record("all real guest checks passed")
        except BaseException as exc:
            for path in ("/", "/srv", "/usr", "/usr/local", "/usr/local/bin", "/etc", "/etc/systemd", "/etc/systemd/system", "/tmp"):
                info = Path(path).stat()
                print(json.dumps({"diagnostic_directory": path, "uid": info.st_uid, "gid": info.st_gid,
                                  "mode": oct(stat.S_IMODE(info.st_mode))}), flush=True)
            for unit in ("shardlure-live.service", "cowrie.service"):
                status = run(["systemctl", "show", unit, "-p", "ActiveState", "-p", "SubState", "-p", "User", "-p", "Group", "-p", "ExecMainStatus"], check=False)
                print("guest service diagnostic", unit, status.stdout, flush=True)
                journal = run(["journalctl", "--unit", unit, "-n", "30", "--no-pager", "-o", "cat"], check=False)
                print("guest-only inert service log", unit, journal.stdout[-6000:], flush=True)
            if hasattr(self, "current_data"):
                try:
                    run(["systemctl", "stop", "shardlure-live.service"], check=False)
                    self.installer.installer_safety.prepare_accounts(self.current_data, Path("/etc/systemd/system"),
                                                                    "cowrie" if self.current_cowrie else None)
                    probe = self.work / "fsprobe"
                    run(["go", "build", "-o", probe, "./scripts/integration/fsprobe"], cwd=ROOT, timeout=240)
                    probe.chmod(0o755)
                    result = run(["runuser", "-u", "shardlure", "--", probe, self.current_data / "evidence/guest-probe"], check=False)
                    print("guest direct filesystem probe", result.stdout, result.stderr, flush=True)
                except Exception as diagnostic:
                    print("guest filesystem diagnostic unavailable", type(diagnostic).__name__, str(diagnostic)[:800], flush=True)
            self.write_report(f"{type(exc).__name__}: {str(exc)[:1600]}")
            raise
        finally:
            if self.master is not None:
                self.master.terminate()
                try:
                    self.master.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.master.kill()
                    self.master.wait()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-guest",action="store_true")
    parser.add_argument("--binary",type=Path)
    parser.add_argument("--report",type=Path)
    args=parser.parse_args()
    check_guest()
    if args.check_guest:
        return
    if args.binary is None or args.report is None:
        parser.error("--binary and --report are required")
    Acceptance(args.binary,args.report).execute()


if __name__=="__main__":
    main()
