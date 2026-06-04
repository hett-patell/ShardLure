#!/usr/bin/env python3
"""ShardLure VPS wrapper installer. Run: sudo python3 scripts/shardlure.py run"""
from __future__ import annotations

import getpass
import glob
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("SHARDLURE_DATA", "/var/lib/shardlure"))
CONFIG_FILE = DATA_DIR / "shardlure.yaml"
COWRIE_HOME = DATA_DIR / "cowrie"
COWRIE_LOG = COWRIE_HOME / "var/log/cowrie/cowrie.json"
COWRIE_USER = os.environ.get("COWRIE_USER", "cowrie")
BIN_DIR = Path("/usr/local/bin")
SYSTEMD_DIR = Path("/etc/systemd/system")


def log(msg: str) -> None:
    print(f"[shardlure] {msg}")


def die(msg: str) -> None:
    print(f"[shardlure] error: {msg}", file=sys.stderr)
    sys.exit(1)


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    log("$ " + " ".join(cmd))
    return subprocess.run(cmd, check=False, **kwargs)


def need_root() -> None:
    if os.geteuid() != 0:
        die("run as root: sudo python3 scripts/shardlure.py run")


def detect_pkg_manager() -> str:
    for cmd, name in [("apt-get", "apt"), ("dnf", "dnf"), ("yum", "yum"), ("pacman", "pacman")]:
        if shutil.which(cmd):
            return name
    return "unknown"


def install_deps() -> None:
    pm = detect_pkg_manager()
    arch = os.uname().machine
    log(f"installing dependencies via {pm} ({arch})")
    if pm == "apt":
        run(["apt-get", "update", "-qq"])
        run(
            [
                "apt-get", "install", "-y",
                "git", "python3", "python3-venv", "python3-dev", "python3-pip",
                "build-essential", "libssl-dev", "libffi-dev", "authbind",
                "curl", "ca-certificates", "golang-go",
            ],
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
    elif pm in ("dnf", "yum"):
        run([pm, "install", "-y", "git", "python3", "python3-pip", "python3-devel",
             "gcc", "openssl-devel", "libffi-devel", "authbind", "curl", "ca-certificates", "golang"])
    elif pm == "pacman":
        run(["pacman", "-Sy", "--noconfirm", "git", "python", "python-pip", "base-devel",
             "openssl", "libffi", "authbind", "curl", "go"])
    else:
        log("unknown package manager; ensure git python3 venv authbind go are installed")


def prompt_config() -> tuple[int, int, int]:
    print("\nShardLure honeypot setup\n------------------------")
    print("Real SSH moves to a private admin port (key-only).")
    print("Cowrie honeypot listens on the bait port for attackers.\n")
    hp = input("Honeypot SSH port attackers should hit [22]: ").strip() or "22"
    ap = input("Admin SSH port for your key-based login [2222]: ").strip() or "2222"
    dp = input("Dashboard port [8080]: ").strip() or "8080"
    honeypot, admin, dash = int(hp), int(ap), int(dp)
    if honeypot == admin:
        die("honeypot port and admin port must differ")
    return honeypot, admin, dash


def collect_admin_ips() -> list[str]:
    ips: list[str] = []
    if shutil.which("tailscale"):
        cp = run(["tailscale", "ip", "-4"], capture_output=True, text=True)
        tsip = (cp.stdout or "").strip().splitlines()[:1]
        if tsip:
            ips.append(tsip[0])
            log(f"detected tailscale admin IP: {tsip[0]}")
    conn = os.environ.get("SSH_CONNECTION", "")
    if conn:
        src = conn.split()[0]
        if src and src != "127.0.0.1":
            ips.append(src)
            log(f"detected current SSH client IP: {src}")
    extra = input("Extra admin IPs to ignore (comma-separated, optional): ").strip()
    if extra:
        ips.extend(x.strip() for x in extra.split(",") if x.strip())
    return list(dict.fromkeys(ips))


def ensure_admin_ssh_keys() -> None:
    found = False
    for path in ["/root/.ssh/authorized_keys", *glob.glob("/home/*/.ssh/authorized_keys")]:
        if Path(path).is_file() and Path(path).stat().st_size > 0:
            found = True
    if not found:
        die("no authorized_keys found. Add your SSH public key before moving real SSH off port 22.")


def migrate_sshd(admin_port: int) -> None:
    log(f"moving real SSH to port {admin_port} (key-only)")
    ensure_admin_ssh_keys()
    dropin = Path("/etc/ssh/sshd_config.d/99-shardlure-admin.conf")
    dropin.parent.mkdir(parents=True, exist_ok=True)
    main_cfg = Path("/etc/ssh/sshd_config")
    bak = Path("/etc/ssh/sshd_config.shardlure-bak")
    if main_cfg.exists() and not bak.exists():
        shutil.copy2(main_cfg, bak)
    if main_cfg.exists():
        text = main_cfg.read_text()
        lines = []
        for line in text.splitlines():
            if line.startswith("Port "):
                lines.append("#" + line)
            else:
                lines.append(line)
        main_cfg.write_text("\n".join(lines) + "\n")
    dropin.write_text(
        f"""# Managed by ShardLure
Port {admin_port}
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
"""
    )

    def _rollback(reason: str) -> None:
        log(f"sshd config invalid ({reason}); rolling back to backup")
        if bak.exists():
            shutil.copy2(bak, main_cfg)
        try:
            dropin.unlink()
        except FileNotFoundError:
            pass
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "reload", "ssh"])

    cp = run(["sshd", "-t"])
    if cp.returncode != 0:
        _rollback("sshd -t failed")
        die("sshd -t rejected the new configuration; original ssh restored")

    run(["systemctl", "daemon-reload"])
    cp = run(["systemctl", "reload", "ssh"])
    if cp.returncode != 0:
        cp2 = run(["systemctl", "reload", "sshd"])
        if cp2.returncode != 0:
            _rollback("systemctl reload failed")
            die("ssh reload failed; original ssh restored")
    log(f"real SSH now on port {admin_port}")


def ensure_cowrie_user() -> None:
    if subprocess.run(["id", COWRIE_USER], capture_output=True).returncode != 0:
        run(["useradd", "-r", "-m", "-d", f"/home/{COWRIE_USER}", "-s", "/bin/bash", COWRIE_USER]).check_returncode()


def setup_authbind(honeypot_port: int) -> None:
    if honeypot_port >= 1024:
        return
    log(f"configuring authbind for port {honeypot_port}")
    if shutil.which("authbind"):
        p = Path(f"/etc/authbind/byport/{honeypot_port}")
        p.touch()
        shutil.chown(p, COWRIE_USER, COWRIE_USER)
        p.chmod(0o500)
        return
    py = COWRIE_HOME / "venv/bin/python3"
    log("authbind not found; applying setcap on python")
    cp = run(["setcap", "cap_net_bind_service=+ep", str(py)])
    if cp.returncode != 0:
        die(f"need authbind or setcap to bind honeypot port {honeypot_port}")


def install_cowrie(honeypot_port: int) -> None:
    log(f"installing Cowrie into {COWRIE_HOME}")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not (COWRIE_HOME / ".git").exists():
        run(["git", "clone", "--depth", "1", "https://github.com/cowrie/cowrie.git", str(COWRIE_HOME)]).check_returncode()
    else:
        run(["git", "-C", str(COWRIE_HOME), "pull", "--ff-only"])
    run([sys.executable, "-m", "venv", str(COWRIE_HOME / "venv")]).check_returncode()
    pip = COWRIE_HOME / "venv/bin/pip"
    run([str(pip), "install", "--upgrade", "pip", "wheel"]).check_returncode()
    run([str(pip), "install", "-r", str(COWRIE_HOME / "requirements.txt")]).check_returncode()
    run([str(pip), "install", "-e", "."], cwd=str(COWRIE_HOME)).check_returncode()
    for d in ["var/log/cowrie", "var/lib/cowrie/downloads", "etc"]:
        (COWRIE_HOME / d).mkdir(parents=True, exist_ok=True)
    cfg = COWRIE_HOME / "etc/cowrie.cfg"
    if not cfg.exists():
        shutil.copy2(COWRIE_HOME / "etc/cowrie.cfg.dist", cfg)
    text = cfg.read_text()
    block = f"""
[honeypot]
hostname = prod-app-server-01
sensor_name = prod-app-server-01
log_path = {COWRIE_HOME}/var/log/cowrie
state_path = {COWRIE_HOME}/var/lib/cowrie
download_path = {COWRIE_HOME}/var/lib/cowrie/downloads
contents_path = {COWRIE_HOME}/honeyfs
data_path = {COWRIE_HOME}/src/cowrie/data
etc_path = {COWRIE_HOME}/etc

[shell]
arch = linux-x64-lsb
kernel_name = Linux
kernel_version = 5.15.0-94-generic
kernel_build_string = #104-Ubuntu SMP Tue Jan 9 15:25:40 UTC 2024
hardware_platform = x86_64
operating_system = GNU/Linux
ssh_version = OpenSSH_8.9p1 Ubuntu-3ubuntu0.6, OpenSSL 3.0.2 15 Mar 2022
filesystem = {COWRIE_HOME}/src/cowrie/data/fs.pickle

[output_jsonlog]
enabled = true
logfile = {COWRIE_HOME}/var/log/cowrie/cowrie.json

[ssh]
version = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
listen_endpoints = tcp:{honeypot_port}:interface=0.0.0.0
"""
    if not all(s in text for s in ("[honeypot]", "[output_jsonlog]", "[ssh]")):
        text = text.rstrip() + "\n" + block
    cfg.write_text(text)
    cfg.write_text(patch_cowrie_cfg(cfg.read_text(), honeypot_port))
    apply_stealth_persona(honeypot_port)
    run(["chown", "-R", f"{COWRIE_USER}:{COWRIE_USER}", str(COWRIE_HOME)])
    setup_authbind(honeypot_port)


def apply_stealth_persona(honeypot_port: int) -> None:
    persona = ROOT / "install" / "persona"
    if (persona / "honeyfs").is_dir():
        log(f"applying stealth persona from {persona}")
        honeyfs_dst = COWRIE_HOME / "honeyfs"
        if honeyfs_dst.exists():
            shutil.rmtree(honeyfs_dst)
        shutil.copytree(persona / "honeyfs", honeyfs_dst)
    stealth_cfg = persona / "cowrie-stealth.cfg"
    if stealth_cfg.is_file():
        merged = patch_cowrie_cfg(stealth_cfg.read_text(), honeypot_port)
        (COWRIE_HOME / "etc/cowrie.cfg").write_text(merged)
    else:
        (COWRIE_HOME / "etc/cowrie.cfg").write_text(
            patch_cowrie_cfg((COWRIE_HOME / "etc/cowrie.cfg").read_text(), honeypot_port)
        )
    userdb = persona / "userdb.txt"
    if userdb.is_file():
        shutil.copy2(userdb, COWRIE_HOME / "etc/userdb.txt")
    ensure_cowrie_filesystem()
    plant_bait_files()
    keydir = COWRIE_HOME / "var/lib/cowrie"
    keydir.mkdir(parents=True, exist_ok=True)
    for pattern in ("ssh_host_*key", "ssh_host_*key.pub"):
        for p in keydir.glob(pattern):
            p.unlink(missing_ok=True)
    for algo, extra in [("ed25519", []), ("ecdsa", []), ("rsa", ["-b", "4096"])]:
        out = keydir / f"ssh_host_{algo}_key"
        run(["ssh-keygen", "-t", algo, *extra, "-f", str(out), "-N", ""]).check_returncode()
        out.chmod(0o600)


def ensure_cowrie_filesystem() -> None:
    src = COWRIE_HOME / "src/cowrie/data/fs.pickle"
    dst = COWRIE_HOME / "var/lib/cowrie/fs.pickle"
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.exists() and not dst.exists():
        shutil.copy2(src, dst)
    if not src.exists() and not dst.exists():
        die(f"missing cowrie filesystem pickle: {src}")


def plant_bait_files() -> None:
    bait_src = ROOT / "install" / "persona" / "bait"
    if not bait_src.is_dir():
        die(f"bait directory missing: {bait_src} — sync install/persona/bait to the server first")
    log("planting bait files into cowrie filesystem")
    pickle_path = COWRIE_HOME / "src/cowrie/data/fs.pickle"
    fsctl = COWRIE_HOME / "venv/bin/fsctl"
    honeyfs = COWRIE_HOME / "honeyfs"
    if honeyfs.exists():
        shutil.rmtree(honeyfs)
    shutil.copytree(bait_src, honeyfs, dirs_exist_ok=True)
    persona_hf = ROOT / "install" / "persona" / "honeyfs"
    if persona_hf.is_dir():
        for p in persona_hf.rglob("*"):
            if p.is_file():
                rel = p.relative_to(persona_hf)
                dest = honeyfs / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, dest)
    if not fsctl.exists() or not pickle_path.exists():
        return

    def fs(cmd: str) -> None:
        run([str(fsctl), str(pickle_path), cmd])

    for d in (
        "/opt", "/opt/app", "/opt/app/config", "/opt/app/secrets",
        "/home/deploy", "/home/deploy/.ssh", "/home/ubuntu/.aws",
        "/root",
        "/var/backups", "/var/backups/nightly",
        "/etc/nginx", "/etc/nginx/sites-available",
    ):
        cp = run([str(fsctl), str(pickle_path), f"mkdir {d}"])
        if cp.returncode != 0:
            pass
    for hostfile in bait_src.rglob("*"):
        if not hostfile.is_file():
            continue
        rel = hostfile.relative_to(bait_src)
        vpath = f"/{rel.as_posix()}"
        run([str(fsctl), str(pickle_path), f"touch {vpath}"])
        dst = honeyfs / rel
        if dst.is_file():
            run([str(fsctl), str(pickle_path), f"load {vpath} {dst}"])
    dst_pickle = COWRIE_HOME / "var/lib/cowrie/fs.pickle"
    if pickle_path.exists():
        shutil.copy2(pickle_path, dst_pickle)


def patch_cowrie_cfg(text: str, honeypot_port: int) -> str:
    endpoint = f"tcp:{honeypot_port}:interface=0.0.0.0"
    lines = text.splitlines()
    out: list[str] = []
    section = ""
    ssh_listen_set = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped.lower()
            out.append(line)
            continue
        if section == "[ssh]" and stripped.startswith("listen_endpoints"):
            if not ssh_listen_set:
                out.append(f"listen_endpoints = {endpoint}")
                ssh_listen_set = True
            continue
        out.append(line)
    if not ssh_listen_set:
        out.extend(["", "[ssh]", f"listen_endpoints = {endpoint}"])
    block = f"""
[honeypot]
hostname = prod-app-server-01
sensor_name = prod-app-server-01
log_path = {COWRIE_HOME}/var/log/cowrie
state_path = {COWRIE_HOME}/var/lib/cowrie
download_path = {COWRIE_HOME}/var/lib/cowrie/downloads
contents_path = {COWRIE_HOME}/honeyfs
data_path = {COWRIE_HOME}/src/cowrie/data
etc_path = {COWRIE_HOME}/etc

[shell]
arch = linux-x64-lsb
kernel_name = Linux
kernel_version = 5.15.0-94-generic
kernel_build_string = #104-Ubuntu SMP Tue Jan 9 15:25:40 UTC 2024
hardware_platform = x86_64
operating_system = GNU/Linux
ssh_version = OpenSSH_8.9p1 Ubuntu-3ubuntu0.6, OpenSSL 3.0.2 15 Mar 2022
filesystem = {COWRIE_HOME}/src/cowrie/data/fs.pickle

[output_jsonlog]
enabled = true
logfile = {COWRIE_HOME}/var/log/cowrie/cowrie.json

[ssh]
version = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
listen_endpoints = {endpoint}
"""
    if "[honeypot]" not in "\n".join(out):
        out.append(block.rstrip())
    return "\n".join(out).rstrip() + "\n"


def build_shardlure() -> None:
    log("building shardlure binary")
    if not (ROOT / "go.mod").exists():
        die(f"go.mod not found under {ROOT}")
    cp = run(["go", "mod", "tidy"], cwd=str(ROOT))
    if cp.returncode != 0:
        die("go mod tidy failed")
    out = Path("/tmp/shardlure")
    cp = run(["go", "build", "-o", str(out), "./cmd/shardlure"], cwd=str(ROOT))
    if cp.returncode != 0:
        die("go build failed")
    shutil.copy2(out, BIN_DIR / "shardlure")
    (BIN_DIR / "shardlure").chmod(0o755)


def write_config(admin_ips: list[str], admin_port: int, honeypot_port: int, dash_port: int) -> None:
    log(f"writing {CONFIG_FILE}")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    lines = [
        f"data_dir: {DATA_DIR}",
        "admin_ips:",
    ]
    for ip in admin_ips:
        lines.append(f"  - {ip}")
    lines.extend([
        "ssh:",
        f"  admin_port: {admin_port}",
        f"  honeypot_port: {honeypot_port}",
        "dashboard:",
        f"  port: {dash_port}",
        "  home_lat: 19.0760",
        "  home_lon: 72.8777",
        "  home_city: Mumbai",
        "  home_country: India",
        "  home_cc: IN",
        "journal:",
        "  unit: ssh",
        "cowrie:",
        f"  home: {COWRIE_HOME}",
        f"  json_log: {COWRIE_LOG}",
    ])
    CONFIG_FILE.write_text("\n".join(lines) + "\n")


def install_services(honeypot_port: int, dash_port: int) -> None:
    log("installing systemd services")
    py = COWRIE_HOME / "venv/bin/python"
    twistd = COWRIE_HOME / "venv/bin/twistd"
    if honeypot_port < 1024 and shutil.which("authbind"):
        cowrie_exec = (
            f"/usr/bin/authbind --deep {py} {twistd} "
            f"--umask 0022 --nodaemon --pidfile= -l - cowrie"
        )
    else:
        cowrie_exec = f"{py} {twistd} --umask 0022 --nodaemon --pidfile= -l - cowrie"
    (SYSTEMD_DIR / "cowrie.service").write_text(
        f"""[Unit]
Description=Cowrie SSH honeypot (ShardLure)
After=network.target

[Service]
Type=simple
User={COWRIE_USER}
Group={COWRIE_USER}
WorkingDirectory={COWRIE_HOME}
Environment=PYTHONPATH={COWRIE_HOME}/src
Environment=PATH={COWRIE_HOME}/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart={cowrie_exec}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    )
    (SYSTEMD_DIR / "shardlure-live.service").write_text(
        f"""[Unit]
Description=ShardLure live dashboard + telemetry ingest
After=network.target cowrie.service
Wants=cowrie.service

[Service]
Type=simple
Environment=SHARDLURE_CONFIG={CONFIG_FILE}
ExecStart={BIN_DIR}/shardlure live :{dash_port} --tailscale --cowrie={COWRIE_LOG}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    )
    run(["systemctl", "daemon-reload"]).check_returncode()
    run(["systemctl", "enable", "cowrie.service", "shardlure-live.service"]).check_returncode()
    run(["systemctl", "restart", "cowrie.service"]).check_returncode()
    run(["systemctl", "restart", "shardlure-live.service"]).check_returncode()


def open_firewall(honeypot_port: int, admin_port: int, dash_port: int) -> None:
    if not shutil.which("ufw"):
        return
    cp = run(["ufw", "status"], capture_output=True, text=True)
    if "active" not in (cp.stdout or "").lower():
        return
    for port in (honeypot_port, admin_port, dash_port):
        run(["ufw", "allow", f"{port}/tcp"])


def print_summary(admin_port: int, honeypot_port: int, dash_port: int) -> None:
    tsurl = ""
    if shutil.which("tailscale"):
        cp = run(["tailscale", "ip", "-4"], capture_output=True, text=True)
        tsurl = (cp.stdout or "").strip().splitlines()[:1]
        tsurl = tsurl[0] if tsurl else ""
    user = getpass.getuser()
    print("\nShardLure is running\n====================")
    print(f"Honeypot SSH (Cowrie): 0.0.0.0:{honeypot_port}")
    print(f"Admin SSH (real):      0.0.0.0:{admin_port}  (key-only)")
    print(f"Dashboard:             http://127.0.0.1:{dash_port}")
    if tsurl:
        print(f"Tailscale dashboard:   http://{tsurl}:{dash_port}")
    print("\nIMPORTANT: open a NEW terminal and verify admin SSH before closing this one:")
    print(f"  ssh -p {admin_port} {user}@<host-ip>")
    print("\nServices:")
    print("  systemctl status cowrie shardlure-live")
    print("  journalctl -u shardlure-live -f")


def load_finish_ports() -> tuple[int, int, int]:
    honeypot = int(os.environ.get("SHARDLURE_HONEYPOT_PORT", "22"))
    admin = int(os.environ.get("SHARDLURE_ADMIN_PORT", "2222"))
    dash = int(os.environ.get("SHARDLURE_DASH_PORT", "8080"))
    return honeypot, admin, dash


def collect_admin_ips_quiet() -> list[str]:
    ips: list[str] = []
    extra = os.environ.get("SHARDLURE_ADMIN_IPS", "")
    if extra:
        ips.extend(x.strip() for x in extra.split(",") if x.strip())
    if shutil.which("tailscale"):
        cp = run(["tailscale", "ip", "-4"], capture_output=True, text=True)
        tsip = (cp.stdout or "").strip().splitlines()[:1]
        if tsip:
            ips.append(tsip[0])
    conn = os.environ.get("SSH_CONNECTION", "")
    if conn:
        src = conn.split()[0]
        if src and src != "127.0.0.1":
            ips.append(src)
    return list(dict.fromkeys(ips))


def cmd_run() -> None:
    need_root()
    install_deps()
    honeypot, admin, dash = prompt_config()
    admin_ips = collect_admin_ips()
    migrate_sshd(admin)
    ensure_cowrie_user()
    install_cowrie(honeypot)
    build_shardlure()
    write_config(admin_ips, admin, honeypot, dash)
    open_firewall(honeypot, admin, dash)
    install_services(honeypot, dash)
    print_summary(admin, honeypot, dash)


def cmd_finish() -> None:
    """Resume setup after Cowrie/SSH steps (e.g. go build failed on corrupted sources)."""
    need_root()
    honeypot, admin, dash = load_finish_ports()
    admin_ips = collect_admin_ips_quiet()
    if not admin_ips:
        admin_ips = collect_admin_ips()
    log(f"finish: honeypot={honeypot} admin={admin} dashboard={dash}")
    build_shardlure()
    write_config(admin_ips, admin, honeypot, dash)
    open_firewall(honeypot, admin, dash)
    install_services(honeypot, dash)
    print_summary(admin, honeypot, dash)


def restore_sshd() -> None:
    """Undo migrate_sshd: remove the ShardLure drop-in and restore the original
    sshd_config from the backup, validated before reload. Done FIRST during
    uninstall so a botched teardown can never leave you locked out.

    If no backup exists (e.g. partial install) we still remove the drop-in and
    re-test; an invalid resulting config aborts the reload rather than risk the
    running sshd."""
    dropin = Path("/etc/ssh/sshd_config.d/99-shardlure-admin.conf")
    main_cfg = Path("/etc/ssh/sshd_config")
    bak = Path("/etc/ssh/sshd_config.shardlure-bak")
    changed = False
    if bak.exists():
        log("restoring original sshd_config from backup")
        shutil.copy2(bak, main_cfg)
        changed = True
    elif main_cfg.exists():
        # No backup: at least un-comment any "#Port " lines we may have added.
        text = main_cfg.read_text()
        new = "\n".join(
            line[1:] if line.startswith("#Port ") else line
            for line in text.splitlines()
        )
        if new != text:
            main_cfg.write_text(new + "\n")
            changed = True
    if dropin.exists():
        log("removing ShardLure sshd drop-in")
        dropin.unlink()
        changed = True
    if not changed:
        log("no ShardLure sshd changes found; leaving ssh config untouched")
        return
    cp = run(["sshd", "-t"])
    if cp.returncode != 0:
        die("restored sshd config failed sshd -t; NOT reloading. "
            "Inspect /etc/ssh/sshd_config before reloading ssh manually.")
    run(["systemctl", "daemon-reload"])
    if run(["systemctl", "reload", "ssh"]).returncode != 0:
        run(["systemctl", "reload", "sshd"])
    if bak.exists():
        bak.unlink(missing_ok=True)
    log("real SSH restored to its pre-ShardLure configuration")


def remove_services() -> None:
    log("stopping and removing systemd services")
    run(["systemctl", "stop", "shardlure-live.service", "cowrie.service"])
    run(["systemctl", "disable", "shardlure-live.service", "cowrie.service"])
    for unit in ("shardlure-live.service", "cowrie.service"):
        p = SYSTEMD_DIR / unit
        if p.exists():
            p.unlink()
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "reset-failed"])


def remove_firewall_rules(honeypot_port: int, admin_port: int, dash_port: int) -> None:
    if not shutil.which("ufw"):
        return
    cp = run(["ufw", "status"], capture_output=True, text=True)
    if "active" not in (cp.stdout or "").lower():
        return
    log("removing ufw rules added at install (admin port left as-is)")
    # Deliberately do NOT delete the admin SSH port rule — removing it could
    # lock the operator out. Only the honeypot + dashboard rules are reverted.
    for port in (honeypot_port, dash_port):
        if port == admin_port:
            continue
        run(["ufw", "delete", "allow", f"{port}/tcp"])


def cmd_uninstall() -> None:
    """Reverse the install: restore SSH, remove services + binary, and (with
    --purge) delete the cowrie user, data dir and captured intel.

    Order matters: SSH is restored FIRST so you cannot be locked out, even if a
    later step fails."""
    need_root()
    purge = "--purge" in sys.argv[2:]
    honeypot, admin, dash = load_finish_ports()

    log("ShardLure uninstall starting")
    log("step 1/5: restore real SSH (before anything else, to avoid lockout)")
    restore_sshd()

    log("step 2/5: stop + remove systemd services")
    remove_services()

    log("step 3/5: remove the shardlure binary")
    binp = BIN_DIR / "shardlure"
    if binp.exists():
        binp.unlink()
        log(f"removed {binp}")

    log("step 4/5: remove authbind byport file (if any)")
    if honeypot < 1024:
        ab = Path(f"/etc/authbind/byport/{honeypot}")
        if ab.exists():
            ab.unlink()
            log(f"removed {ab}")

    log("step 5/5: firewall + data")
    remove_firewall_rules(honeypot, admin, dash)

    if purge:
        log(f"--purge: deleting data dir {DATA_DIR} (cowrie clone, DB, evidence, config)")
        if DATA_DIR.exists():
            shutil.rmtree(DATA_DIR, ignore_errors=True)
        if subprocess.run(["id", COWRIE_USER], capture_output=True).returncode == 0:
            log(f"--purge: removing system user {COWRIE_USER}")
            run(["userdel", "-r", COWRIE_USER])
    else:
        log(f"data preserved at {DATA_DIR} (captured intel, DB, config).")
        log(f"  to also delete it and the '{COWRIE_USER}' user, re-run with --purge:")
        log("  sudo python3 scripts/shardlure.py uninstall --purge")

    print("\nShardLure uninstalled\n=====================")
    print(f"Real SSH restored. VERIFY before logging out: ssh -p {admin} <user>@<host>")
    print("  (If the backup was missing, double-check /etc/ssh/sshd_config by hand.)")
    if not purge:
        print(f"Data kept at {DATA_DIR}. Re-run with --purge to remove it.")


def cmd_status() -> None:
    run(["systemctl", "status", "cowrie.service", "shardlure-live.service", "--no-pager"])
    if (BIN_DIR / "shardlure").exists():
        run([str(BIN_DIR / "shardlure"), "status"])


def cmd_stop() -> None:
    need_root()
    run(["systemctl", "stop", "shardlure-live.service", "cowrie.service"])


def cmd_start() -> None:
    need_root()
    run(["systemctl", "start", "cowrie.service", "shardlure-live.service"])


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd in ("run", "setup"):
        cmd_run()
    elif cmd == "status":
        cmd_status()
    elif cmd == "stop":
        cmd_stop()
    elif cmd == "start":
        cmd_start()
    elif cmd == "finish":
        cmd_finish()
    elif cmd in ("plant-bait", "bait"):
        need_root()
        plant_bait_files()
        run(["systemctl", "restart", "cowrie.service"]).check_returncode()
        log("bait planted — test: ssh root@<public-ip> then cat /opt/app/.env")
    elif cmd in ("uninstall", "remove"):
        cmd_uninstall()
    else:
        die("usage: sudo python3 scripts/shardlure.py "
            "{run|finish|start|stop|status|plant-bait|uninstall [--purge]}")


if __name__ == "__main__":
    main()
