#!/usr/bin/env python3
"""ShardLure VPS wrapper installer. Run: sudo python3 scripts/shardlure.py run"""
from __future__ import annotations

import getpass
import json
import glob
import os
import pwd
import grp
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

if __package__:
    from . import installer_safety
    from . import ssh_transition
else:
    import installer_safety
    import ssh_transition

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("SHARDLURE_DATA", "/var/lib/shardlure"))
CONFIG_FILE = DATA_DIR / "shardlure.yaml"
COWRIE_HOME = DATA_DIR / "cowrie"
COWRIE_LOG = COWRIE_HOME / "var/log/cowrie/cowrie.json"
COWRIE_USER = os.environ.get("COWRIE_USER", "cowrie")
COWRIE_REPOSITORY = "https://github.com/cowrie/cowrie.git"
COWRIE_PIN_FILE = ROOT / "install" / "cowrie.commit"
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


def read_cowrie_pin(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1 or re.fullmatch(r"[0-9a-f]{40}", lines[0]) is None:
        raise ValueError(f"invalid Cowrie pin: {path}")
    return lines[0]


def ensure_cowrie_checkout(
    target: Path,
    pin: str,
    repository: str = COWRIE_REPOSITORY,
) -> None:
    """Create the exact detached Cowrie checkout or validate an existing one."""
    if (target / ".git").exists():
        current = run(
            [
                "git",
                "-c",
                f"safe.directory={target.resolve()}",
                "-C",
                str(target),
                "rev-parse",
                "HEAD",
            ],
            capture_output=True,
            text=True,
        )
        if current.returncode != 0:
            die(f"cannot read Cowrie HEAD at {target}; move the checkout aside and rerun")
        actual = current.stdout.strip()
        if actual != pin:
            die(
                f"Cowrie checkout at {target} is {actual}, expected {pin}; "
                "move it aside or check out the tested commit manually. "
                "ShardLure is refusing to pull or reset an existing checkout"
            )
        log(f"existing Cowrie checkout matches tested commit {pin}")
        return

    if target.exists():
        die(f"Cowrie target {target} exists but is not a Git checkout; move it aside and rerun")

    target.parent.mkdir(parents=True, exist_ok=True)
    staging_root = Path(tempfile.mkdtemp(prefix=".cowrie-checkout-", dir=str(target.parent)))
    checkout = staging_root / "cowrie"
    try:
        run(["git", "init", "-q", str(checkout)]).check_returncode()
        run(["git", "-C", str(checkout), "remote", "add", "origin", repository]).check_returncode()
        run([
            "git", "-C", str(checkout), "fetch", "--depth", "1", "origin", pin,
        ]).check_returncode()
        run(["git", "-C", str(checkout), "checkout", "--detach", pin]).check_returncode()
        current = run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
        )
        if current.returncode != 0 or current.stdout.strip() != pin:
            die(f"Cowrie checkout verification failed: expected HEAD {pin}")
        os.replace(checkout, target)
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)


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
        # `update` may fail on a transient repo mirror yet still leave usable
        # cached package lists, so it's non-fatal; the `install` MUST succeed
        # (a partial dep set surfaces later as a cryptic build/runtime failure).
        run(["apt-get", "update", "-qq"])
        run(
            [
                "apt-get", "install", "-y",
                "git", "python3", "python3-venv", "python3-dev", "python3-pip",
                "build-essential", "libssl-dev", "libffi-dev", "authbind",
                "curl", "ca-certificates", "golang-go",
            ],
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        ).check_returncode()
    elif pm in ("dnf", "yum"):
        run([pm, "install", "-y", "git", "python3", "python3-pip", "python3-devel",
             "gcc", "openssl-devel", "libffi-devel", "authbind", "curl", "ca-certificates", "golang"]).check_returncode()
    elif pm == "pacman":
        run(["pacman", "-Sy", "--noconfirm", "git", "python", "python-pip", "base-devel",
             "openssl", "libffi", "authbind", "curl", "go"]).check_returncode()
    else:
        log("unknown package manager; ensure git python3 venv authbind go are installed")


def _ask_port(prompt: str, default: int) -> int:
    while True:
        raw = input(f"{prompt} [{default}]: ").strip() or str(default)
        try:
            n = int(raw)
        except ValueError:
            print("  Not a number — enter a port between 1 and 65535.")
            continue
        if 1 <= n <= 65535:
            return n
        print("  Port must be between 1 and 65535.")


def prompt_config() -> tuple[int, int, int]:
    print("\nShardLure honeypot setup\n------------------------")
    print("Real SSH moves to a private admin port (key-only).")
    print("Cowrie honeypot listens on the bait port for attackers.\n")
    honeypot = _ask_port("Honeypot SSH port attackers should hit", 22)
    admin = _ask_port("Admin SSH port for your key-based login", 2222)
    dash = _ask_port("Dashboard port", 8080)
    if honeypot == admin:
        die("honeypot port and admin port must differ")
    if dash in (honeypot, admin):
        die("dashboard port must differ from the SSH ports")
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


def _existing_authorized_keys() -> list[str]:
    """Return authorized_keys files that already hold at least one key."""
    found = []
    for path in ["/root/.ssh/authorized_keys", *glob.glob("/home/*/.ssh/authorized_keys")]:
        p = Path(path)
        if p.is_file() and p.stat().st_size > 0:
            found.append(path)
    return found


def _looks_like_ssh_pubkey(line: str) -> bool:
    parts = line.strip().split()
    return (
        len(parts) >= 2
        and parts[0] in (
            "ssh-ed25519", "ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com",
            "sk-ecdsa-sha2-nistp256@openssh.com",
        )
        and len(parts[1]) > 20
    )


def _install_pubkey(pubkey: str) -> None:
    """Update only the selected account's descriptor-validated key file."""
    user = os.environ.get("SUDO_USER") or "root"
    account = pwd.getpwnam(user)
    path = ssh_transition.append_public_key(account, pubkey)
    log(f"installed public key for account {user} at {path}")


def ensure_admin_ssh_keys() -> None:
    """Guarantee a usable SSH key exists BEFORE we move real SSH off port 22 —
    interactively onboarding one if needed, so a fresh-VPS user is never told to
    'go add a key yourself' and then locked out. Refuses to proceed without a key."""
    found = _existing_authorized_keys()
    if found:
        log(f"found existing authorized_keys: {', '.join(found)}")
        return

    print(
        "\n  No SSH public key found on this server.\n"
        "  Real SSH is about to move to a key-only admin port, so you MUST have a\n"
        "  key installed first — otherwise you'll be locked out.\n\n"
        "  On YOUR laptop, print your public key (create one with `ssh-keygen -t ed25519` if needed):\n"
        "      cat ~/.ssh/id_ed25519.pub      # or id_rsa.pub\n"
    )
    for attempt in range(3):
        pubkey = input("  Paste your SSH PUBLIC key here (starts with ssh-ed25519/ssh-rsa), or blank to abort: ").strip()
        if not pubkey:
            break
        if _looks_like_ssh_pubkey(pubkey):
            _install_pubkey(pubkey)
            if _existing_authorized_keys():
                return
            die("key install did not take effect; aborting before touching sshd")
        print("  That doesn't look like a public key (expected e.g. 'ssh-ed25519 AAAA... user@host'). Try again.")
    die("no SSH key installed. Add your public key and re-run; "
        "real SSH was NOT moved, so you are not locked out.")


def ssh_is_socket_activated() -> bool:
    """True when systemd's ssh.socket owns the listening port(s).

    On Ubuntu 22.10+/24.04 sshd is socket-activated: ssh.socket's
    ListenStream= determines the listening port and the `Port` directive in
    sshd_config is silently IGNORED. If we don't account for this, the admin
    SSH "move" writes Port <admin> but sshd keeps listening on 22 — and once
    Cowrie grabs 22, the operator is locked out. Detect it so migrate_sshd can
    write a socket drop-in instead of relying on the (ineffective) Port line.
    """
    cp = run(["systemctl", "is-active", "ssh.socket"], capture_output=True, text=True)
    if cp.stdout.strip() == "active":
        return True
    cp = run(["systemctl", "is-enabled", "ssh.socket"], capture_output=True, text=True)
    return cp.stdout.strip() in ("enabled", "static", "indirect")


SSHD_CONFIG = Path("/etc/ssh/sshd_config")
SSHD_DROPIN = Path("/etc/ssh/sshd_config.d/99-shardlure-admin.conf")
SSH_SOCKET_DROPIN = Path("/etc/systemd/system/ssh.socket.d/zz-shardlure-admin.conf")


def _effective_ssh_config() -> str:
    cp = run(["sshd", "-T"], capture_output=True, text=True)
    cp.check_returncode()
    return cp.stdout or ""


def _ssh_ports(config: str) -> set[int]:
    return {int(m.group(1)) for m in re.finditer(r"(?im)^port\s+(\d+)\s*$", config)}


def _reload_ssh(socket_activated: bool) -> None:
    if socket_activated:
        # Accept=no socket activation passes listeners to the long-lived sshd
        # parent. Restarting only the socket leaves that parent holding the old
        # descriptors (and the old authentication policy). Debian/Ubuntu use
        # KillMode=process so replacing the parent preserves session children.
        # Refuse unknown/custom kill semantics rather than disconnect the admin.
        cp = run(["systemctl", "show", "ssh.service", "--property=KillMode", "--value"],
                 capture_output=True, text=True)
        cp.check_returncode()
        if (cp.stdout or "").strip() != "process":
            die("socket-activated SSH requires KillMode=process to preserve sessions; configure SSH manually")
    run(["systemctl", "daemon-reload"]).check_returncode()
    if socket_activated:
        run(["systemctl", "restart", "ssh.socket", "ssh.service"]).check_returncode()
    else:
        cp = run(["systemctl", "reload", "ssh"])
        if cp.returncode != 0:
            run(["systemctl", "reload", "sshd"]).check_returncode()


def _ssh_transition() -> ssh_transition.SSHTransition:
    state = installation_state().load()
    return ssh_transition.SSHTransition(SSHD_CONFIG, SSHD_DROPIN, SSH_SOCKET_DROPIN,
        runner=run, socket_activated=ssh_is_socket_activated(), reloader=_reload_ssh,
        install_id=state["stamp"])


def _apply_ssh_ports(admin_port: int, *, final: bool):
    transition = _ssh_transition()
    transition.stage(admin_port, final=final)
    return transition.rollback


def migrate_sshd(admin_port: int):
    """Stage the new listener while retaining all effective old SSH ports."""
    log(f"adding admin SSH port {admin_port}; existing ports stay available until verification")
    return _apply_ssh_ports(admin_port, final=False)


def finalize_sshd_migration(admin_port: int) -> None:
    """Retire old listeners only after a separate public-key login succeeds."""
    _apply_ssh_ports(admin_port, final=True)


def open_admin_firewall(admin_port: int) -> bool:
    if not 1 <= admin_port <= 65535:
        raise ValueError("admin port must be 1-65535")
    if not shutil.which("ufw"):
        return False
    cp = run(["ufw", "status"], capture_output=True, text=True)
    cp.check_returncode()
    if not re.search(r"(?im)^status:\s*active\s*$", cp.stdout or ""):
        return False
    run(["ufw", "allow", f"{admin_port}/tcp"]).check_returncode()
    return True


def migrate_ssh_safely(admin_port: int) -> None:
    ensure_admin_ssh_keys()
    if not open_admin_firewall(admin_port):
        log("UFW is absent/inactive: ensure the admin port is allowed by any host/cloud firewall")
    rollback = migrate_sshd(admin_port)
    try:
        verify_admin_ssh_gate(admin_port)
        finalize_sshd_migration(admin_port)
    except BaseException:
        if rollback is not None:
            rollback()
        raise


def ensure_cowrie_user() -> None:
    validate_existing_accounts()
    if subprocess.run(["id", COWRIE_USER], capture_output=True).returncode != 0:
        run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", str(COWRIE_HOME), "--shell", "/usr/sbin/nologin", COWRIE_USER]).check_returncode()
        installation_state().remember_account(pwd.getpwnam(COWRIE_USER), True)


def setup_authbind(honeypot_port: int) -> None:
    if honeypot_port >= 1024:
        return
    log(f"configuring authbind for port {honeypot_port}")
    if not shutil.which("authbind"):
        die("authbind is required for low ports; refusing to change shared interpreter capabilities")
    installer_safety.ensure_authbind(honeypot_port, COWRIE_USER)


def install_cowrie(honeypot_port: int) -> None:
    try:
        pin = read_cowrie_pin(COWRIE_PIN_FILE)
    except (OSError, ValueError) as exc:
        die(f"cannot load tested Cowrie commit: {exc}")
    log(f"installing Cowrie into {COWRIE_HOME}")
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    existing = COWRIE_HOME.exists()
    ensure_cowrie_checkout(COWRIE_HOME, pin)
    if existing:
        log("existing Cowrie source, environment, host keys and configuration preserved; use the dedicated patch workflow for source changes")
        return
    run([sys.executable, "-m", "venv", str(COWRIE_HOME / "venv")]).check_returncode()
    pip = [str(COWRIE_HOME / "venv/bin/python"), "-m", "pip"]
    run([*pip, "install", "--upgrade", "pip", "wheel"]).check_returncode()
    run([*pip, "install", "-r", str(COWRIE_HOME / "requirements.txt")]).check_returncode()
    # Build Cowrie from a sanitized path.  Its vcs_versioning backend performs
    # variable substitution on the checkout path, so paths containing `$` or
    # `%` can fail during wheel metadata generation.  Build from a safe
    # temporary copy (preserving .git so the version backend can still derive
    # the pinned commit), then install the resulting wheel into the real venv.
    #
    # The build venv must also live under the sanitized path: setuptools'
    # bdist_wheel -> install -> expand_basedirs reads config_vars from
    # sys.prefix, so building with the real venv's Python (whose prefix
    # contains $VALUE) triggers subst_vars -> ValueError even from a clean
    # working directory.  The throwaway venv has a clean sys.prefix; the
    # resulting wheel is then installed into the real venv using pip's wheel
    # installer, which bypasses distutils entirely.
    with tempfile.TemporaryDirectory(prefix="cowrie-build-") as build_root:
        build_root = Path(build_root)
        build_checkout = build_root / "cowrie"

        # Copy the source checkout without the venv and generated runtime data.
        shutil.copytree(
            COWRIE_HOME,
            build_checkout,
            ignore=shutil.ignore_patterns(
                "venv",
                "var",
                "honeyfs",
                "__pycache__",
                "*.pyc",
            ),
        )

        # Create a throwaway build venv under the sanitized path.
        build_venv = build_root / "venv"
        run([sys.executable, "-m", "venv", str(build_venv)]).check_returncode()
        build_pip = [str(build_venv / "bin/python"), "-m", "pip"]
        run([*build_pip, "install", "--upgrade", "pip", "wheel", "setuptools"]).check_returncode()

        wheel_dir = build_root / "wheel"
        wheel_dir.mkdir()

        run(
            [
                *build_pip,
                "wheel",
                "--no-deps",
                "--wheel-dir",
                str(wheel_dir),
                ".",
            ],
            cwd=str(build_checkout),
        ).check_returncode()

        wheels = sorted(wheel_dir.glob("cowrie-*.whl"))
        if len(wheels) != 1:
            die(f"expected one Cowrie wheel, found: {wheels}")

        run([*pip, "install", str(wheels[0])]).check_returncode()

        # cowrie.service runs with PYTHONPATH=<cowrie>/src so the
        # anti-fingerprint patches applied to src/ below take effect, and
        # Cowrie's package __init__ exits "Cowrie is not installed" unless
        # src/cowrie/_version.py exists. That file is generated by the build
        # (an editable install used to write it in place); carry it over from
        # the temporary build copy, or the service crash-loops on start.
        generated = build_checkout / "src/cowrie/_version.py"
        if not generated.is_file():
            die("Cowrie build did not generate src/cowrie/_version.py; refusing an unstartable install")
        shutil.copy2(generated, COWRIE_HOME / "src/cowrie/_version.py")
    for d in ["var/log/cowrie", "var/lib/cowrie/downloads", "etc"]:
        (COWRIE_HOME / d).mkdir(parents=True, exist_ok=True)
    cfg = COWRIE_HOME / "etc/cowrie.cfg"
    if not cfg.exists():
        # Locate the distributed default config. Cowrie used to ship it at
        # etc/cowrie.cfg.dist; newer revisions moved it under
        # src/cowrie/data/etc/. Search both (and fall back to a glob) so the
        # installer works across Cowrie versions.
        dist_candidates = [
            COWRIE_HOME / "etc/cowrie.cfg.dist",
            COWRIE_HOME / "src/cowrie/data/etc/cowrie.cfg.dist",
        ]
        dist = next((p for p in dist_candidates if p.exists()), None)
        if dist is None:
            found = list(COWRIE_HOME.glob("**/cowrie.cfg.dist"))
            dist = found[0] if found else None
        if dist is None:
            die("could not find cowrie.cfg.dist in the Cowrie checkout; "
                "Cowrie's layout may have changed again")
        shutil.copy2(dist, cfg)
    # patch_cowrie_cfg injects/normalizes the [honeypot]/[shell]/[output_jsonlog]/
    # [ssh] sections (and the listen_endpoints port) idempotently. It is the
    # single source of truth for the config shape — apply_stealth_persona below
    # re-runs it against the stealth template, so we don't hand-assemble a
    # duplicate block here.
    cfg.write_text(patch_cowrie_cfg(cfg.read_text(), honeypot_port))
    apply_stealth_persona(honeypot_port)
    installer_safety.prepare_cowrie_tree(DATA_DIR, COWRIE_USER)
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
        # Cowrie reads userdb.txt as STRICT ASCII (auth.py uses
        # read_text(encoding="ascii")); a single non-ASCII byte makes the whole
        # userdb load throw and cowrie silently falls back to built-in defaults
        # — so our bait credentials would never apply. Validate here and strip
        # any stray non-ASCII rather than shipping a userdb cowrie can't read.
        raw = userdb.read_bytes()
        try:
            raw.decode("ascii")
            clean = raw
        except UnicodeDecodeError:
            log("warning: persona userdb.txt has non-ASCII bytes; stripping them "
                "(cowrie reads userdb as strict ASCII and would otherwise ignore it)")
            clean = raw.decode("utf-8", "ignore").encode("ascii", "ignore")
        (COWRIE_HOME / "etc/userdb.txt").write_bytes(clean)
    ensure_cowrie_filesystem()
    plant_bait_files()
    deploy_txtcmds()
    deploy_time_persona()
    deploy_patches()
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

    python = COWRIE_HOME / "venv/bin/python"

    def fs(cmd: str) -> None:
        # mkdir on an existing dir (and similar) is a benign non-zero exit;
        # fsctl prints its own diagnostics, so no extra handling here.
        # Run the script through the venv interpreter, never via its own
        # shebang: pip writes a /bin/sh trampoline that quotes the interpreter
        # path without escaping `"`, `$` or `\`, so on such a data path every
        # call failed "not found" and the bait silently never loaded. This is
        # the same way cowrie.service starts twistd.
        run([str(python), str(fsctl), str(pickle_path), cmd])

    for d in (
        "/opt", "/opt/app", "/opt/app/config", "/opt/app/secrets",
        "/home/deploy", "/home/deploy/.ssh", "/home/ubuntu/.aws",
        "/root",
        "/var/backups", "/var/backups/nightly",
        "/etc/nginx", "/etc/nginx/sites-available",
    ):
        fs(f"mkdir {d}")
    for hostfile in bait_src.rglob("*"):
        if not hostfile.is_file():
            continue
        rel = hostfile.relative_to(bait_src)
        vpath = f"/{rel.as_posix()}"
        fs(f"touch {vpath}")
        dst = honeyfs / rel
        if dst.is_file():
            fs(f"load {vpath} {dst}")
    dst_pickle = COWRIE_HOME / "var/lib/cowrie/fs.pickle"
    if pickle_path.exists():
        shutil.copy2(pickle_path, dst_pickle)


def deploy_txtcmds() -> None:
    """Copy persona txtcmds into Cowrie's share dir (anti-fingerprint stubs)."""
    txtcmds_src = ROOT / "install" / "persona" / "txtcmds"
    if not txtcmds_src.is_dir():
        return
    txtcmds_dst = COWRIE_HOME / "share" / "cowrie" / "txtcmds"
    txtcmds_dst.mkdir(parents=True, exist_ok=True)
    log("deploying txtcmds anti-fingerprint stubs")
    for src_file in txtcmds_src.rglob("*"):
        if not src_file.is_file():
            continue
        rel = src_file.relative_to(txtcmds_src)
        dst = txtcmds_dst / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_file, dst)


def deploy_time_persona() -> None:
    """Regenerate time-sensitive persona files against the live clock.

    The txtcmds/honeyfs files are otherwise frozen at a fixed date, which is a
    honeypot tell: Cowrie's `date` renders from the real clock, so a visitor
    comparing `date` to `uptime`/`last`/`who` would see the box stuck months in
    the past. The generator rewrites uptime/w/who/last and /proc/uptime so they
    track "now" and agree with each other. Must run AFTER deploy_txtcmds() (it
    overwrites files that step just planted).
    """
    gen = ROOT / "install" / "persona" / "gen-time-persona.py"
    if not gen.is_file():
        return
    log("refreshing time-sensitive persona against live clock")
    proc = run([sys.executable, str(gen), str(COWRIE_HOME)])
    if proc.returncode != 0:
        # Non-fatal: a stale-but-planted persona still works, just fingerprintable.
        log(f"warning: time-persona generator exited {proc.returncode}; "
            "persona time files may be stale (fingerprintable)")


def deploy_patches() -> None:
    """Preflight and apply all Cowrie source patches as one guarded batch."""
    orchestrator = ROOT / "install" / "persona" / "apply-patches.py"
    if not orchestrator.is_file():
        die(f"Cowrie patch orchestrator missing: {orchestrator}")
    log("applying Cowrie source patches (anti-fingerprint)")
    proc = run([sys.executable, str(orchestrator), str(COWRIE_HOME)])
    if proc.returncode != 0:
        die("Cowrie patch preflight/apply failed; refusing to continue with a fingerprintable honeypot")


def cowrie_cfg_value(value: object) -> str:
    """Escape a literal for Cowrie's ExtendedInterpolation config reader.

    Cowrie (install/cowrie.commit, core/config.py) parses cowrie.cfg with
    configparser.ExtendedInterpolation, where `$` introduces `${...}`
    references and a bare `$` is a syntax error. A data path containing `$`
    therefore made every path lookup raise and Cowrie could not start.
    """
    return str(value).replace("$", "$$")


def patch_cowrie_cfg(text: str, honeypot_port: int) -> str:
    endpoint = f"tcp:{honeypot_port}:interface=0.0.0.0"
    home = cowrie_cfg_value(COWRIE_HOME)
    lines = text.splitlines()
    out: list[str] = []
    section = ""
    ssh_listen_set = False
    ssh_section_seen = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            # Leaving a section. If it was [ssh] and it had no
            # listen_endpoints line of its own, inject ours here rather than
            # emitting a second [ssh] header later (configparser rejects
            # duplicate sections with DuplicateSectionError).
            if section == "[ssh]" and not ssh_listen_set:
                out.append(f"listen_endpoints = {endpoint}")
                ssh_listen_set = True
            section = stripped.lower()
            if section == "[ssh]":
                ssh_section_seen = True
            out.append(line)
            continue
        if section == "[ssh]" and stripped.startswith("listen_endpoints"):
            if not ssh_listen_set:
                out.append(f"listen_endpoints = {endpoint}")
                ssh_listen_set = True
            continue
        out.append(line)
    # Handle [ssh] being the final section in the file (no trailing header to
    # trigger the inject-on-exit path above).
    if ssh_section_seen and not ssh_listen_set:
        out.append(f"listen_endpoints = {endpoint}")
        ssh_listen_set = True
    if not ssh_listen_set:
        out.extend(["", "[ssh]", f"listen_endpoints = {endpoint}"])
    # Ensure required sections exist AND that each carries its required keys.
    # Guaranteeing only the section header (the old behaviour) was a latent bug:
    # the stealth persona template ships a [honeypot] with just hostname/
    # sensor_name, so a header-only check left etc_path/log_path/state_path/
    # contents_path/data_path and [shell] filesystem UNSET. Cowrie then silently
    # ignored etc/userdb.txt (etc_path empty -> custom creds never applied) and
    # could miss the bait fs.pickle (filesystem unset). We now merge any missing
    # key into an existing section and only append a whole section when absent.
    required = {
        "honeypot": [
            ("hostname", "prod-app-server-01"),
            # timezone=UTC is load-bearing, not cosmetic: cowrie's output
            # plugin stamps the jsonlog 'timestamp' field with a 'Z' suffix
            # only when TZ is UTC at process start. On a non-UTC host without
            # this key, cowrie writes LOCAL time mislabeled as Zulu and every
            # ShardLure event lands hours off from journal events in the same
            # DB. Belt-and-braces with Environment=TZ=UTC in cowrie.service
            # (cowrie sets os.environ['TZ'] from this key but never calls
            # time.tzset(), so the unit env is what reliably wins).
            ("timezone", "UTC"),
            ("sensor_name", "prod-app-server-01"),
            ("log_path", f"{home}/var/log/cowrie"),
            ("state_path", f"{home}/var/lib/cowrie"),
            ("download_path", f"{home}/var/lib/cowrie/downloads"),
            ("contents_path", f"{home}/honeyfs"),
            ("data_path", f"{home}/src/cowrie/data"),
            ("etc_path", f"{home}/etc"),
        ],
        "shell": [
            ("arch", "linux-x64-lsb"),
            ("kernel_name", "Linux"),
            ("kernel_version", "5.15.0-94-generic"),
            ("kernel_build_string", "#104-Ubuntu SMP Tue Jan 9 15:25:40 UTC 2024"),
            ("hardware_platform", "x86_64"),
            ("operating_system", "GNU/Linux"),
            ("ssh_version", "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6, OpenSSL 3.0.2 15 Mar 2022"),
            ("filesystem", f"{home}/src/cowrie/data/fs.pickle"),
        ],
        "output_jsonlog": [
            ("enabled", "true"),
            ("logfile", f"{home}/var/log/cowrie/cowrie.json"),
        ],
    }

    # Parse the current output into ordered sections so we can inject missing
    # keys in place (rather than appending a duplicate header).
    def section_of(line: str) -> str | None:
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            return s[1:-1].lower()
        return None

    # Which keys already appear under each section?
    present: dict[str, set[str]] = {}
    cur = ""
    for line in out:
        sec = section_of(line)
        if sec is not None:
            cur = sec
            present.setdefault(cur, set())
            continue
        s = line.strip()
        if cur and s and not s.startswith("#") and "=" in s:
            present.setdefault(cur, set()).add(s.split("=", 1)[0].strip().lower())

    # Inject missing keys into existing sections by rebuilding line-by-line,
    # emitting the additions right after the section header.
    rebuilt: list[str] = []
    cur = ""
    for line in out:
        rebuilt.append(line)
        sec = section_of(line)
        if sec is not None and sec in required:
            have = present.get(sec, set())
            for key, val in required[sec]:
                if key not in have:
                    rebuilt.append(f"{key} = {val}")
                    have.add(key)
    out = rebuilt

    # Append any required section that was entirely absent.
    joined_secs = {section_of(l) for l in out if section_of(l) is not None}
    for sec, kvs in required.items():
        if sec not in joined_secs:
            out.append("")
            out.append(f"[{sec}]")
            out.extend(f"{k} = {v}" for k, v in kvs)

    return "\n".join(out).rstrip() + "\n"


def build_shardlure() -> None:
    log("building shardlure binary")
    if not (ROOT / "go.mod").exists():
        die(f"go.mod not found under {ROOT}")
    cp = run(["go", "mod", "tidy"], cwd=str(ROOT))
    if cp.returncode != 0:
        die("go mod tidy failed")
    # Build into a private temp file inside the root-owned BIN_DIR (not the
    # world-writable /tmp) to avoid a TOCTOU/symlink race on a predictable
    # path, then atomically move it into place.
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".shardlure.", dir=str(BIN_DIR))
    os.close(fd)
    out = Path(tmp_name)
    try:
        cp = run(["go", "build", "-o", str(out), "./cmd/shardlure"], cwd=str(ROOT))
        if cp.returncode != 0:
            die("go build failed")
        installation_state().publish(BIN_DIR / "shardlure", installer_safety.read_regular(out, 128 << 20), 0o755)
    finally:
        out.unlink(missing_ok=True)


def write_config(admin_ips: list[str], admin_port: int, honeypot_port: int, dash_port: int) -> None:
    log(f"writing {CONFIG_FILE}")
    if CONFIG_FILE.exists() or CONFIG_FILE.is_symlink():
        installer_safety.read_regular(CONFIG_FILE, 4 << 20)
        log("existing configuration preserved; edit it explicitly to change policy")
        return
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    lines = [
        f"data_dir: {json.dumps(str(DATA_DIR), ensure_ascii=False)}",
        "admin_ips:",
    ]
    for ip in admin_ips:
        lines.append(f"  - {json.dumps(ip)}")
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
        f"  home: {json.dumps(str(COWRIE_HOME), ensure_ascii=False)}",
        f"  json_log: {json.dumps(str(COWRIE_LOG), ensure_ascii=False)}",
        # config.Default() leaves geoip disabled; without this section a box
        # installed via this script had the globe/country stats silently off
        # while install.sh boxes had them on.
        "geoip:",
        "  enabled: true",
        "  insecure_http: true",
    ])
    installer_safety.atomic_create(CONFIG_FILE, ("\n".join(lines) + "\n").encode())


def prepare_service_account() -> None:
    """Preflight all selected objects, then change only pinned descriptors."""
    validate_existing_accounts()
    if COWRIE_HOME != DATA_DIR / "cowrie" or CONFIG_FILE != DATA_DIR / "shardlure.yaml":
        die("service state paths must remain inside the selected data directory")
    try:
        installer_safety.prepare_accounts(DATA_DIR, SYSTEMD_DIR, COWRIE_USER, runner=run)
    except (OSError, ValueError):
        die("unsafe or changed service data; ownership migration refused")


def validate_existing_accounts() -> None:
    """Read-only identity preflight shared with the release installer."""
    try:
        for path in (DATA_DIR, COWRIE_HOME, COWRIE_LOG, CONFIG_FILE, BIN_DIR, SYSTEMD_DIR):
            systemd_value(str(path))
            installer_safety.checked_absolute(path)
        installer_safety.validate_accounts(DATA_DIR, COWRIE_USER)
    except (OSError, ValueError) as exc:
        die(f"service account/path preflight refused: {exc}")


def installation_state():
    return installer_safety.InstallationState(DATA_DIR, SYSTEMD_DIR)


def managed_resource_paths() -> list[Path]:
    return [SYSTEMD_DIR / "shardlure-live.service", SYSTEMD_DIR / "cowrie.service", BIN_DIR / "shardlure"]


def validate_installation() -> None:
    """Read-only preflight before packages, SSH changes or filesystem writes."""
    try:
        installer_safety.preflight(DATA_DIR, SYSTEMD_DIR, BIN_DIR, COWRIE_USER, runner=run)
    except (OSError, ValueError) as exc:
        die(f"installation preflight refused: {exc}")


def begin_installation() -> None:
    owners = set()
    for name in ("shardlure", COWRIE_USER):
        try:
            owners.add(pwd.getpwnam(name).pw_uid)
        except KeyError:
            pass
    with installer_safety.PermissionPlan(DATA_DIR, owners):
        pass
    installation_state().begin()


def validate_purge_target() -> None:
    """Require installer-owned directory identity before any uninstall mutation."""
    if (not DATA_DIR.is_absolute() or len(DATA_DIR.parts) < 3 or
            DATA_DIR == Path.home() or DATA_DIR in (Path("/var/lib"), Path("/var/log"), Path("/usr/local")) or
            DATA_DIR.parent == Path("/home") or
            any(p.is_symlink() for p in (DATA_DIR, *DATA_DIR.parents))):
        die("refusing broad or unsafe purge target")
    try:
        installation_state().load()
    except (OSError, ValueError, TypeError):
        die("purge requires verified installation provenance; legacy data is preserved")


def record_installation() -> None:
    state = installation_state()
    state.begin()
    state.finish()


def systemd_value(value: str) -> str:
    """Encode a literal directive value without Exec-only dollar expansion."""
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("unsupported control character in service value")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    return f'"{escaped}"'


def systemd_path(value: str) -> str:
    """Encode a single-path setting that systemd does NOT unquote.

    WorkingDirectory= takes the raw rest of the line (only %-specifiers are
    expanded), unlike Exec*/Environment=/ReadWritePaths=. Quoting it the way
    systemd_value does made systemd read the value as a relative path and
    refuse the whole unit on the adversarial-path guest. Spaces, quotes, `$`
    and backslashes are literal here; only `%` needs doubling, and outer
    whitespace would be silently trimmed, so it is refused.
    """
    systemd_value(value)
    if not value.startswith("/") or value != value.strip():
        raise ValueError("unsupported path for a raw systemd path setting")
    return value.replace("%", "%%")


def systemd_exec_arg(value: str) -> str:
    return systemd_value(value).replace("$", "$$")


def systemd_environment(key: str, value: str) -> str:
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None:
        raise ValueError("invalid environment variable name")
    return systemd_value(key + "=" + value)


def render_services(honeypot_port: int, dash_port: int) -> dict[str, str]:
    # Validate the complete input set before writing either unit.
    for value in (DATA_DIR, COWRIE_HOME, COWRIE_LOG, CONFIG_FILE, BIN_DIR, SYSTEMD_DIR):
        systemd_value(str(value))
        if not value.is_absolute():
            raise ValueError("service paths must be absolute")
    if re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", COWRIE_USER) is None:
        raise ValueError("invalid Cowrie service account")
    tailscale = _tailscale_iface()
    listen = f":{dash_port} --tailscale" if tailscale else f"127.0.0.1:{dash_port}"
    tailscale_unit = ""
    tailscale_prestart = ""
    if tailscale:
        tailscale_bin = shutil.which("tailscale")
        if not tailscale_bin:
            die("Tailscale executable disappeared before service generation")
        tailscale_arg = systemd_exec_arg(os.path.abspath(tailscale_bin))
        # tailscaled can report active before it has assigned tailscale0 an
        # address after boot. Keep --tailscale fail-closed, but wait for the
        # address rather than making systemd restart the daemon repeatedly.
        tailscale_unit = "Wants=network-online.target tailscaled.service\nAfter=network-online.target tailscaled.service\n"
        # Pass the detected path as a positional argument: it is data for sh,
        # not shell syntax. $$ survives systemd's environment expansion as $.
        tailscale_prestart = (
            "ExecStartPre=/bin/sh -ec 'for i in 1 2 3 4 5 6 7 8 9 10 "
            "11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; "
            'do address=$$("$$1" ip -4) && test -n "$$address" && exit 0; '
            f"sleep 1; done; exit 1' sh {tailscale_arg}\n"
        )
    py = COWRIE_HOME / "venv/bin/python"
    twistd = COWRIE_HOME / "venv/bin/twistd"
    authbind_bin = shutil.which("authbind")
    if honeypot_port < 1024 and authbind_bin:
        cowrie_exec = (
            f"{systemd_exec_arg(os.path.abspath(authbind_bin))} --deep {systemd_exec_arg(str(py))} {systemd_exec_arg(str(twistd))} "
            f"--umask 0027 --nodaemon --pidfile= -l - cowrie"
        )
    else:
        # systemd refuses an Exec executable path containing `$` (and `$$` is
        # only unescaped in arguments), so the venv interpreter under a data
        # path cannot be argv[0] of the unit. A fixed /bin/sh exec()s it
        # instead: the path stays a literal argument and the shell never
        # parses it ("$@" expands positional parameters without re-splitting).
        cowrie_exec = (
            "/bin/sh -c 'exec \"$$@\"' cowrie-launch "
            f"{systemd_exec_arg(str(py))} {systemd_exec_arg(str(twistd))} --umask 0027 --nodaemon --pidfile= -l - cowrie"
        )
    cowrie_text = f"""[Unit]
Description=Cowrie SSH honeypot (ShardLure)
After=network.target

[Service]
Type=simple
User={COWRIE_USER}
Group={COWRIE_USER}
WorkingDirectory={systemd_path(str(COWRIE_HOME))}
Environment={systemd_environment("PYTHONPATH",str(COWRIE_HOME / "src"))}
Environment={systemd_environment("PATH",str(COWRIE_HOME / "venv/bin")+":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")}
Environment=TZ=UTC
UMask=0027
ExecStart={cowrie_exec}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    live_text = f"""[Unit]
Description=ShardLure live dashboard + telemetry ingest
After=network.target cowrie.service
Wants=cowrie.service
{tailscale_unit}

[Service]
Type=simple
User=shardlure
Group=shardlure
SupplementaryGroups=systemd-journal {COWRIE_USER}
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths={systemd_value(str(DATA_DIR))}
ReadOnlyPaths={systemd_value(str(COWRIE_HOME))}
ReadWritePaths={systemd_value(str(COWRIE_HOME / "var/lib/cowrie/downloads"))} {systemd_value(str(COWRIE_HOME / "var/lib/cowrie/tty"))}
MemoryMax=1G
TasksMax=256
TimeoutStopSec=45
Environment={systemd_environment("SHARDLURE_CONFIG",str(CONFIG_FILE))}
{tailscale_prestart}ExecStart={systemd_exec_arg(str(BIN_DIR / "shardlure"))} live {listen} {systemd_exec_arg("--cowrie="+str(COWRIE_LOG))}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    return {"cowrie.service": cowrie_text, "shardlure-live.service": live_text}


def install_services(honeypot_port: int, dash_port: int) -> None:
    units = render_services(honeypot_port, dash_port)
    log("validating and publishing systemd services")
    state = installation_state()
    state.check_resources([SYSTEMD_DIR / name for name in units])
    with tempfile.TemporaryDirectory(prefix=".shardlure-units-", dir=SYSTEMD_DIR) as staging:
        paths = []
        for name, text in units.items():
            path = Path(staging) / name
            path.write_text(text)
            paths.append(str(path))
        run(["systemd-analyze", "verify", *paths], capture_output=True, text=True).check_returncode()
        for name, text in units.items():
            state.publish(SYSTEMD_DIR / name, text.encode(), 0o600)
    run(["systemctl", "daemon-reload"]).check_returncode()
    installer_safety.verify_unit_accounts(COWRIE_USER, runner=run)
    run(["systemctl", "enable", "cowrie.service", "shardlure-live.service"]).check_returncode()
    try:
        run(["systemctl", "restart", "cowrie.service"]).check_returncode()
        run(["systemctl", "restart", "shardlure-live.service"]).check_returncode()
        run(["systemctl", "is-active", "--quiet", "cowrie.service", "shardlure-live.service"]).check_returncode()
    except BaseException:
        run(["systemctl", "stop", "shardlure-live.service", "cowrie.service"]).check_returncode()
        raise


def open_firewall(honeypot_port: int, admin_port: int, dash_port: int) -> None:
    if not shutil.which("ufw"):
        return
    cp = run(["ufw", "status"], capture_output=True, text=True)
    cp.check_returncode()
    if not re.search(r"(?im)^Status:\s+active\s*$", cp.stdout or ""):
        return
    # The honeypot MUST be world-reachable (that's the point) and the admin
    # SSH port is key-only, so both open publicly. The DASHBOARD is different:
    # it exposes attacker IPs, captured payloads, and the bait-file layout with
    # no built-in auth unless SHARDLURE_DASH_TOKEN is set — so it must NOT be
    # opened to the internet. Bind it to the Tailscale interface when present
    # (the intended admin path); otherwise leave it firewalled and reachable
    # only via localhost / an SSH tunnel. An operator who genuinely wants it
    # public can `ufw allow 8080/tcp` themselves after setting a token.
    for port in (honeypot_port, admin_port):
        run(["ufw", "allow", f"{port}/tcp"]).check_returncode()
    ts_iface = _tailscale_iface()
    if ts_iface:
        run(["ufw", "allow", "in", "on", ts_iface, "to", "any", "port", str(dash_port), "proto", "tcp"])
        log(f"dashboard port {dash_port} allowed on {ts_iface} only (not public)")
    else:
        log(f"dashboard port {dash_port} left firewalled (no tailscale iface); "
            f"reach it via: ssh -L {dash_port}:127.0.0.1:{dash_port} -p {admin_port} <user>@<host>")


def _tailscale_iface() -> str:
    """Return the Tailscale interface name (usually tailscale0) if this host is
    on a tailnet, else ''. Used to scope the dashboard firewall rule."""
    if not shutil.which("tailscale"):
        return ""
    cp = run(["tailscale", "ip", "-4"], capture_output=True, text=True)
    if not (cp.stdout or "").strip():
        return ""
    # tailscale0 is the near-universal name; confirm it exists before returning.
    if Path("/sys/class/net/tailscale0").exists():
        return "tailscale0"
    return ""


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
    print(f"Dashboard:             http://127.0.0.1:{dash_port}  (not public — see below)")
    if tsurl:
        print(f"Tailscale dashboard:   http://{tsurl}:{dash_port}")
    else:
        print(f"  reach the dashboard via an SSH tunnel:")
        print(f"    ssh -L {dash_port}:127.0.0.1:{dash_port} -p {admin_port} {user}@<host-ip>")
    print("  (the dashboard is firewalled off the public internet; set")
    print("   SHARDLURE_DASH_TOKEN + `ufw allow " + str(dash_port) + "/tcp` if you want it exposed)")
    print("\nIMPORTANT: open a NEW terminal and verify admin SSH before closing this one:")
    print(f"  ssh -p {admin_port} {user}@<host-ip>")
    print("\nServices:")
    print("  systemctl status cowrie shardlure-live")
    print("  journalctl -u shardlure-live -f")


def _env_port(name: str, default: int) -> int:
    """Parse a port from the environment, falling back to default on a missing,
    non-numeric, or out-of-range value (rather than crashing with a bare
    int() ValueError mid-install)."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        p = int(raw)
    except ValueError:
        die(f"{name} must be an integer 1-65535, got {raw!r}")
    if not (1 <= p <= 65535):
        die(f"{name} must be in range 1-65535, got {p}")
    return p


def load_finish_ports() -> tuple[int, int, int]:
    honeypot = _env_port("SHARDLURE_HONEYPOT_PORT", 22)
    admin = _env_port("SHARDLURE_ADMIN_PORT", 2222)
    dash = _env_port("SHARDLURE_DASH_PORT", 8080)
    return honeypot, admin, dash


def load_ports_from_config() -> tuple[int, int, int]:
    """Read the honeypot/admin/dashboard ports from the persisted
    shardlure.yaml so teardown reverses the firewall/authbind for the ports
    that were ACTUALLY used, not the env defaults. Falls back to
    load_finish_ports() (env/defaults) when the config is missing or a value
    can't be parsed. The installer writes this file by hand, so we parse the
    three known lines directly rather than pull in a YAML dependency."""
    honeypot, admin, dash = load_finish_ports()
    if not CONFIG_FILE.is_file():
        return honeypot, admin, dash
    section = ""
    for raw in CONFIG_FILE.read_text().splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")) and line.rstrip().endswith(":"):
            section = line.strip().rstrip(":")
            continue
        kv = line.strip()
        if ":" not in kv:
            continue
        key, _, val = kv.partition(":")
        key, val = key.strip(), val.strip()
        try:
            if section == "ssh" and key == "honeypot_port":
                honeypot = int(val)
            elif section == "ssh" and key == "admin_port":
                admin = int(val)
            elif section == "dashboard" and key == "port":
                dash = int(val)
        except ValueError:
            pass  # keep the fallback for an unparseable value
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


def intro() -> None:
    print(
        "\n"
        "============================================================\n"
        " ShardLure installer — SSH honeypot + threat-intel dashboard\n"
        "============================================================\n"
        " This will, on THIS server:\n"
        "   1. Install dependencies (git, python, Go, authbind, …)\n"
        "   2. Move your REAL SSH to a private, key-only admin port\n"
        "   3. Run the Cowrie honeypot on the bait port (default 22)\n"
        "   4. Build + start ShardLure (live ingest + dashboard)\n"
        "\n"
        "  Before it moves SSH it will make sure you have a working key\n"
        "  installed (it'll help you paste one in if not), and it pauses\n"
        "  for you to VERIFY the new admin port works before continuing.\n"
        "  The original sshd config is backed up and auto-rolled-back if\n"
        "  the new one fails to validate.\n"
    )
    if input("  Proceed? [Y/n]: ").strip().lower() in ("n", "no"):
        die("aborted by user (nothing changed)")


def verify_admin_ssh_gate(admin_port: int, *, key_only: bool = True) -> None:
    """Pause after migrating sshd so the user proves they can still get in on the
    new port BEFORE the install proceeds (and before they close this session)."""
    user = os.environ.get("SUDO_USER") or getpass.getuser()
    host = "<this-server-ip>"
    conn = os.environ.get("SSH_CONNECTION", "")
    if conn:
        parts = conn.split()
        if len(parts) >= 3:
            host = parts[2]  # the server-side IP of the current SSH connection
    auth_options = ("-o PreferredAuthentications=publickey -o PasswordAuthentication=no "
                    "-o KbdInteractiveAuthentication=no ") if key_only else ""
    print(
        "\n  -------------------------------------------------------------\n"
        f"  Real SSH also listens on port {admin_port}; old SSH ports remain open.\n"
        "  >>> In a SEPARATE terminal, confirm a NEW authenticated login:\n"
        f"        ssh -o ControlMaster=no -o ControlPath=none {auth_options}-p {admin_port} {user}@{host}\n"
        "  Do NOT close this session until that works.\n"
        "  No unverified listener retirement is allowed; restoration keeps original policy.\n"
        "  If it fails, Ctrl-C here to restore the previous SSH configuration.\n"
        "  -------------------------------------------------------------\n"
    )
    while True:
        ans = input(f"  Did `ssh -p {admin_port}` succeed in the other terminal? [yes/abort]: ").strip().lower()
        if ans in ("yes", "y"):
            return
        if ans in ("abort", "a", "no", "n"):
            die("aborted — restoring previous SSH configuration; fix your key access before proceeding")
        print("  Please type 'yes' once you've confirmed login, or 'abort' to stop.")


def cmd_run() -> None:
    need_root()
    validate_existing_accounts()
    validate_installation()
    intro()
    install_deps()
    honeypot, admin, dash = prompt_config()
    admin_ips = collect_admin_ips()
    begin_installation()
    state = installation_state()
    state.seal()
    try:
        migrate_ssh_safely(admin)
        ensure_cowrie_user()
        install_cowrie(honeypot)
        build_shardlure()
        write_config(admin_ips, admin, honeypot, dash)
        open_firewall(honeypot, admin, dash)
        prepare_service_account()
        install_services(honeypot, dash)
        record_installation()
    finally:
        state.unseal()
    print_summary(admin, honeypot, dash)


def cmd_finish() -> None:
    """Resume setup after Cowrie/SSH steps (e.g. go build failed on corrupted sources)."""
    need_root()
    validate_existing_accounts()
    validate_installation()
    begin_installation()
    honeypot, admin, dash = load_finish_ports()
    admin_ips = collect_admin_ips_quiet()
    if not admin_ips:
        admin_ips = collect_admin_ips()
    log(f"finish: honeypot={honeypot} admin={admin} dashboard={dash}")
    state = installation_state()
    state.seal()
    try:
        build_shardlure()
        write_config(admin_ips, admin, honeypot, dash)
        open_firewall(honeypot, admin, dash)
        prepare_service_account()
        install_services(honeypot, dash)
        record_installation()
    finally:
        state.unseal()
    print_summary(admin, honeypot, dash)


def restore_sshd() -> set[int]:
    """Restore verified SSH state without retiring unverified management access."""
    transition = _ssh_transition()
    if not transition.receipt.exists():
        if any(p.exists() or p.is_symlink() for p in (SSHD_DROPIN, SSH_SOCKET_DROPIN, transition.backup)):
            die("SSH recovery provenance is missing; existing configuration and listeners were preserved")
        log("this installation did not change SSH; leaving it untouched")
        return transition.before_ports

    def stop_conflicting(ports):
        honeypot, _, _ = load_ports_from_config()
        if honeypot not in ports:
            return False
        status = run(["systemctl", "is-active", "cowrie.service"], capture_output=True, text=True)
        if (status.stdout or "").strip() != "active":
            return False
        installation_state().check_resources([SYSTEMD_DIR / "cowrie.service"])
        run(["systemctl", "stop", "cowrie.service"]).check_returncode()
        return True

    restored = transition.restore(
        lambda port: verify_admin_ssh_gate(port, key_only=False),
        stop_conflicting=stop_conflicting,
        restart_conflicting=lambda: run(["systemctl", "start", "cowrie.service"]).check_returncode())
    log("SSH restoration verified; original recovery material retained")
    return restored


def remove_services() -> None:
    log("stopping and removing systemd services")
    state = installation_state()
    state.check_resources(managed_resource_paths())
    units = [name for name in ("shardlure-live.service", "cowrie.service") if (SYSTEMD_DIR / name).exists()]
    if units:
        run(["systemctl", "stop", *units]).check_returncode()
        run(["systemctl", "disable", *units]).check_returncode()
    for unit in units:
        p = SYSTEMD_DIR / unit
        state.remove(p)
    run(["systemctl", "daemon-reload"]).check_returncode()


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
    # Preserving data is not permission to remove an unrelated binary or unit.
    # Legacy installations need an explicit ownership review before teardown.
    validate_purge_target()
    try:
        installation_state().check_resources(managed_resource_paths())
    except (OSError, ValueError):
        die("uninstall ownership check failed; customized or unrelated resources are preserved")
    # Use the persisted install config so firewall/authbind cleanup and the
    # lockout-verification hint target the ports this install ACTUALLY used,
    # not the env defaults (env vars/SHARDLURE_*_PORT still override).
    honeypot, admin, dash = load_ports_from_config()
    log(f"uninstall: honeypot={honeypot} admin={admin} dashboard={dash} (from {CONFIG_FILE} if present)")

    log("ShardLure uninstall starting")
    log("step 1/5: restore real SSH (before anything else, to avoid lockout)")
    restored_ports = restore_sshd()

    log("step 2/5: stop + remove systemd services")
    remove_services()

    log("step 3/5: remove the shardlure binary")
    binp = BIN_DIR / "shardlure"
    if binp.exists():
        installation_state().remove(binp)
        log(f"removed {binp}")

    log("step 4/5: remove authbind byport file (if any)")
    if honeypot < 1024:
        ab = Path(f"/etc/authbind/byport/{honeypot}")
        if ab.exists():
            log("authbind rule retained; review shared port ownership before manual removal")

    log("step 5/5: firewall + data")
    remove_firewall_rules(honeypot, admin, dash)

    if purge:
        log(f"--purge: deleting data dir {DATA_DIR} (cowrie clone, DB, evidence, config)")
        if DATA_DIR.exists():
            validate_purge_target()
            installation_state().purge()
        log("service accounts retained; review shared ownership before manual removal")
    else:
        log(f"data preserved at {DATA_DIR} (captured intel, DB, config).")
        log("  to also delete verified installation data, re-run with --purge (accounts are retained):")
        log("  sudo python3 scripts/shardlure.py uninstall --purge")

    print("\nShardLure uninstalled\n=====================")
    print("Verified SSH ports: " + ", ".join(str(p) for p in sorted(restored_ports)))
    print("  Original SSH recovery material is retained for operator review.")
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
