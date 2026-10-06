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


# The pinned Cowrie (install/cowrie.commit, v3.1.1) declares requires-python
# >=3.11: v3.1 dropped 3.10, which is what Ubuntu 22.04 ships. Its venv is
# built from the interpreter running this installer, so an older one gives a
# pip failure halfway through the install, after the SSH migration.
COWRIE_MIN_PYTHON = (3, 11)


def require_cowrie_python(version: tuple = tuple(sys.version_info[:3]),
                          executable: str = sys.executable) -> None:
    """Refuse, before anything is changed, to install the pinned Cowrie with a
    Python it does not support."""
    if tuple(version[:2]) >= COWRIE_MIN_PYTHON:
        return
    have = ".".join(str(part) for part in version)
    want = ".".join(str(part) for part in COWRIE_MIN_PYTHON)
    die(f"the pinned Cowrie (v3.1.1) needs Python {want} or newer, but this installer runs "
        f"under Python {have} ({executable}); Ubuntu 22.04 ships 3.10. Use Ubuntu 24.04 or "
        f"newer, or install python{want} with its venv module and rerun with it "
        f"(sudo python{want} scripts/shardlure.py run). Nothing was changed")


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
    require_cowrie_python()
    try:
        pin = read_cowrie_pin(COWRIE_PIN_FILE)
    except (OSError, ValueError) as exc:
        die(f"cannot load tested Cowrie commit: {exc}")
    log(f"installing Cowrie into {COWRIE_HOME}")
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    existing = COWRIE_HOME.exists()
    ensure_cowrie_checkout(COWRIE_HOME, pin)
    if existing:
        # Preserve only a complete installation. A checkout left by a run that
        # failed before the venv/build/config finished would otherwise be
        # "preserved" into an unstartable honeypot on every re-run.
        missing = [rel for rel in ("venv/bin/python", "src/cowrie/_version.py", "etc/cowrie.cfg")
                   if not (COWRIE_HOME / rel).is_file()]
        if missing:
            die(f"Cowrie at {COWRIE_HOME} is incomplete (missing {', '.join(missing)}), "
                "probably from an interrupted install; move it aside and rerun. Nothing was changed")
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
    # Before the two persona steps: over a tree the Cowrie account already
    # owns they run as that account from this root-owned copy.
    deploy_persona_regen()
    deploy_time_persona()
    # gen-time-persona rewrites honeyfs/etc/motd after plant_bait_files sized
    # its node; size it (and embed it) again from the final file.
    cmd_persona_fs(COWRIE_HOME)
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


def cowrie_owned_prefix(*paths: Path) -> list[str]:
    """`runuser -u <cowrie> --` when root is about to run code or parse data
    that a non-root account can write (any of `paths` not owned by root),
    else []. Unprivileged callers need no prefix."""
    if os.geteuid() != 0:
        return []
    for path in paths:
        try:
            owner = os.lstat(path).st_uid
        except OSError:
            continue
        if owner != 0:
            return ["runuser", "-u", COWRIE_USER, "--"]
    return []


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
    # fsctl is Cowrie's own tool: it pickle.loads the fs.pickle, and it runs
    # from the venv. On a fresh install both are root's (the tree is handed to
    # the Cowrie account afterwards, prepare_cowrie_tree); on `plant-bait`
    # over an installed tree both belong to the account that handles attacker
    # input, so root running them would execute whatever that account planted
    # (Task 7 re-review N-2). Run it as that account then: it can only edit a
    # pickle it could already write.
    as_owner = cowrie_owned_prefix(COWRIE_HOME / "venv", COWRIE_HOME / "venv/bin",
                                   fsctl, pickle_path.parent, pickle_path)

    def fs(cmd: str) -> None:
        # mkdir on an existing dir (and similar) is a benign non-zero exit;
        # fsctl prints its own diagnostics, so no extra handling here.
        # Run the script through the venv interpreter, never via its own
        # shebang: pip writes a /bin/sh trampoline that quotes the interpreter
        # path without escaping `"`, `$` or `\`, so on such a data path every
        # call failed "not found" and the bait silently never loaded. This is
        # the same way cowrie.service starts twistd.
        run([*as_owner, str(python), str(fsctl), str(pickle_path), cmd])

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
    apply_persona_fs(pickle_path, honeyfs)
    dst_pickle = COWRIE_HOME / "var/lib/cowrie/fs.pickle"
    if pickle_path.exists():
        shutil.copy2(pickle_path, dst_pickle)


# Cowrie's fs.pickle node layout (cowrie/shell/fs.py A_NAME..A_REALFILE) and
# node types. A node is a 10-item list; a directory's A_CONTENTS is its list of
# children, a symlink's target is A_TARGET.
_FS_NAME, _FS_TYPE, _FS_UID, _FS_GID, _FS_SIZE, _FS_MODE, _FS_CTIME, _FS_CONTENTS, _FS_TARGET = range(9)
_FS_LINK, _FS_DIR, _FS_FILE = 0, 1, 2
# The persona is a 22.04.4 cloud image built in early 2024 (os-release, kernel
# 5.15.0-94); a node newer than that would date the box. The pickle stamps its
# own /etc/os-release with this instant.
PERSONA_IMAGE_TIME = 1706476800

# Files a 22.04 server cloud image ships that Cowrie runs (it registers these
# commands) but whose pickle has no node, so `ls -l /usr/bin/sudo`, `[ -x
# /usr/bin/crontab ]` and `command -v sudo` said the box lacks them. Path,
# size, mode, gid and time are the jammy cloud rootfs's (ubuntu-22.04-server-
# cloudimg-amd64-root.tar.xz), times clamped to PERSONA_IMAGE_TIME; crontab is
# setgid crontab (104 in the persona's /etc/group), sudo setuid root. Where
# the package was updated after the persona image, the time is a plausible
# pre-image jammy-updates build of it, not the image instant for all (seven
# nodes sharing one minute looked like a cluster; review m-6). The
# names 22.04 does not ship (python, php, gcc, yum, ifconfig, netstat...) stay
# absent, as on the real box.
PERSONA_FS_FILES = (
    ("/usr/bin/busybox", 2193272, 0o100755, 0, 1648118592),
    ("/usr/bin/crontab", 39568, 0o102755, 104, 1648063140),
    ("/usr/bin/dig", 154448, 0o100755, 0, 1697212300),
    ("/usr/bin/git", 3710360, 0o100755, 0, 1689171362),
    # The persona ships txtcmds for these two, but with no node they answered
    # `command not found` (review m-7): lsb-release 11.1.0ubuntu4 and systemd.
    ("/usr/bin/hostnamectl", 31104, 0o100755, 0, 1699965993),
    ("/usr/bin/lsb_release", 3638, 0o100755, 0, 1566787260),
    # psmisc 23.4-2build3; Cowrie registers killall (Task 7 review I-2).
    ("/usr/bin/killall", 32096, 0o100755, 0, 1648139377),
    ("/usr/bin/lspci", 94288, 0o100755, 0, 1630311300),
    ("/usr/bin/nc.openbsd", 39560, 0o100755, 0, 1645634340),
    ("/usr/bin/ping", 76680, 0o100755, 0, 1643876571),
    ("/usr/bin/sudo", 232416, 0o104755, 0, 1680595879),
    ("/usr/bin/systemctl", 1119856, 0o100755, 0, 1699965993),
    ("/usr/sbin/ethtool", 564712, 0o100755, 0, 1645855964),
    ("/usr/sbin/xtables-nft-multi", 224296, 0o100755, 0, 1705459440),
    # python3.10 3.10.12-1~22.04.3 (built Nov 20 2023, the build python3 -VV
    # and its REPL banner print; install/persona/patches/python3-emulation.py).
    # The pickle shipped Debian's python3.11, which 22.04 does not have.
    ("/usr/bin/python3.10", 5941864, 0o100755, 0, 1700493240),
    ("/usr/bin/pydoc3.10", 79, 0o100755, 0, 1700493240),
)
# Their symlinks, as 22.04 lays them out. Targets are absolute: Cowrie resolves
# a relative target from / rather than from the link's directory, so the real
# `xtables-nft-multi` (relative) would dangle.
PERSONA_FS_LINKS = (
    ("/etc/alternatives/nc", "/bin/nc.openbsd"),
    ("/etc/alternatives/netcat", "/bin/nc.openbsd"),
    ("/usr/bin/nc", "/etc/alternatives/nc"),
    ("/usr/bin/netcat", "/etc/alternatives/netcat"),
    ("/etc/alternatives/iptables", "/usr/sbin/iptables-nft"),
    ("/usr/sbin/iptables-nft", "/usr/sbin/xtables-nft-multi"),
    ("/usr/sbin/iptables", "/etc/alternatives/iptables"),
    ("/usr/sbin/halt", "/bin/systemctl"),
    ("/usr/sbin/poweroff", "/bin/systemctl"),
    ("/usr/sbin/reboot", "/bin/systemctl"),
    ("/usr/sbin/shutdown", "/bin/systemctl"),
    ("/usr/bin/python3", "/usr/bin/python3.10"),
    ("/usr/bin/pydoc3", "/usr/bin/pydoc3.10"),
)
# Directories renamed in place (contents kept): the stdlib directory follows
# the interpreter version.
PERSONA_FS_RENAMES = (
    ("/usr/lib/python3.11", "python3.10"),
)
# Real 22.04 sizes for binaries whose pickle node carries another build's:
# `ls -lh $(which ls)` (35 sessions in 30 days) prints this one, `135K` on
# coreutils 8.32-4.1ubuntu1 (the pickle's Debian ls is 151344, `148K`).
PERSONA_FS_SIZES = (
    ("/usr/bin/ls", 138216),
)
# Stock Cowrie's demo user: phil (uid 1000) is in the pickle's passwd, group
# and shadow with a /home/phil, a known Cowrie fingerprint (the IMC 2025
# study saw >90% of phil logins disconnect at once). The persona's honeyfs
# passwd/group/shadow drop him; this drops his home.
PERSONA_FS_REMOVE = ("/home/phil", "/usr/bin/python3.11", "/usr/bin/pydoc3.11")
# The persona's users own their homes (honeyfs/etc/passwd: cloud-init's ubuntu
# 1000, the operator's deploy 1001); fsctl made them root's. 22.04's
# login.defs HOME_MODE is 0750.
PERSONA_HOMES = (
    ("/home/ubuntu", 1000, 1000),
    ("/home/deploy", 1001, 1001),
)
# The account files were last written when the operator added deploy (its
# shadow change day, 19790 = 2024-03-08); the pickle stamped them with one
# instant every v3.1.1 install shares (May  4 20:16, review m-6).
PERSONA_ACCOUNTS_TIME = 1709906557
PERSONA_FS_STAMPS = tuple((f"/etc/{name}", PERSONA_ACCOUNTS_TIME)
                          for name in ("passwd", "group", "shadow", "gshadow"))
# Modes the owning tool would have set; fsctl gives a node its parent's mode,
# so the bait key was -rwxr-xr-x inside a world-readable .ssh.
PERSONA_FS_MODES = (
    ("/root/.bash_history", 0o100600),
    ("/home/ubuntu/.bash_history", 0o100600),
    ("/home/ubuntu/.aws/credentials", 0o100600),
    ("/home/deploy/.ssh", 0o40700),
    ("/home/deploy/.ssh/id_rsa", 0o100600),
)


def _fs_dir(tree: list, path: str) -> list | None:
    """The directory node at an absolute path, following no symlinks."""
    node = tree
    for part in [p for p in path.split("/") if p]:
        if node[_FS_TYPE] != _FS_DIR:
            return None
        node = next((c for c in node[_FS_CONTENTS] if c[_FS_NAME] == part), None)
        if node is None:
            return None
    return node if node[_FS_TYPE] == _FS_DIR else None


def _fs_put(tree: list, path: str, node: list) -> bool:
    """Link node at path, replacing any entry of the same name. False when the
    parent directory is missing (the node is then skipped, never invented)."""
    parent_path, _, name = path.rpartition("/")
    parent = _fs_dir(tree, parent_path or "/")
    if parent is None:
        return False
    node[_FS_NAME] = name
    parent[_FS_CONTENTS][:] = [c for c in parent[_FS_CONTENTS] if c[_FS_NAME] != name] + [node]
    return True


def _fs_entry(tree: list, path: str) -> list | None:
    """The node at an absolute path itself (a final symlink is not followed;
    nor is any on the way, the persona's paths cross none)."""
    parent_path, _, name = path.rpartition("/")
    parent = _fs_dir(tree, parent_path or "/")
    if parent is None:
        return None
    return next((c for c in parent[_FS_CONTENTS] if c[_FS_NAME] == name), None)


def persona_fs_edit(tree: list, honeyfs_sizes: dict[str, int | bytes] | None = None,
                    now: float = PERSONA_IMAGE_TIME) -> list[str]:
    """Apply the persona's node changes to an unpickled fs tree in place.

    honeyfs_sizes maps each file the persona serves from honeyfs (bait and
    persona overlays, "/etc/hostname" -> bytes) to its size: Cowrie reads such
    a file's contents from disk but lists the node's own size, so `ls -l
    /etc/hostname` said 13 bytes beside 19 bytes of content, and fsctl's
    bait nodes all said 4096. Each node takes its file's size; a file with no
    node gets one (Cowrie serves honeyfs only onto an existing node, so the
    persona's /home/ubuntu/.bash_history was never visible), stamped `now`.
    These are data files: a node fsctl created with its parent's x bits
    loses them (every bait file was -rwxr-xr-x). A value given as bytes is
    the file's content and is also embedded in the node (fsctl `load`'s
    effect), so the pickle itself serves the persona's /etc/passwd, group
    and shadow: its stock copies carry phil and Cowrie's root hash, masked
    only while contents_path points at honeyfs (review m-4).

    Idempotent: every change replaces a node by name or sets attributes, so a
    second `plant-bait` run leaves the tree as the first left it. Returns the
    paths it could not place (a missing parent directory).
    """
    skipped = []
    for path, data in sorted((honeyfs_sizes or {}).items()):
        size = len(data) if isinstance(data, bytes) else data
        node = _fs_entry(tree, path)
        if node is None:
            parent = _fs_dir(tree, path.rpartition("/")[0] or "/")
            if parent is None:
                skipped.append(path)
                continue
            node = [None, _FS_FILE, parent[_FS_UID], parent[_FS_GID], size, 0o100644, now,
                    [], None, None]
            _fs_put(tree, path, node)
        elif node[_FS_TYPE] == _FS_FILE:
            node[_FS_SIZE] = size
        if node[_FS_TYPE] == _FS_FILE:
            node[_FS_MODE] &= ~0o111
            if isinstance(data, bytes):
                node[_FS_CONTENTS] = data
    for path, size in PERSONA_FS_SIZES:
        node = _fs_entry(tree, path)
        if node is None or node[_FS_TYPE] != _FS_FILE:
            skipped.append(path)
            continue
        node[_FS_SIZE] = size
    for path, new_name in PERSONA_FS_RENAMES:
        parent_path, _, name = path.rpartition("/")
        parent = _fs_dir(tree, parent_path or "/")
        if parent is None or any(c[_FS_NAME] == new_name for c in parent[_FS_CONTENTS]):
            continue
        for child in parent[_FS_CONTENTS]:
            if child[_FS_NAME] == name:
                child[_FS_NAME] = new_name
    for path in PERSONA_FS_REMOVE:
        parent_path, _, name = path.rpartition("/")
        parent = _fs_dir(tree, parent_path or "/")
        if parent is not None:
            parent[_FS_CONTENTS][:] = [c for c in parent[_FS_CONTENTS] if c[_FS_NAME] != name]
    for path, uid, gid in PERSONA_HOMES:
        home = _fs_dir(tree, path)
        if home is None:
            skipped.append(path)
            continue
        home[_FS_MODE] = 0o40750
        stack = [home]
        while stack:
            node = stack.pop()
            node[_FS_UID], node[_FS_GID] = uid, gid
            if node[_FS_TYPE] == _FS_DIR:
                stack.extend(node[_FS_CONTENTS])
    for path, ctime in PERSONA_FS_STAMPS:
        node = _fs_entry(tree, path)
        if node is not None and node[_FS_TYPE] == _FS_FILE:
            node[_FS_CTIME] = ctime
    for path, mode in PERSONA_FS_MODES:
        node = _fs_entry(tree, path)
        if node is not None and node[_FS_TYPE] in (_FS_FILE, _FS_DIR):
            node[_FS_MODE] = mode
    for path, size, mode, gid, ctime in PERSONA_FS_FILES:
        node = [None, _FS_FILE, 0, gid, size, mode, ctime, [], None, None]
        if not _fs_put(tree, path, node):
            skipped.append(path)
    for path, target in PERSONA_FS_LINKS:
        node = [None, _FS_LINK, 0, 0, len(target), 0o120777, PERSONA_IMAGE_TIME, [], target, None]
        if not _fs_put(tree, path, node):
            skipped.append(path)
    return skipped


def honeyfs_files(honeyfs: Path) -> dict[str, bytes]:
    """Virtual path -> content of every regular file under honeyfs, except
    /proc: a real /proc lists every file as 0 bytes, and so does the pickle
    (and Cowrie generates /proc/uptime)."""
    files = {}
    if honeyfs.is_dir():
        for f in honeyfs.rglob("*"):
            rel = f.relative_to(honeyfs).as_posix()
            if f.is_file() and not f.is_symlink() and rel.split("/")[0] != "proc":
                files["/" + rel] = f.read_bytes()
    return files


class FsPickleRefused(ValueError):
    """A file named fs.pickle that is not a plain Cowrie filesystem tree."""


# Cowrie's node layout (cowrie/shell/fs.py, v3.1.1): exactly ten fields,
# A_NAME..A_REALFILE, and node types T_LINK..T_FIFO (0..6). The pinned
# pickle, inspected: 28,966 nodes, every one of length 10; name str; type,
# uid, gid, size, mode int; ctime int (one float); contents a list of child
# nodes for a directory and otherwise an empty list or, for a file, the
# bytes fsctl `load` embedded; target a str for a link and None otherwise;
# realfile None (Cowrie sets it in memory, a str when it is kept). What
# persona_fs_edit writes is the same shape with float times. Exact types: a
# bool or a subclass is not a filesystem field.
_FS_NODE_FIELDS = 10
_FS_NODE_TYPES = range(7)


def _fs_tree_problem(tree: object) -> str | None:
    """Why `tree` is not a Cowrie filesystem tree, or None when it is.

    A pickle of allowed types can still be shaped wrong (["/",1,0,0,0,0,0,
    [["etc"]],None,None] passed the type check, and persona_fs_edit then
    died with an IndexError traceback, aborting a root installer run instead
    of refusing; Task 8 review I-2). Every node is checked against the
    layout above before anything indexes into it, and a node reachable twice
    (a loop, or one node shared by two directories, which the pickle memo
    can express) is refused too: the edits walk the tree and would never end
    or would edit two places at once."""
    if type(tree) is not list:
        return "the top level is not a node"
    seen: set[int] = set()
    stack: list[tuple[object, str]] = [(tree, "/")]
    while stack:
        node, where = stack.pop()
        if type(node) is not list or len(node) != _FS_NODE_FIELDS:
            return f"{where}: a node is a list of {_FS_NODE_FIELDS} fields"
        if id(node) in seen:
            return f"{where}: a node is reachable twice"
        seen.add(id(node))
        name, kind, uid, gid, size, mode, ctime, contents, target, realfile = node
        if type(name) is not str:
            return f"{where}: the name is not a str"
        if type(kind) is not int or kind not in _FS_NODE_TYPES:
            return f"{where}: the type is not one of Cowrie's node types"
        if any(type(v) is not int for v in (uid, gid, size, mode)):
            return f"{where}: uid, gid, size and mode must be int"
        if type(ctime) not in (int, float):
            return f"{where}: the ctime is not a number"
        if not (type(target) is str if kind == _FS_LINK else target is None or type(target) is str):
            return f"{where}: the link target is malformed"
        if realfile is not None and type(realfile) is not str:
            return f"{where}: the real file is not a str"
        if kind == _FS_DIR:
            if type(contents) is not list or id(contents) in seen:
                return f"{where}: a directory's contents must be its own list of nodes"
            seen.add(id(contents))
            for child in contents:
                child_name = child[_FS_NAME] if type(child) is list and child and type(child[_FS_NAME]) is str else "?"
                stack.append((child, where.rstrip("/") + "/" + ascii(child_name)[1:-1][:64]))
        elif not ((type(contents) is bytes and kind == _FS_FILE) or (type(contents) is list and not contents)):
            return f"{where}: a non-directory's contents must be empty or a file's bytes"
    if tree[_FS_TYPE] != _FS_DIR:
        return "the root is not a directory"
    return None


def load_fs_pickle(data: bytes) -> list:
    """Unpickle a Cowrie fs.pickle without letting it run anything.

    fs.pickle lives in the tree the cowrie account owns, and that account
    handles attacker input; root runs persona-fs and plant-bait over it (Task
    7 re-review N-2). pickle.load would call whatever callable the file names
    (`__reduce__` -> os.system) as root. Cowrie's tree needs no global at all,
    so find_class refuses every one (that is what GLOBAL, STACK_GLOBAL, INST,
    OBJ and EXT* resolve through; without a callable REDUCE/NEWOBJ/BUILD have
    nothing to call), persistent ids are refused, and the result must have
    Cowrie's node layout exactly (_fs_tree_problem), so the edits that follow
    can index any node without failing."""
    import io  # noqa: PLC0415
    import pickle  # noqa: PLC0415

    class _Unpickler(pickle.Unpickler):
        def find_class(self, module: str, name: str):  # noqa: ANN202
            raise FsPickleRefused(
                f"refusing a pickle that references {module}.{name}: a Cowrie fs.pickle "
                "holds only lists, str, int, float, bytes and None")

        def persistent_load(self, pid):  # noqa: ANN001, ANN202
            raise FsPickleRefused("refusing a pickle with a persistent id")

    try:
        tree = _Unpickler(io.BytesIO(data)).load()
    except FsPickleRefused:
        raise
    except Exception as exc:  # noqa: BLE001 - any parse failure is "not a tree"
        raise FsPickleRefused(f"not a Cowrie filesystem pickle ({type(exc).__name__}: {exc})") from None
    problem = _fs_tree_problem(tree)
    if problem is not None:
        raise FsPickleRefused(f"not a Cowrie filesystem tree ({problem})")
    return tree


def apply_persona_fs(pickle_path: Path, honeyfs: Path | None = None) -> bool:
    """Edit Cowrie's fs.pickle for the persona: what fsctl cannot express
    (setuid modes, symlinks, real sizes). The pickle is the pinned Cowrie
    checkout's own file, the one Cowrie itself unpickles; it is read through
    load_fs_pickle (never pickle.load: root runs this over a file the Cowrie
    account can write) and rewritten via a temporary file and an atomic
    rename. False when the pickle was refused or unreadable."""
    import pickle  # noqa: PLC0415 - only the installer's bait step needs it
    import time  # noqa: PLC0415

    try:
        tree = load_fs_pickle(pickle_path.read_bytes())
    except (OSError, FsPickleRefused) as exc:
        log(f"warning: cannot edit {pickle_path} for the persona ({exc}); "
            "persona filesystem nodes not applied (fingerprintable)")
        return False
    files = honeyfs_files(honeyfs) if honeyfs is not None else {}
    try:
        skipped = persona_fs_edit(tree, files, time.time())
    except (IndexError, KeyError, TypeError, ValueError, RecursionError) as exc:
        # load_fs_pickle validated the layout, so this is a gap in that
        # check, never an expected path: still refuse by name, not by
        # traceback, and write nothing.
        log(f"warning: cannot edit {pickle_path} for the persona (not a Cowrie filesystem tree: "
            f"{type(exc).__name__}); persona filesystem nodes not applied (fingerprintable)")
        return False
    if skipped:
        log(f"warning: persona filesystem nodes without a parent directory: {', '.join(skipped)}")
    # The directory belongs to the Cowrie account and this runs as root: a
    # fixed temp name could be a planted symlink (review m-3). mkstemp opens
    # a fresh name with O_EXCL; the result keeps the pickle's mode and owner.
    st = pickle_path.stat()
    fd, tmp_name = tempfile.mkstemp(dir=pickle_path.parent, prefix=".fs.pickle.persona-")
    try:
        with os.fdopen(fd, "wb") as f:
            pickle.dump(tree, f)
        os.chmod(tmp_name, stat.S_IMODE(st.st_mode))
        if os.geteuid() == 0:
            os.chown(tmp_name, st.st_uid, st.st_gid)
        os.replace(tmp_name, pickle_path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return True


def cowrie_fs_pickles(cowrie_home: Path) -> list[Path]:
    """Every fs.pickle an installed Cowrie may load: the cfg's [shell]
    filesystem (patch_cowrie_cfg points it at src/cowrie/data/fs.pickle; an
    older or hand-edited cfg may not), the checkout's own, and the
    var/lib/cowrie copy plant_bait_files keeps. Existing files only."""
    import configparser  # noqa: PLC0415

    found: list[Path] = []
    cfg = cowrie_home / "etc/cowrie.cfg"
    if cfg.is_file():
        # Cowrie reads its cfg with ExtendedInterpolation (`$$` is a literal `$`).
        parser = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
        try:
            parser.read_string(cfg.read_text())
            name = parser.get("shell", "filesystem", fallback="")
        except (configparser.Error, UnicodeDecodeError):
            name = ""
        if name:
            path = Path(name)
            found.append(path if path.is_absolute() else cowrie_home / path)
    found += [cowrie_home / "src/cowrie/data/fs.pickle", cowrie_home / "var/lib/cowrie/fs.pickle"]
    unique: list[Path] = []
    for path in found:
        if path.is_file() and path not in unique:
            unique.append(path)
    return unique


def cmd_persona_fs(cowrie_home: Path) -> int:
    """`shardlure.py persona-fs [COWRIE_HOME]`: apply the persona's pickle
    edits to an installed Cowrie. apply-stealth.sh (the re-apply path for an
    existing box) calls it after syncing honeyfs: without it such a box got
    the new command/type resolver, which answers from the fake PATH alone,
    over a stock pickle with no sudo/crontab/ping nodes, and kept /home/phil
    (Task 7 review I-1). Idempotent; Cowrie must be restarted to load it.

    Run by root over a tree the Cowrie account owns, it re-runs itself as
    that account from the root-owned PERSONA_REGEN_LIB copy (as
    cowrie.service does before every start): the pickles, their directories
    and honeyfs are the account's, so root would read and write through paths
    the account can redirect (Task 8 fix round, the same rule as
    deploy_time_persona)."""
    prefix = persona_tree_prefix(cowrie_home)
    if prefix:
        copy = PERSONA_REGEN_LIB / "shardlure.py"
        if not copy.is_file():
            log(f"warning: {copy} missing (run persona-regen-install); persona filesystem not applied")
            return 1
        return run([*prefix, sys.executable, str(copy), "persona-fs", str(cowrie_home)]).returncode
    pickles = cowrie_fs_pickles(cowrie_home)
    if not pickles:
        log(f"warning: no Cowrie fs.pickle under {cowrie_home}; persona filesystem not applied")
        return 1
    ok = True
    for pickle_path in pickles:
        log(f"applying persona filesystem nodes to {pickle_path}")
        ok = apply_persona_fs(pickle_path, cowrie_home / "honeyfs") and ok
    return 0 if ok else 1


# txtcmds the persona used to ship, removed from a deployed share dir on every
# deploy (the copy below only adds). bin/uname printed the static `uname -a`
# line for every option set and won over Cowrie's own uname for any path that
# resolves to /bin/uname, e.g. `/bin/./uname -s -v -n -r -m` (130 sessions in
# 30 days); Cowrie's uname reads the persona cfg and answers each option.
# apply-stealth.sh retires the same list (test_shardlure pins the two).
RETIRED_TXTCMDS = ("bin/uname",)


def deploy_txtcmds() -> None:
    """Copy persona txtcmds into Cowrie's share dir (anti-fingerprint stubs)."""
    txtcmds_src = ROOT / "install" / "persona" / "txtcmds"
    if not txtcmds_src.is_dir():
        return
    txtcmds_dst = COWRIE_HOME / "share" / "cowrie" / "txtcmds"
    txtcmds_dst.mkdir(parents=True, exist_ok=True)
    log("deploying txtcmds anti-fingerprint stubs")
    for rel in RETIRED_TXTCMDS:
        (txtcmds_dst / rel).unlink(missing_ok=True)
    for src_file in txtcmds_src.rglob("*"):
        if not src_file.is_file():
            continue
        rel = src_file.relative_to(txtcmds_src)
        dst = txtcmds_dst / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_file, dst)


def persona_tree_prefix(cowrie_home: Path) -> list[str]:
    """`runuser -u <cowrie> --` when the tree the persona steps write is not
    root's own (cowrie_owned_prefix), else []."""
    return cowrie_owned_prefix(cowrie_home, cowrie_home / "honeyfs", cowrie_home / "share/cowrie/txtcmds",
                               cowrie_home / "src/cowrie/data", cowrie_home / "var/lib/cowrie")


def deploy_time_persona(cowrie_home: Path | None = None) -> None:
    """Regenerate time-sensitive persona files against the live clock.

    The txtcmds/honeyfs files are otherwise frozen at a fixed date, which is a
    honeypot tell: Cowrie's `date` renders from the real clock, so a visitor
    comparing `date` to `uptime`/`last`/`who` would see the box stuck months in
    the past. The generator rewrites uptime/w/who/last and /proc/uptime so they
    track "now" and agree with each other. Must run AFTER deploy_txtcmds() (it
    overwrites files that step just planted).

    Root runs it only over a tree root owns (a fresh install, before
    prepare_cowrie_tree hands it over). Over a tree the Cowrie account owns
    (a re-run, apply-stealth.sh) it runs as that account, from the root-owned
    PERSONA_REGEN_LIB copy, exactly as cowrie.service runs it before every
    start (Task 8 review m-3): the generator opens paths inside that tree, and
    as root it wrote persona text through any symlink the account planted
    there. As the account it can only write what the account could already
    write. That is simpler than making every write in the generator
    descriptor-pinned and no-follow, and it is the same code path and the same
    privileges as the per-start run, so the two cannot diverge.
    """
    home = COWRIE_HOME if cowrie_home is None else cowrie_home
    prefix = persona_tree_prefix(home)
    gen = (PERSONA_REGEN_LIB if prefix else ROOT / "install" / "persona") / "gen-time-persona.py"
    if not gen.is_file():
        log(f"warning: {gen} missing; persona time files may be stale (fingerprintable)")
        return
    log("refreshing time-sensitive persona against live clock")
    proc = run([*prefix, sys.executable, str(gen), str(home)])
    if proc.returncode != 0:
        # Non-fatal: a stale-but-planted persona still works, just fingerprintable.
        log(f"warning: time-persona generator exited {proc.returncode}; "
            "persona time files may be stale (fingerprintable)")


# Per-start persona regeneration (Task 8). gen-time-persona anchors the motd's
# "Last login" and the txtcmd/proc time files to the clock it runs at, and
# Cowrie's patched last/w anchor the same persona history to its own process
# start: run only at deploy, every later restart (a crash, a reboot, a
# Restart=always) left the motd naming a login that last no longer shows
# (Task 5 residual). cowrie.service therefore re-runs both generators before
# every start, gen-time-persona first and persona-fs second (it sizes the
# motd node from the rewritten file).
#
# They run as the Cowrie account, never root: the unit's User= applies (no
# `+`/`!` prefix) and everything they write is in the tree that account
# owns (honeyfs, share/cowrie/txtcmds, the fs.pickle files and their
# directories). They run from a root-owned copy outside that tree,
# PERSONA_REGEN_LIB (/usr/local/lib/shardlure/persona: root 0755, files
# 0644), because the checkout the installer ran from (often /root/...) is not
# readable by the account. The copy lives outside the Cowrie tree on purpose
# (Task 8 review I-1): it used to sit in COWRIE_HOME/shardlure-persona, owned
# by the account, so on every re-run root's copyfile/cp wrote through any
# symlink the account had planted there (shardlure.py ->
# /usr/local/bin/shardlure). Now root writes only into a directory nobody
# else can change (installer_safety.install_root_files), and the account
# cannot tamper with the code it runs before every start either.
# SHARDLURE_PERSONA_LIB overrides the location (rehearsals under /srv); both
# installers and apply-stealth.sh read the same variable and default.
# The prefix `-` keeps a failed regeneration from keeping Cowrie down: a
# honeypot that does not answer loses every capture, while a stale persona
# is the residual tell the box ran with before this. `timeout` keeps both
# steps inside systemd's 90 s start budget, so a hung step cannot turn into
# a start-timeout restart loop. A missing copy (a box whose persona was never
# deployed, e.g. install.sh without apply-stealth.sh) is a silent no-op.
PERSONA_REGEN_LIB = Path(os.environ.get("SHARDLURE_PERSONA_LIB") or "/usr/local/lib/shardlure/persona")
# Where the copy lived before; removed (never written) on every deploy.
LEGACY_PERSONA_REGEN_DIR = "shardlure-persona"
PERSONA_REGEN_TIMEOUT = 30
PERSONA_REGEN_FILES = {
    "gen-time-persona.py": ROOT / "install/persona/gen-time-persona.py",
    "cowrie-stealth.cfg": ROOT / "install/persona/cowrie-stealth.cfg",
    "shardlure.py": ROOT / "scripts/shardlure.py",
    "installer_safety.py": ROOT / "scripts/installer_safety.py",
    "ssh_transition.py": ROOT / "scripts/ssh_transition.py",
}
# The /bin/sh program both installers put in front of each step ($$ is
# systemd's escape for a literal $). The paths are positional arguments, never
# shell syntax; install.sh renders the same text (a test pins the two).
PERSONA_REGEN_SH = (
    'test -f "$$2" || exit 0; '
    f'timeout {PERSONA_REGEN_TIMEOUT} "$$@" && exit 0; rc=$$?; '
    'echo "persona regeneration: $$2 exited $$rc; Cowrie starts with its existing persona files" >&2; '
    "exit $$rc"
)


def persona_regen_prestart(cowrie_home: Path) -> str:
    """cowrie.service's ExecStartPre= lines for the per-start regeneration."""
    py = cowrie_home / "venv/bin/python"
    lib = PERSONA_REGEN_LIB
    steps = (
        [py, lib / "gen-time-persona.py", cowrie_home],
        [py, lib / "shardlure.py", "persona-fs", cowrie_home],
    )
    return "".join(
        f"ExecStartPre=-/bin/sh -c '{PERSONA_REGEN_SH}' persona-regen "
        # Paths are quoted and escaped; the literal subcommand is not.
        + " ".join(systemd_exec_arg(str(arg)) if isinstance(arg, Path) else arg for arg in step)
        + "\n"
        for step in steps
    )


def remove_legacy_persona_regen(cowrie_home: Path) -> None:
    """Delete the pre-fix copy in the Cowrie tree, following nothing: a
    symlink there is unlinked itself, a directory is removed by rmtree's
    descriptor-based walk (it never descends through a symlink)."""
    legacy = cowrie_home / LEGACY_PERSONA_REGEN_DIR
    try:
        info = os.lstat(legacy)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode) and shutil.rmtree.avoids_symlink_attacks:
        shutil.rmtree(legacy)
    elif not stat.S_ISDIR(info.st_mode):
        legacy.unlink()


def deploy_persona_regen(cowrie_home: Path | None = None) -> None:
    """Install the per-start regeneration scripts root-owned outside the
    Cowrie tree (see PERSONA_REGEN_LIB) and drop the old in-tree copy."""
    files = {}
    for name, src in PERSONA_REGEN_FILES.items():
        if not src.is_file():
            die(f"persona regeneration source missing: {src}")
        files[name] = src.read_bytes()
    try:
        installer_safety.install_root_files(PERSONA_REGEN_LIB, files)
    except (OSError, installer_safety.SafetyError) as exc:
        die(f"cannot install the persona regeneration scripts into {PERSONA_REGEN_LIB}: {exc}")
    remove_legacy_persona_regen(COWRIE_HOME if cowrie_home is None else cowrie_home)


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
            # Bounded downloads (== capture.max_bytes). Cowrie reads it only
            # from [honeypot]; without it an attacker can fill the disk.
            ("download_limit_size", "52428800"),
            # The persona's 42d 3h17m (== cowrie-stealth.cfg). Unset, v3.1.1
            # picks a random 1-90 day boot per process, and /proc/uptime,
            # uptime, w and last stop agreeing with the persona.
            ("boot_offset", "3640620"),
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
            # (== cowrie-stealth.cfg, which records the measurement.) v3.1.1's
            # own default, pinned so a change is deliberate: a higher cap
            # makes big scripts stall every session for up to the 10 s parse
            # timeout and then answer a syntax error instead of running.
            ("max_input_size", "16384"),
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

    # The persona's last history spans 4d23h before the Cowrie start
    # (last-persona.py); a smaller kept boot_offset puts sessions before boot.
    cur = ""
    for line in out:
        sec = section_of(line)
        if sec is not None:
            cur = sec
            continue
        key, _, val = line.partition("=")
        if cur == "honeypot" and key.strip().lower() == "boot_offset":
            try:
                kept = int(val.strip())
            except ValueError:
                kept = -1
            if kept < 604800:
                log(f"warning: [honeypot] boot_offset = {val.strip()} is under 7 days; the"
                    " persona's login history (last/w) would predate the boot")

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
{persona_regen_prestart(COWRIE_HOME)}ExecStart={cowrie_exec}
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
    require_cowrie_python()
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
    elif cmd == "persona-fs":
        # An option-shaped argument is a usage error, not a Cowrie home
        # (`persona-fs --bogus` used to look for a pickle under ./--bogus;
        # Task 7 re-review N-1): unknown flags are fatal here.
        if len(sys.argv) > 3 or (len(sys.argv) == 3 and sys.argv[2].startswith("-")):
            die("usage: python3 scripts/shardlure.py persona-fs [COWRIE_HOME]")
        sys.exit(cmd_persona_fs(Path(sys.argv[2]) if len(sys.argv) == 3 else COWRIE_HOME))
    elif cmd == "time-persona":
        # apply-stealth.sh's entry to deploy_time_persona: the same
        # run-as-the-tree's-owner rule as the installer.
        if len(sys.argv) > 3 or (len(sys.argv) == 3 and sys.argv[2].startswith("-")):
            die("usage: sudo python3 scripts/shardlure.py time-persona [COWRIE_HOME]")
        deploy_time_persona(Path(sys.argv[2]) if len(sys.argv) == 3 else COWRIE_HOME)
    elif cmd == "persona-regen-install":
        # apply-stealth.sh's way to (re)install PERSONA_REGEN_LIB with the
        # same checks as the installer; COWRIE_HOME locates the legacy copy.
        if len(sys.argv) > 3 or (len(sys.argv) == 3 and sys.argv[2].startswith("-")):
            die("usage: sudo python3 scripts/shardlure.py persona-regen-install [COWRIE_HOME]")
        deploy_persona_regen(Path(sys.argv[2]) if len(sys.argv) == 3 else COWRIE_HOME)
        log(f"persona regeneration scripts installed in {PERSONA_REGEN_LIB}")
    elif cmd in ("plant-bait", "bait"):
        need_root()
        plant_bait_files()
        # The bait copy runs as root; hand the tree back to the Cowrie account
        # (as install does), or the per-start regeneration, which runs as that
        # account, can no longer rewrite the honeyfs files root just wrote.
        installer_safety.prepare_cowrie_tree(DATA_DIR, COWRIE_USER)
        run(["systemctl", "restart", "cowrie.service"]).check_returncode()
        log("bait planted — test: ssh root@<public-ip> then cat /opt/app/.env")
    elif cmd in ("uninstall", "remove"):
        cmd_uninstall()
    else:
        die("usage: sudo python3 scripts/shardlure.py "
            "{run|finish|start|stop|status|plant-bait|persona-fs [COWRIE_HOME]|"
            "persona-regen-install [COWRIE_HOME]|time-persona [COWRIE_HOME]|uninstall [--purge]}")


if __name__ == "__main__":
    main()
