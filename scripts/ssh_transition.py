"""Bounded, reversible SSH configuration transitions; no import-time effects."""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import pwd
import re
import shlex
import socket
import stat
from pathlib import Path

if __package__:
    from . import installer_safety as safe
else:
    import installer_safety as safe


def operator_context() -> dict:
    user = os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
    account = pwd.getpwnam(user)
    if account.pw_name != user or re.fullmatch(r"[A-Za-z0-9_.@-]+", user) is None:
        raise safe.SafetyError("cannot identify the administrative SSH user")
    # The source address decides which `Match Address` blocks `sshd -T -C`
    # evaluates when proving the operator keeps key-only access. It used to
    # fall back silently to 127.0.0.1 when SSH_CONNECTION was missing (the
    # normal case under sudo's env_reset), validating the wrong policy. Take it
    # from our own environment, else the parent login shell sudo was started
    # from, else an explicit console override; otherwise refuse.
    fields = os.environ.get("SSH_CONNECTION", "").split()
    if len(fields) != 4:
        fields = (_ancestor_ssh_connection() or "").split()
    if len(fields) == 4:
        peer, local = fields[0], fields[2]
    elif os.environ.get("SHARDLURE_ADMIN_SSH_FROM", "").strip():
        peer = os.environ["SHARDLURE_ADMIN_SSH_FROM"].strip()
        local = "::" if ":" in peer else "0.0.0.0"
    else:
        raise safe.SafetyError(
            "cannot determine the address you will administer SSH from; run the installer "
            "from your SSH session, or set SHARDLURE_ADMIN_SSH_FROM=<your client IP>")
    try:
        ipaddress.ip_address(peer)
        ipaddress.ip_address(local)
    except ValueError as exc:
        raise safe.SafetyError("invalid administrative SSH address") from exc
    return {"user": user, "addr": peer, "host": peer, "laddr": local}


def _ancestor_ssh_connection(max_depth: int = 32):
    """SSH_CONNECTION of the nearest ancestor process that has one.

    sudo resets the environment it passes to the child, but the operator's
    login shell (its ancestor) keeps it; root can read that process's environ.
    """
    pid = os.getppid()
    for _ in range(max_depth):
        if pid <= 1:
            return None
        try:
            environ = Path(f"/proc/{pid}/environ").read_bytes()
        except OSError:
            environ = b""
        for item in environ.split(b"\0"):
            if item.startswith(b"SSH_CONNECTION="):
                return item.split(b"=", 1)[1].decode("ascii", "replace")
        try:
            stat_text = Path(f"/proc/{pid}/stat").read_text()
            pid = int(stat_text.rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            return None
    return None


def ports(text: str) -> set[int]:
    return {int(p) for p in re.findall(r"(?im)^port\s+([0-9]+)\s*$", text)}


def context_argument(context: dict, port: int) -> str:
    return ",".join(f"{k}={context[k]}" for k in ("user", "addr", "host", "laddr")) + f",lport={port}"


def endpoint(value: str) -> tuple[str, int]:
    if value.isdigit():
        return "::", int(value)
    if value.startswith("["):
        host, separator, port = value[1:].partition("]:")
    else:
        host, separator, port = value.rpartition(":")
    if not separator or not port.isdigit():
        raise safe.SafetyError("unsupported SSH socket endpoint")
    address = ipaddress.ip_address(host)
    return str(address), int(port)


def socket_text(bindings: set[tuple[str, int]]) -> bytes:
    lines = ["# Managed by ShardLure", "[Socket]", "BindIPv6Only=ipv6-only", "ListenStream="]
    for host, port in sorted(bindings):
        value = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        lines.append('ListenStream=' + value.replace("%", "%%"))
    return ("\n".join(lines) + "\n").encode()


def managed_main(text: str, dropin: Path) -> str:
    """Retain original policy while ensuring our global drop-in is read."""
    covered = False
    for line in text.splitlines():
        words = shlex.split(line, comments=True)
        if not words:
            continue
        if words[0].lower() == "match":
            break
        if words[0].lower() == "include":
            for pattern in words[1:]:
                absolute = Path(pattern) if Path(pattern).is_absolute() else Path("/etc/ssh") / pattern
                if dropin.match(str(absolute)):
                    covered = True
    text = re.sub(r"(?im)^(\s*Port\s+.*)$", r"#\1", text)
    if not covered:
        path = str(dropin).replace("\\", "\\\\").replace('"', '\\"')
        text = f'Include "{path}"\n' + text
    return text


def append_public_key(account, public_key: str) -> Path:
    key = public_key.strip()
    if not key or len(key) > 16384 or any(ord(c) < 32 or ord(c) == 127 for c in key):
        raise safe.SafetyError("one bounded public-key line is required")
    home = safe.checked_absolute(Path(account.pw_dir))
    with safe.directory(home, owners={account.pw_uid}) as parent:
        created = False
        try:
            os.mkdir(".ssh", 0o700, dir_fd=parent)
            created = True
        except FileExistsError:
            pass
        folder = os.open(".ssh", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            info = os.fstat(folder)
            if not created and info.st_uid != account.pw_uid:
                raise safe.SafetyError("existing SSH directory has a different owner; manual key setup required")
            if created:
                os.fchown(folder, account.pw_uid, account.pw_gid)
            os.fchmod(folder, 0o700)
            flags = os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            new_file = False
            try:
                fd = os.open("authorized_keys", flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=folder)
                new_file = True
            except FileExistsError:
                fd = os.open("authorized_keys", flags, dir_fd=folder)
            with os.fdopen(fd, "r+b") as stream:
                before = os.fstat(stream.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 1 << 20 or
                        (not new_file and before.st_uid != account.pw_uid)):
                    raise safe.SafetyError("unsafe authorized_keys file; manual key setup required")
                existing = stream.read((1 << 20) + 1)
                if len(existing) > 1 << 20:
                    raise safe.SafetyError("authorized_keys exceeds the safe update limit")
                if key.encode() not in existing.splitlines():
                    suffix = (b"\n" if existing and not existing.endswith(b"\n") else b"") + key.encode() + b"\n"
                    stream.write(suffix)  # O_APPEND preserves concurrent complete keys.
                    stream.flush()
                if new_file:
                    os.fchown(stream.fileno(), account.pw_uid, account.pw_gid)
                os.fchmod(stream.fileno(), 0o600)
                os.fsync(stream.fileno())
                if not safe.same_object(before, os.stat("authorized_keys", dir_fd=folder, follow_symlinks=False)):
                    raise safe.SafetyError("authorized_keys replaced during update")
            os.fsync(folder)
            if not safe.same_object(info, os.stat(".ssh", dir_fd=parent, follow_symlinks=False)):
                raise safe.SafetyError("SSH directory replaced during update")
            safe.verify_directory(home, parent, owners={account.pw_uid})
            os.fsync(parent)
        finally:
            os.close(folder)
    return home / ".ssh/authorized_keys"


class SSHTransition:
    def __init__(self, config: Path, dropin: Path, socket_dropin: Path, *, runner,
                 socket_activated: bool, reloader, install_id: str = ""):
        self.paths = {"config": config, "dropin": dropin, "socket": socket_dropin}
        self.run = runner
        self.socket_activated = socket_activated
        self.reload = reloader
        self.context = operator_context()
        self.install_id = install_id
        self.receipt = config.with_name("sshd_config.shardlure-state.json")
        self.backup = config.with_name("sshd_config.shardlure-bak")
        self.before = self.capture()
        effective = self.effective(22)
        self.before_ports = ports(effective)
        if not self.before_ports:
            raise safe.SafetyError("cannot determine effective SSH ports")
        self.bindings = self.socket_bindings() if socket_activated else set()
        if self.bindings:
            self.before_ports = {p for _, p in self.bindings}

    def effective(self, port: int) -> str:
        args = ["sshd", "-T", "-f", str(self.paths["config"]), "-C", context_argument(self.context, port)]
        result = self.run(args, capture_output=True, text=True)
        result.check_returncode()
        text = result.stdout or ""
        if re.search(r"(?im)^usedns\s+yes$", text) and self.context["host"] == self.context["addr"]:
            try:
                name = socket.gethostbyaddr(self.context["addr"])[0]
                answers = {ipaddress.ip_address(a[4][0]) for a in socket.getaddrinfo(name, None)}
                if ipaddress.ip_address(self.context["addr"]) in answers:
                    self.context["host"] = name
                    result = self.run(args[:-1] + [context_argument(self.context, port)], capture_output=True, text=True)
                    result.check_returncode()
                    text = result.stdout or ""
            except OSError:
                pass  # sshd likewise falls back to the numeric peer on failed DNS.
        return text

    def socket_bindings(self) -> set[tuple[str, int]]:
        result = self.run(["systemctl", "show", "ssh.socket", "--property=Listen", "--value"], capture_output=True, text=True)
        result.check_returncode()
        values = re.findall(r"(\S+)\s+\(Stream\)", result.stdout or "")
        if not values:
            raise safe.SafetyError("cannot determine current SSH socket listeners")
        bindings = {endpoint(value) for value in values}
        mode = self.run(["systemctl", "show", "ssh.socket", "--property=BindIPv6Only", "--value"], capture_output=True, text=True)
        mode.check_returncode()
        dual = (mode.stdout or "").strip() == "both"
        if (mode.stdout or "").strip() in ("", "default"):
            dual = Path("/proc/sys/net/ipv6/bindv6only").read_text().strip() == "0"
        # Do not turn the existing IPv4 side of an inherited dual-stack socket
        # off merely by making the new socket configuration deterministic.
        if dual:
            bindings |= {("0.0.0.0", port) for host, port in bindings if host == "::"}
        return bindings

    def capture(self) -> dict:
        out = {}
        for role, path in self.paths.items():
            try:
                raw = safe.read_regular(path, 1 << 20)
            except FileNotFoundError:
                out[role] = None
                continue
            info = path.lstat()
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise safe.SafetyError("SSH configuration has untrusted ownership or permissions")
            out[role] = {"bytes": base64.b64encode(raw).decode(), "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}
        if out["config"] is None:
            raise safe.SafetyError("SSH main configuration is missing")
        return out

    def write(self, role: str, raw: bytes | None, saved: dict | None = None) -> None:
        path = self.paths[role]
        with safe.directory(path.parent, create=True) as parent:
            try:
                previous = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                previous = None
            if previous is not None and (not stat.S_ISREG(previous.st_mode) or previous.st_nlink != 1 or previous.st_uid != os.geteuid()):
                raise safe.SafetyError("SSH path identity changed")
            if raw is None:
                if previous is not None:
                    os.unlink(path.name, dir_fd=parent)
                    os.fsync(parent)
                return
        mode = saved["mode"] if saved else (stat.S_IMODE(previous.st_mode) if previous else 0o600)
        safe.atomic_create(path, raw, mode, replace=previous,
                           owner=(saved["uid"], saved["gid"]) if saved else None)

    def restore_files(self, snapshot: dict) -> None:
        for role, saved in snapshot.items():
            raw = base64.b64decode(saved["bytes"], validate=True) if saved else None
            self.write(role, raw, saved)

    def remember_original(self) -> None:
        if self.receipt.exists() or self.receipt.is_symlink():
            self.original()
            return
        original = {"format": 1, "installation": self.install_id, "config": str(self.paths["config"]),
                    "files": self.before, "ports": sorted(self.before_ports),
                    "bindings": sorted(self.bindings), "socket_activated": self.socket_activated,
                    "operator": self.context}
        safe.atomic_create(self.receipt, json.dumps(original, separators=(",", ":")).encode())
        if not self.backup.exists() and not self.backup.is_symlink():
            safe.atomic_create(self.backup, base64.b64decode(self.before["config"]["bytes"]))

    def original(self) -> dict:
        original = json.loads(safe.read_regular(self.receipt, 8 << 20))
        info = self.receipt.lstat()
        if (info.st_uid != os.geteuid() or info.st_mode & 0o077 or original.get("format") != 1 or
                original.get("installation") != self.install_id or original.get("config") != str(self.paths["config"]) or
                set(original.get("files", {})) != set(self.paths) or not original.get("ports")):
            raise safe.SafetyError("SSH recovery record does not belong to this installation")
        for port in original["ports"]:
            if not isinstance(port, int) or not 1 <= port <= 65535:
                raise safe.SafetyError("invalid saved listener state")
        return original

    def validate(self, expected_ports: set[int], *, key_only=False) -> None:
        self.run(["sshd", "-t", "-f", str(self.paths["config"])]).check_returncode()
        for port in sorted(expected_ports):
            effective = self.effective(port)
            if ports(effective) != expected_ports:
                raise safe.SafetyError("SSH includes override the requested ports")
            values = dict(line.split(None, 1) for line in effective.splitlines() if len(line.split(None, 1)) == 2)
            if key_only and (values.get("pubkeyauthentication") != "yes" or values.get("passwordauthentication") != "no" or values.get("kbdinteractiveauthentication") != "no"):
                raise safe.SafetyError("operator Match policy does not permit the required key-only login")

    def rollback(self) -> None:
        self.restore_files(self.before)
        self.run(["sshd", "-t", "-f", str(self.paths["config"])]).check_returncode()
        self.reload(self.socket_activated)

    def stage(self, port: int, *, final: bool) -> None:
        if not 1 <= port <= 65535:
            raise safe.SafetyError("invalid administrative port")
        self.remember_original()
        desired = {port} if final else self.before_ports | {port}
        try:
            main = base64.b64decode(self.before["config"]["bytes"]).decode()
            main = managed_main(main, self.paths["dropin"])
            self.write("config", main.encode(), self.before["config"])
            prior = self.before["dropin"]
            policy = re.sub(r"(?im)^\s*Port[ \t]+[^\n]*\n?", "", base64.b64decode(prior["bytes"]).decode()) if prior else ""
            if final:
                policy = "PasswordAuthentication no\nKbdInteractiveAuthentication no\nChallengeResponseAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin prohibit-password\n"
            self.write("dropin", ("# Managed by ShardLure\n" + "".join(f"Port {p}\n" for p in sorted(desired)) + policy).encode())
            if self.socket_activated:
                addresses = {host for host, _ in self.bindings}
                bindings = {(host, p) for host in addresses for p in desired}
                self.write("socket", socket_text(bindings))
            self.validate(desired, key_only=final)
            self.reload(self.socket_activated)
        except BaseException:
            self.rollback()
            raise

    def restore(self, verify, *, stop_conflicting=None, restart_conflicting=None) -> set[int]:
        original = self.original()
        desired = set(original["ports"])
        stopped = False
        try:
            if stop_conflicting:
                stopped = bool(stop_conflicting(desired))
            # Keep current access while introducing the saved listener(s).
            # Stage the original authentication policy with both listener sets;
            # verify a fresh login before retiring the current administrative port.
            temporary = self.before_ports | desired
            main = base64.b64decode(original["files"]["config"]["bytes"]).decode()
            main = managed_main(main, self.paths["dropin"])
            self.write("config", main.encode(), original["files"]["config"])
            saved_policy = original["files"]["dropin"]
            policy = re.sub(r"(?im)^\s*Port[ \t]+[^\n]*\n?", "", base64.b64decode(saved_policy["bytes"]).decode()) if saved_policy else ""
            self.write("dropin", ("# ShardLure recovery staging\n" + "".join(f"Port {p}\n" for p in sorted(temporary)) + policy).encode())
            if self.socket_activated:
                bindings = self.bindings | {tuple(b) for b in original["bindings"]}
                self.write("socket", socket_text(bindings))
            self.validate(temporary)
            self.reload(self.socket_activated)
            for port in sorted(desired):
                verify(port)
            self.restore_files(original["files"])
            # The configured port set can differ from socket activation's
            # actual listeners; syntax/operator checks still apply to each.
            self.run(["sshd", "-t", "-f", str(self.paths["config"])]).check_returncode()
            for port in sorted(desired):
                self.effective(port)
            self.reload(bool(original["socket_activated"]))
            for port in sorted(desired):
                verify(port)
            return desired
        except BaseException:
            self.rollback()
            if stopped and restart_conflicting:
                restart_conflicting()
            raise
