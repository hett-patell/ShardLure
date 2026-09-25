"""Shared, stdlib-only Linux installer filesystem primitives.

Never follow an operator-supplied symlink. Directory descriptors bind each
operation to the objects validated by that operation; names are rechecked at
publication. Importing this module performs no filesystem or system changes.
"""
from __future__ import annotations

import contextlib
import argparse
import fcntl
import hashlib
import json
import os
import pwd
import grp
import re
import shutil
import stat
import subprocess
import sys
import uuid
from pathlib import Path


class SafetyError(ValueError):
    pass


def checked_absolute(path: Path) -> Path:
    path = Path(path)
    str(path).encode("utf-8", "strict")
    if (not path.is_absolute() or ".." in path.parts or
            any(ord(c) < 32 or ord(c) == 127 for c in str(path))):
        raise SafetyError("absolute, control-character-free paths are required")
    return path


def same_object(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_dev, a.st_ino, stat.S_IFMT(a.st_mode)) == (b.st_dev, b.st_ino, stat.S_IFMT(b.st_mode))


def process_identity(pid: int) -> dict | None:
    try:
        proc = Path(f"/proc/{pid}")
        if proc.stat().st_uid != os.geteuid():
            return None
        tail = (proc / "stat").read_text().rpartition(") ")[2].split()
        return {"pid": pid, "start": tail[19], "boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
    except (OSError, IndexError):
        return None


def mount_id(fd: int) -> int:
    with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as stream:
        for line in stream.read(4096).splitlines():
            if line.startswith("mnt_id:"):
                return int(line.partition(":")[2])
    raise SafetyError("Linux mount identity unavailable")


@contextlib.contextmanager
def directory(path: Path, *, owners: set[int] | None = None, create: bool = False):
    path = checked_absolute(path)
    allowed = {0, os.geteuid()} if owners is None else {0, os.geteuid(), *owners}
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            try:
                child = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=fd)
                child = os.open(part, flags, dir_fd=fd)
                os.fsync(child)
                os.fsync(fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid not in allowed:
                raise SafetyError("unrecognized directory owner")
            if owners is None and info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
                raise SafetyError("directory is replaceable by an untrusted account")
        yield fd
    finally:
        os.close(fd)


def verify_directory(path: Path, fd: int, *, owners: set[int] | None = None) -> None:
    with directory(path, owners=owners) as current:
        if not same_object(os.fstat(fd), os.fstat(current)):
            raise SafetyError("directory identity changed")


def read_regular(path: Path, limit: int = 65536) -> bytes:
    path = checked_absolute(path)
    with directory(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
                raise SafetyError("expected a bounded, unaliased regular file")
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (len(data) > limit or not same_object(before, named) or
                    (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise SafetyError("file changed during inspection")
        verify_directory(path.parent, parent)
        return data


def atomic_create(path: Path, data: bytes, mode: int = 0o600, *, replace: os.stat_result | None = None, owner: tuple[int, int] | None = None) -> None:
    """Publish only synced bytes, without overwriting any existing pathname."""
    path = checked_absolute(path)
    with directory(path.parent) as parent:
        name = ".shardlure-write-" + uuid.uuid4().hex
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
        created = os.fstat(fd)
        published = False
        try:
            with os.fdopen(fd, "wb") as stream:
                if owner is not None:
                    os.fchown(stream.fileno(), *owner)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            verify_directory(path.parent, parent)
            if replace is None:
                os.link(name, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            else:
                current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                if not same_object(replace, current) or not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
                    raise SafetyError("refusing to replace a changed file")
                os.replace(name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
            published = True
            if replace is None:
                os.unlink(name, dir_fd=parent)
            os.fsync(parent)
            verify_directory(path.parent, parent)
        except BaseException:
            if published and replace is None:
                current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                if same_object(created, current):
                    os.unlink(path.name, dir_fd=parent)
            raise
        finally:
            try:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if same_object(created, current):
                    os.unlink(name, dir_fd=parent)
            except FileNotFoundError:
                pass


def dedicated_data_path(path: Path) -> Path:
    path = checked_absolute(path)
    broad = {Path(p) for p in ("/", "/home", "/root", "/var", "/var/lib", "/var/log", "/srv", "/opt", "/tmp", "/usr", "/usr/local", "/mnt", "/media")}
    if path in broad or path == Path.home() or path.parent == Path("/home") or len(path.parts) < 3:
        raise SafetyError("use a dedicated data directory, never a system or home directory")
    return path


class PermissionPlan:
    """Preflight a bounded tree, then mutate pinned descriptors, deepest first.

    It never reads captured bytes, follows symlinks, changes unlisted siblings,
    or hands a recursive pathname to chown/chmod. The caller must separately
    refuse active services and validate account ownership before applying it.
    """
    limit = 200000

    def __init__(self, root: Path, owners: set[int] | None = None, *, create=True):
        self.root = dedicated_data_path(root)
        self.owners = {0, os.geteuid(), *(owners or set())}
        self.stack = contextlib.ExitStack()
        self.entries: dict[str, tuple[os.stat_result, str]] = {}
        self.dirs: dict[str, os.stat_result] = {}
        self.create = create

    def __enter__(self):
        try:
            parent = self.stack.enter_context(directory(self.root.parent, create=self.create))
            if self.create:
                try:
                    os.mkdir(self.root.name, 0o700, dir_fd=parent)
                    os.fsync(parent)
                except FileExistsError:
                    pass
            self.fd = os.open(self.root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            self.stack.callback(os.close, self.fd)
            info = os.fstat(self.fd)
            if info.st_uid not in self.owners:
                raise SafetyError("unrecognized data-directory owner")
            self.dirs[""] = info
            self.mount = mount_id(self.fd)
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *args):
        self.stack.close()

    def _parts(self, rel: str) -> tuple[str, ...]:
        if rel == "":
            return ()
        parts = Path(rel).parts
        if Path(rel).is_absolute() or ".." in parts or len(parts) > 64:
            raise SafetyError("invalid or excessively nested relative path")
        return parts

    def _directory(self, parts: tuple[str, ...], *, create=False, register=False) -> int:
        fd = os.dup(self.fd)
        try:
            for index, part in enumerate(parts):
                key = str(Path(*parts[:index+1]))
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(part, 0o700, dir_fd=fd)
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = child
                info = os.fstat(fd)
                if mount_id(fd) != self.mount:
                    raise SafetyError("nested mounts require separate ownership review")
                if info.st_uid not in self.owners:
                    raise SafetyError("unrecognized directory owner in service data")
                previous = self.dirs.get(key)
                if previous is not None and not same_object(previous, info):
                    raise SafetyError("directory replaced after preflight")
                if previous is None:
                    if not register:
                        raise SafetyError("directory was not preflighted")
                    self.dirs[key] = info
            return fd
        except BaseException:
            os.close(fd)
            raise

    def ensure_directory(self, rel: str) -> None:
        verify_directory(self.root, self.fd, owners=self.owners)
        fd = self._directory(self._parts(rel), create=True, register=True)
        os.close(fd)
        verify_directory(self.root, self.fd, owners=self.owners)

    def _probe(self, rel: str, *, register=False) -> int:
        parts = self._parts(rel)
        if not parts:
            return os.dup(self.fd)
        parent = self._directory(parts[:-1], register=register)
        try:
            return os.open(parts[-1], os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        finally:
            os.close(parent)

    def collect(self, rel: str, role: str, *, recursive=False, preserve_symlinks=False, exclude=()) -> None:
        if len(self.entries) >= self.limit:
            raise SafetyError("permission preflight entry limit exceeded")
        probe = self._probe(rel, register=True)
        try:
            info = os.fstat(probe)
            if mount_id(probe) != self.mount:
                raise SafetyError("nested mounts require separate ownership review")
            if stat.S_ISLNK(info.st_mode) and preserve_symlinks:
                return  # Keep code/venv links literally; never follow or chmod.
            if not stat.S_ISDIR(info.st_mode) and not stat.S_ISREG(info.st_mode):
                raise SafetyError("symlink or special file in service data")
            if info.st_uid not in self.owners or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
                raise SafetyError("foreign-owned or hard-linked service data")
            self.entries[rel] = (info, role)
            if stat.S_ISDIR(info.st_mode):
                self.dirs[rel] = info
                if recursive:
                    fd = self._directory(self._parts(rel), register=True)
                    try:
                        with os.scandir(fd) as children:
                            for child in children:
                                name = str(Path(rel) / child.name)
                                if name not in exclude:
                                    self.collect(name, role, recursive=True, preserve_symlinks=preserve_symlinks, exclude=exclude)
                    finally:
                        os.close(fd)
        finally:
            os.close(probe)

    def apply(self, policy) -> None:
        for rel in sorted(self.entries, key=lambda p: len(self._parts(p)), reverse=True):
            original, role = self.entries[rel]
            verify_directory(self.root, self.fd, owners=self.owners)
            probe = self._probe(rel)
            fd = None
            try:
                current = os.fstat(probe)
                if (not same_object(original, current) or current.st_uid != original.st_uid or
                        current.st_gid != original.st_gid or
                        (stat.S_ISREG(current.st_mode) and current.st_nlink != 1)):
                    raise SafetyError("service entry changed after preflight")
                # Reopen only this process's pinned O_PATH descriptor, never the
                # original pathname. FIFOs/devices were rejected above.
                fd = os.open(f"/proc/self/fd/{probe}", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                if not same_object(current, os.fstat(fd)):
                    raise SafetyError("descriptor identity changed")
                uid, gid, mode = policy(role, original)
                self.owners.add(uid)
                os.fchown(fd, uid, gid)
                os.fchmod(fd, mode)
                os.fsync(fd)
                check = self._probe(rel)
                try:
                    after = os.fstat(check)
                    if not same_object(original, after) or (stat.S_ISREG(after.st_mode) and after.st_nlink != 1):
                        raise SafetyError("service entry replaced during permission update")
                finally:
                    os.close(check)
            finally:
                if fd is not None:
                    os.close(fd)
                os.close(probe)
        verify_directory(self.root, self.fd, owners=self.owners)


def plan_service_permissions(plan: PermissionPlan, *, cowrie: bool) -> None:
    plan.collect("", "data")
    for rel in ("evidence", "artifacts", "logs", "captures", "payloads"):
        plan.ensure_directory(rel)
        plan.collect(rel, "private", recursive=True)
    for rel in ("shardlure.db", "shardlure.db-wal", "shardlure.db-shm", "shardlure.yaml"):
        try:
            plan.collect(rel, "config" if rel.endswith(".yaml") else "private")
        except FileNotFoundError:
            pass
    if cowrie:
        for rel in ("cowrie", "cowrie/var", "cowrie/var/lib", "cowrie/var/lib/cowrie", "cowrie/var/log"):
            plan.ensure_directory(rel)
            plan.collect(rel, "cowrie-parent")
        for rel in ("cowrie/var/log/cowrie", "cowrie/var/lib/cowrie/downloads", "cowrie/var/lib/cowrie/tty"):
            plan.ensure_directory(rel)
            plan.collect(rel, "cowrie-runtime", recursive=True)
            if not rel.endswith("/log/cowrie"):
                plan.collect(rel, "retention")


def service_policy(service, cowrie=None):
    def policy(role, info):
        is_dir = stat.S_ISDIR(info.st_mode)
        if role == "data":
            return service.pw_uid, cowrie.pw_gid if cowrie else service.pw_gid, 0o710
        if role == "private":
            return service.pw_uid, service.pw_gid, 0o700 if is_dir else 0o600
        if role == "config":
            return os.geteuid(), service.pw_gid, 0o640
        if cowrie is None:
            raise SafetyError("Cowrie policy requested without its account")
        if role == "cowrie-parent":
            return info.st_uid, cowrie.pw_gid, 0o750
        if role == "retention":
            return cowrie.pw_uid, cowrie.pw_gid, 0o770
        if role == "cowrie-runtime":
            return cowrie.pw_uid, cowrie.pw_gid, 0o750 if is_dir else 0o640
        raise SafetyError("unknown permission role")
    return policy


def data_identity(path: Path) -> dict:
    path = dedicated_data_path(path)
    with directory(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            info = os.fstat(fd)
            return {"path": str(path), "device": info.st_dev, "inode": info.st_ino}
        finally:
            os.close(fd)


def resource_identity(path: Path) -> dict:
    raw = read_regular(path, 128 << 20)
    with directory(path.parent) as parent:
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise SafetyError("unrecognized administrative resource owner")
    return {"device": info.st_dev, "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode), "sha256": hashlib.sha256(raw).hexdigest()}


def data_stamp(path: Path) -> str:
    try:
        with directory(path.parent) as parent:
            root = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                fd = os.open(".shardlure-installation-id", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=root)
                with os.fdopen(fd, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
                        raise SafetyError("unsafe installation identity stamp")
                    raw = stream.read(34)
                    if info.st_size != 33 or re.fullmatch(rb"[0-9a-f]{32}\n", raw) is None:
                        raise SafetyError("invalid installation identity stamp")
                    return raw[:-1].decode("ascii")
            finally:
                os.close(root)
    except (OSError, UnicodeError) as exc:
        raise SafetyError("installation identity stamp unavailable") from exc


class InstallationState:
    """Root-owned provenance, shared by both installers. Never trust paths in it.

    Operations take explicit caller-selected paths and compare them to this
    record. Pending publications retain their exact intended digest, allowing
    interrupted setup to resume without claiming arbitrary existing resources.
    """
    def __init__(self, data: Path, systemd: Path):
        self.data = dedicated_data_path(data)
        self.marker = checked_absolute(systemd) / ".shardlure-installation.json"

    def load(self) -> dict:
        raw = read_regular(self.marker)
        info = self.marker.lstat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise SafetyError("unsafe installation provenance permissions")
        state = json.loads(raw)
        if (not isinstance(state, dict) or state.get("format") != 2 or
                state.get("data") != data_identity(self.data) or
                state.get("stamp") != data_stamp(self.data) or
                not isinstance(state.get("resources"), dict) or
                not isinstance(state.get("accounts"), dict)):
            raise SafetyError("installation provenance does not match this directory")
        return state

    @contextlib.contextmanager
    def locked(self):
        with directory(self.marker.parent) as parent:
            fd = os.open(".shardlure-installation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
                    raise SafetyError("unsafe installer lock")
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                yield
            finally:
                os.close(fd)

    def _save(self, state: dict) -> None:
        raw = json.dumps(state, separators=(",", ":")).encode()
        if len(raw) > 65536:
            raise SafetyError("installation provenance limit exceeded")
        try:
            previous = self.marker.lstat()
        except FileNotFoundError:
            previous = None
        atomic_create(self.marker, raw, replace=previous)

    def begin(self) -> None:
        with self.locked():
            if self.marker.exists() or self.marker.is_symlink():
                self.load()
                return
            identity = data_identity(self.data)
            with directory(self.data.parent) as parent:
                fd = os.open(self.data.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    names = os.listdir(fd)
                    if names and names != [".shardlure-installation-id"]:
                        raise SafetyError("legacy nonempty data has no installation provenance")
                finally:
                    os.close(fd)
            stamp_file = self.data / ".shardlure-installation-id"
            if not names:
                atomic_create(stamp_file, (uuid.uuid4().hex + "\n").encode())
            self._save({"format": 2, "data": identity, "stamp": data_stamp(self.data), "phase": "preparing", "resources": {}, "accounts": {}})

    def finish(self) -> None:
        with self.locked():
            state = self.load()
            for name in state["resources"]:
                self._check_resource(state, Path(name))
            state["phase"] = "installed"
            state.pop("seal", None)
            self._save(state)

    def seal(self, owner_pid: int | None = None) -> None:
        """Prevent service users replacing checkout/config names during setup."""
        owner = process_identity(owner_pid or os.getpid())
        if owner is None:
            raise SafetyError("cannot identify the installer process")
        with self.locked():
            state = self.load()
            previous = state.get("seal")
            if previous and process_identity(previous["owner"]["pid"]) == previous["owner"] and previous["owner"] != owner:
                raise SafetyError("another installer owns the maintenance window")
            with directory(self.data.parent) as parent:
                fd = os.open(self.data.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    info = os.fstat(fd)
                    if (info.st_dev, info.st_ino) != (state["data"]["device"], state["data"]["inode"]):
                        raise SafetyError("data directory changed before maintenance")
                    saved = previous or {"uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}
                    saved["owner"] = owner
                    state["seal"] = saved
                    self._save(state)
                    try:
                        os.fchown(fd, os.geteuid(), info.st_gid)
                        os.fchmod(fd, 0o710)
                        os.fsync(fd)
                        if not same_object(info, os.stat(self.data.name, dir_fd=parent, follow_symlinks=False)):
                            raise SafetyError("data directory moved during maintenance entry")
                    except BaseException:
                        os.fchown(fd, saved["uid"], saved["gid"])
                        os.fchmod(fd, saved["mode"])
                        raise
                finally:
                    os.close(fd)

    def unseal(self, owner_pid: int | None = None) -> None:
        with self.locked():
            state = self.load()
            saved = state.get("seal")
            if not saved:
                return
            owner = process_identity(owner_pid or os.getpid())
            if process_identity(saved["owner"]["pid"]) == saved["owner"] and saved["owner"] != owner:
                raise SafetyError("another installer owns the maintenance window")
            with directory(self.data.parent) as parent:
                fd = os.open(self.data.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    info = os.fstat(fd)
                    if (info.st_dev, info.st_ino) != (state["data"]["device"], state["data"]["inode"]):
                        raise SafetyError("data identity changed; maintenance metadata retained")
                    os.fchown(fd, saved["uid"], saved["gid"])
                    os.fchmod(fd, saved["mode"])
                    os.fsync(fd)
                finally:
                    os.close(fd)
            state.pop("seal", None)
            self._save(state)

    def remember_account(self, account, created: bool = False) -> None:
        with self.locked():
            state = self.load()
            prior = state["accounts"].get(account.pw_name)
            identity = {"uid": account.pw_uid, "gid": account.pw_gid, "home": account.pw_dir}
            if prior is not None and any(prior.get(k) != v for k, v in identity.items()):
                raise SafetyError("installation account identity changed")
            identity["created"] = created or bool(prior and prior.get("created"))
            state["accounts"][account.pw_name] = identity
            self._save(state)

    def _check_resource(self, state: dict, path: Path) -> None:
        entry = state["resources"].get(str(path))
        if not isinstance(entry, dict):
            raise SafetyError("resource was not created by this installation")
        actual = resource_identity(path)
        if actual == entry.get("file"):
            return
        pending = entry.get("pending")
        if isinstance(pending, dict) and actual["sha256"] == pending.get("sha256") and actual["mode"] == pending.get("mode"):
            return
        raise SafetyError("managed resource was replaced or customized; preserving it")

    def check_resources(self, paths: list[Path]) -> None:
        state = self.load()
        for path in paths:
            if path.exists() or path.is_symlink():
                self._check_resource(state, path)

    def publish(self, path: Path, raw: bytes, mode: int) -> None:
        path = checked_absolute(path)
        with self.locked():
            state = self.load()
            previous = None
            if path.exists() or path.is_symlink():
                self._check_resource(state, path)
                previous = path.lstat()
            entry = state["resources"].setdefault(str(path), {})
            entry["pending"] = {"sha256": hashlib.sha256(raw).hexdigest(), "mode": mode}
            self._save(state)  # Durable intent before publication; no blind adoption.
            atomic_create(path, raw, mode, replace=previous)
            state["resources"][str(path)] = {"file": resource_identity(path)}
            self._save(state)

    def remove(self, path: Path) -> None:
        with self.locked():
            state = self.load()
            if not path.exists() and not path.is_symlink():
                return
            self._check_resource(state, path)
            expected = path.lstat()
            with directory(path.parent) as parent:
                if not same_object(expected, os.stat(path.name, dir_fd=parent, follow_symlinks=False)):
                    raise SafetyError("resource replaced before removal")
                os.unlink(path.name, dir_fd=parent)
                os.fsync(parent)
            state["resources"].pop(str(path), None)
            self._save(state)

    def purge(self) -> None:
        with self.locked():
            state = self.load()
            if state["resources"]:
                raise SafetyError("remove verified administrative resources before purging data")
            owners = {a["uid"] for a in state["accounts"].values()}
            with PermissionPlan(self.data, owners, create=False) as plan:
                plan.collect("", "purge", recursive=True, preserve_symlinks=True)
            marker_info = self.marker.lstat()
            if not shutil.rmtree.avoids_symlink_attacks:
                raise SafetyError("descriptor-based tree removal unavailable")
            with directory(self.data.parent) as parent:
                before = os.stat(self.data.name, dir_fd=parent, follow_symlinks=False)
                if (before.st_dev, before.st_ino) != (state["data"]["device"], state["data"]["inode"]) or not stat.S_ISDIR(before.st_mode):
                    raise SafetyError("purge directory changed")
                hold_name = ".shardlure-purge-" + uuid.uuid4().hex
                os.mkdir(hold_name, 0o700, dir_fd=parent)
                hold = os.open(hold_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    os.rename(self.data.name, "data", src_dir_fd=parent, dst_dir_fd=hold)
                    claimed = os.stat("data", dir_fd=hold, follow_symlinks=False)
                    if not same_object(before, claimed):
                        # Never delete a replacement. Keep it in the private
                        # recovery directory rather than overwrite another entry.
                        raise SafetyError("purge identity changed; recovery directory retained")
                    os.fsync(parent)
                    os.fsync(hold)
                    shutil.rmtree("data", dir_fd=hold)
                    os.fsync(hold)
                finally:
                    os.close(hold)
                os.rmdir(hold_name, dir_fd=parent)
                os.fsync(parent)
            with directory(self.marker.parent) as parent:
                if not same_object(marker_info, os.stat(self.marker.name, dir_fd=parent, follow_symlinks=False)):
                    raise SafetyError("provenance changed; metadata retained")
                os.unlink(self.marker.name, dir_fd=parent)
                os.fsync(parent)


def validate_accounts(data: Path, cowrie_user: str | None = "cowrie") -> dict:
    data = dedicated_data_path(data)
    if cowrie_user and (cowrie_user == "shardlure" or re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", cowrie_user) is None):
        raise SafetyError("invalid Cowrie account name")
    specs = [("shardlure", {str(data)}, {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false"})]
    if cowrie_user:
        specs.append((cowrie_user, {str(data / "cowrie"), f"/home/{cowrie_user}"}, {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/bin/bash", "/bin/sh"}))
    accounts = {}
    for name, homes, shells in specs:
        try:
            account = pwd.getpwnam(name)
        except KeyError:
            try:
                grp.getgrnam(name)
            except KeyError:
                continue
            raise SafetyError("service group exists without its account")
        try:
            group = grp.getgrgid(account.pw_gid)
        except KeyError as exc:
            raise SafetyError("service account has no primary group") from exc
        if (account.pw_name != name or not 0 < account.pw_uid < 2**32-1 or not 0 < account.pw_gid < 2**32-1 or
                account.pw_dir not in homes or account.pw_shell not in shells or group.gr_name != name):
            raise SafetyError("service account conflicts with this installation")
        if any(p.pw_uid == account.pw_uid and p.pw_name != name for p in pwd.getpwall()):
            raise SafetyError("ambiguous service UID")
        groups = grp.getgrall()
        if any(g.gr_gid == account.pw_gid and g.gr_name != name for g in groups):
            raise SafetyError("ambiguous service GID")
        allowed = {name} if name == cowrie_user else {name, cowrie_user, "systemd-journal"}
        if any(name in g.gr_mem and g.gr_name not in allowed for g in groups):
            raise SafetyError("unrelated supplementary service groups")
        accounts[name] = account
    return accounts


def refuse_active_services(cowrie: bool, runner=None) -> None:
    runner = runner or subprocess.run
    units = ["shardlure-live.service"] + (["cowrie.service"] if cowrie else [])
    for unit in units:
        result = runner(["systemctl", "show", unit, "--property=ActiveState", "--value"], capture_output=True, text=True)
        if result.returncode != 0:
            raise SafetyError("cannot inspect service state")
        if (result.stdout or "").strip() not in ("inactive", "failed", ""):
            raise SafetyError("stop services and back up data before installer maintenance")


def verify_unit_accounts(cowrie_user="cowrie", runner=None) -> None:
    runner = runner or subprocess.run
    units = {"shardlure-live.service": "shardlure"}
    if cowrie_user:
        units["cowrie.service"] = cowrie_user
    for unit, user in units.items():
        result = runner(["systemctl", "show", unit, "--property=User", "--property=Group"], capture_output=True, text=True)
        result.check_returncode()
        values = dict(line.split("=", 1) for line in (result.stdout or "").splitlines() if "=" in line)
        if values.get("User") != user or values.get("Group") != user:
            raise SafetyError("effective service account differs from the verified installation")


def preflight(data: Path, systemd: Path, binary_dir: Path, cowrie_user="cowrie", runner=None) -> None:
    runner = runner or subprocess.run
    accounts = validate_accounts(data, cowrie_user)
    refuse_active_services(bool(cowrie_user), runner)
    paths = [systemd / "shardlure-live.service", binary_dir / "shardlure"]
    if cowrie_user:
        paths.append(systemd / "cowrie.service")
    state = InstallationState(data, systemd)
    current = data
    while not current.exists() and not current.is_symlink():
        current = current.parent
    with directory(current, owners={a.pw_uid for a in accounts.values()}):
        pass
    if state.marker.exists() or state.marker.is_symlink():
        state.check_resources(paths)
        saved = state.load()
        seal = saved.get("seal")
        if seal and process_identity(seal["owner"]["pid"]) == seal["owner"]:
            raise SafetyError("another installer owns the maintenance window")
        known = saved["accounts"]
        for name, identity in known.items():
            account = accounts.get(name)
            if account is None or (account.pw_uid, account.pw_gid, account.pw_dir) != (identity["uid"], identity["gid"], identity["home"]):
                raise SafetyError("registered service account changed")
    else:
        if any(p.exists() or p.is_symlink() for p in paths):
            raise SafetyError("unrecognized installed resources; use binary-only upgrade or explicit ownership review")
        if data.exists():
            with directory(data, owners={a.pw_uid for a in accounts.values()}) as fd:
                names = os.listdir(fd)
                if names and names != [".shardlure-installation-id"]:
                    raise SafetyError("legacy nonempty data lacks installation provenance")
                if names:
                    data_stamp(data)


def prepare_accounts(data: Path, systemd: Path, cowrie_user="cowrie", runner=None) -> None:
    runner = runner or subprocess.run
    accounts = validate_accounts(data, cowrie_user)
    refuse_active_services(bool(cowrie_user), runner)
    state = InstallationState(data, systemd)
    with PermissionPlan(data, {a.pw_uid for a in accounts.values()}) as plan:
        plan_service_permissions(plan, cowrie=bool(cowrie_user))
        if cowrie_user and cowrie_user not in accounts:
            raise SafetyError("Cowrie account missing; complete Cowrie setup first")
        created = "shardlure" not in accounts
        if created:
            runner(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", str(data), "--shell", "/usr/sbin/nologin", "shardlure"]).check_returncode()
            accounts["shardlure"] = pwd.getpwnam("shardlure")
        groups = "systemd-journal" + ("," + cowrie_user if cowrie_user else "")
        runner(["usermod", "-a", "-G", groups, "shardlure"]).check_returncode()
        if state.marker.exists():
            state.remember_account(accounts["shardlure"], created)
            if cowrie_user:
                state.remember_account(accounts[cowrie_user])
        plan.apply(service_policy(accounts["shardlure"], accounts.get(cowrie_user)))


def prepare_cowrie_tree(data: Path, user: str) -> None:
    account = pwd.getpwnam(user)
    with PermissionPlan(data, {account.pw_uid}) as plan:
        plan.collect("cowrie", "code", recursive=True, preserve_symlinks=True)
        plan.collect("", "parent")
        def policy(role, info):
            if role == "parent":
                return info.st_uid, account.pw_gid, 0o710
            mode = 0o700 if stat.S_ISDIR(info.st_mode) or info.st_mode & 0o111 else 0o600
            return account.pw_uid, account.pw_gid, mode
        plan.apply(policy)


def ensure_authbind(port: int, user: str) -> None:
    if port >= 1024:
        return
    if not 1 <= port <= 65535:
        raise SafetyError("invalid authbind port")
    account = pwd.getpwnam(user)
    root = Path("/etc/authbind/byport")
    with directory(root) as parent:
        try:
            fd = os.open(str(port), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o500, dir_fd=parent)
        except FileExistsError:
            info = os.stat(str(port), dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != account.pw_uid or stat.S_IMODE(info.st_mode) != 0o500:
                raise SafetyError("existing authbind rule is not compatible; preserving it")
            return
        try:
            os.fchown(fd, account.pw_uid, account.pw_gid)
            os.fchmod(fd, 0o500)
            os.fsync(fd)
            os.fsync(parent)
        finally:
            os.close(fd)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("preflight", "begin", "seal", "unseal", "prepare", "verify-units", "cowrie-permissions", "authbind", "publish", "config", "finish", "remember-account"))
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--systemd-dir", type=Path, default=Path("/etc/systemd/system"))
    parser.add_argument("--bin-dir", type=Path, default=Path("/usr/local/bin"))
    parser.add_argument("--cowrie", choices=("0", "1"), default="1")
    parser.add_argument("--cowrie-user", default="cowrie")
    parser.add_argument("--path", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--mode", type=lambda x: int(x, 8), default=0o600)
    parser.add_argument("--name")
    parser.add_argument("--created", action="store_true")
    parser.add_argument("--owner-pid", type=int)
    parser.add_argument("--port", type=int)
    args = parser.parse_args(argv)
    user = args.cowrie_user if args.cowrie == "1" else None
    state = InstallationState(args.data_dir, args.systemd_dir)
    if args.operation == "preflight":
        preflight(args.data_dir, args.systemd_dir, args.bin_dir, user)
    elif args.operation == "begin":
        accounts = validate_accounts(args.data_dir, user)
        with PermissionPlan(args.data_dir, {a.pw_uid for a in accounts.values()}) as plan:
            state.begin()
            for name in ("evidence", "captures", "payloads", "artifacts", "logs"):
                plan.ensure_directory(name)
        print(str(args.data_dir))
    elif args.operation == "prepare":
        prepare_accounts(args.data_dir, args.systemd_dir, user)
    elif args.operation == "verify-units":
        verify_unit_accounts(user)
    elif args.operation == "seal":
        state.seal(args.owner_pid)
    elif args.operation == "unseal":
        state.unseal(args.owner_pid)
    elif args.operation == "cowrie-permissions":
        if not user:
            raise SafetyError("Cowrie account required")
        prepare_cowrie_tree(args.data_dir, user)
    elif args.operation == "authbind":
        if not user or args.port is None:
            raise SafetyError("Cowrie account and port required")
        ensure_authbind(args.port, user)
    elif args.operation == "publish":
        allowed = {args.bin_dir / "shardlure", args.systemd_dir / "shardlure-live.service"}
        if user:
            allowed.add(args.systemd_dir / "cowrie.service")
        if args.path not in allowed or args.source is None or args.mode not in (0o600, 0o755):
            raise SafetyError("unsupported administrative publication")
        state.publish(args.path, read_regular(args.source, 128 << 20), args.mode)
    elif args.operation == "config":
        target = args.data_dir / "shardlure.yaml"
        if target.exists() or target.is_symlink():
            accounts = validate_accounts(args.data_dir, user)
            with PermissionPlan(args.data_dir, {a.pw_uid for a in accounts.values()}) as plan:
                plan.collect("shardlure.yaml", "config")
            print("existing configuration preserved")
        else:
            if args.source is None:
                raise SafetyError("configuration source required")
            atomic_create(target, read_regular(args.source, 4 << 20))
    elif args.operation == "finish":
        state.finish()
    elif args.operation == "remember-account":
        if args.name not in ("shardlure", user):
            raise SafetyError("unexpected service account")
        state.remember_account(pwd.getpwnam(args.name), args.created)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"installer safety: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
