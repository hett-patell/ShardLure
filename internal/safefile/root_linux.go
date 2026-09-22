//go:build linux

package safefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

type Root struct {
	mu   sync.RWMutex
	dir  *os.File
	path string
}

const confinedResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV

func safeError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.ENOENT):
		return ErrNotExist
	case errors.Is(err, unix.EEXIST), errors.Is(err, unix.ENOTEMPTY):
		return ErrExists
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		return ErrPermission
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		return ErrUnsafePath
	case errors.Is(err, unix.EAGAIN):
		return ErrChanged
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.EXDEV), errors.Is(err, unix.EINVAL):
		return ErrUnsupported
	case errors.Is(err, unix.ENOSPC), errors.Is(err, unix.EDQUOT):
		return ErrNoSpace
	default:
		return ErrIO
	}
}

func supportedFilesystem(fd int) error {
	var st unix.Statfs_t
	if err := unix.Fstatfs(fd, &st); err != nil {
		return safeError(err)
	}
	// The supported Linux deployment/test filesystems implement descriptor
	// access, exclusive creation, renameat2(NOREPLACE), and directory fsync.
	// In particular, never silently accept procfs, sysfs, NFS or FUSE inputs.
	switch uint64(uint32(st.Type)) {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC:
		return nil
	default:
		return ErrUnsupported
	}
}

func OpenRoot(path string) (*Root, error) {
	if path == "" || strings.ContainsRune(path, 0) || !utf8.ValidString(path) {
		return nil, ErrUnsafePath
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrUnsafePath
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, abs, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK), Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, safeError(err)
	}
	if err := supportedFilesystem(fd); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &Root{dir: os.NewFile(uintptr(fd), "confined-root"), path: abs}, nil
}

func validRelative(rel string) bool {
	return rel != "" && rel != "." && rel != ".." && !filepath.IsAbs(rel) && filepath.Clean(rel) == rel &&
		!strings.HasPrefix(rel, "../") && !strings.ContainsRune(rel, 0) && utf8.ValidString(rel) && len(rel) <= 4096
}

func probeAt(root int, rel string) (int, unix.Stat_t, error) {
	var st unix.Stat_t
	fd, err := unix.Openat2(root, rel, &unix.OpenHow{Flags: uint64(unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW), Resolve: confinedResolve})
	if err != nil {
		return -1, st, safeError(err)
	}
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, st, safeError(err)
	}
	return fd, st, nil
}

func sameObject(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode&unix.S_IFMT == b.Mode&unix.S_IFMT && a.Uid == b.Uid && a.Gid == b.Gid
}

func unchangedFile(a, b unix.Stat_t) bool {
	return sameObject(a, b) && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// Reopen a checked O_PATH descriptor, not an attacker-replaceable name. The
// only followed magic link is in the kernel's verified /proc/self/fd directory
// and refers to our own still-open descriptor. This avoids opening a device or
// blocking on a FIFO merely to learn its type. No unsafe pathname fallback.
func reopenPinned(fd int, directory bool) (int, error) {
	proc, err := unix.Open("/proc/self/fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, ErrUnsupported
	}
	defer unix.Close(proc)
	var fsstat unix.Statfs_t
	if err := unix.Fstatfs(proc, &fsstat); err != nil || uint64(uint32(fsstat.Type)) != unix.PROC_SUPER_MAGIC {
		return -1, ErrUnsupported
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY
	if directory {
		flags |= unix.O_DIRECTORY
	}
	readFD, err := unix.Openat(proc, strconv.Itoa(fd), flags, 0)
	if err != nil {
		return -1, safeError(err)
	}
	return readFD, nil
}

func (r *Root) OpenRegular(rel string) (*os.File, error) {
	if !validRelative(rel) {
		return nil, ErrUnsafePath
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.dir == nil {
		return nil, ErrClosed
	}
	root := int(r.dir.Fd())
	probe, initial, err := probeAt(root, rel)
	if err != nil {
		return nil, err
	}
	defer unix.Close(probe)
	if initial.Mode&unix.S_IFMT != unix.S_IFREG || initial.Nlink != 1 {
		return nil, ErrNotRegular
	}
	if err := supportedFilesystem(probe); err != nil {
		return nil, err
	}
	fd, err := reopenPinned(probe, false)
	if err != nil {
		return nil, err
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		unix.Close(fd)
		return nil, safeError(err)
	}
	current, currentStat, err := probeAt(root, rel)
	if err != nil {
		unix.Close(fd)
		return nil, ErrChanged
	}
	unix.Close(current)
	if !unchangedFile(initial, opened) || !unchangedFile(initial, currentStat) {
		unix.Close(fd)
		return nil, ErrChanged
	}
	return os.NewFile(uintptr(fd), "confined-file"), nil
}

func (r *Root) CreateExclusive(rel string, mode fs.FileMode) (*os.File, error) {
	if !validRelative(rel) {
		return nil, ErrUnsafePath
	}
	if mode&^fs.FileMode(0600) != 0 || mode == 0 {
		return nil, ErrInvalidMode
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.dir == nil {
		return nil, ErrClosed
	}
	if err := r.checkOutputLocked(); err != nil {
		return nil, err
	}
	fd, err := unix.Openat2(int(r.dir.Fd()), rel, &unix.OpenHow{Flags: uint64(unix.O_RDWR | unix.O_CLOEXEC | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW), Mode: uint64(mode.Perm()), Resolve: confinedResolve})
	if err != nil {
		return nil, safeError(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, safeError(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		unix.Close(fd)
		return nil, ErrNotRegular
	}
	if err := r.checkOutputLocked(); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "confined-output"), nil
}

// CheckOutput is also required before adopting an existing published file:
// read-only source roots may be writable by a different (Cowrie) account, but
// output entries must be protected against replacement by other accounts.
func (r *Root) CheckOutput() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.dir == nil {
		return ErrClosed
	}
	return r.checkOutputLocked()
}

func (r *Root) checkOutputLocked() error {
	if err := checkOutputDirectory(int(r.dir.Fd())); err != nil {
		return err
	}
	uid := uint32(os.Geteuid())
	for name := r.path; ; name = filepath.Dir(name) {
		var st unix.Stat_t
		if err := unix.Lstat(name, &st); err != nil {
			return ErrChanged
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return ErrChanged
		}
		if st.Uid != uid && st.Uid != 0 {
			return ErrPermission
		}
		if st.Mode&0022 != 0 && st.Mode&unix.S_ISVTX == 0 {
			return ErrPermission
		}
		if filepath.Dir(name) == name {
			break
		}
	}
	// Reads keep their original descriptor capability after a rename. Outputs
	// additionally require their published pathname to still name that root.
	fd, err := unix.Openat2(unix.AT_FDCWD, r.path, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK), Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return ErrChanged
	}
	defer unix.Close(fd)
	var held, named unix.Stat_t
	if unix.Fstat(int(r.dir.Fd()), &held) != nil || unix.Fstat(fd, &named) != nil {
		return ErrIO
	}
	if !sameObject(held, named) {
		return ErrChanged
	}
	return nil
}

func checkOutputDirectory(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return safeError(err)
	}
	uid := uint32(os.Geteuid())
	if st.Uid == uid && st.Mode&0022 == 0 {
		return nil
	}
	// A root/current-user-owned sticky temporary directory protects entries
	// owned by this process too; a foreign directory owner is never trusted.
	if (st.Uid == 0 || st.Uid == uid) && st.Mode&unix.S_ISVTX != 0 {
		return nil
	}
	return ErrPermission
}

func (r *Root) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dir == nil {
		return nil
	}
	err := r.dir.Close()
	r.dir = nil
	return safeError(err)
}

func PublishNoReplace(parent, stagedName, finalName string) error {
	r, err := OpenRoot(parent)
	if err != nil {
		return err
	}
	defer r.Close()
	return r.publishNoReplace(stagedName, finalName, unix.Fsync)
}

func (r *Root) publishNoReplace(stagedName, finalName string, syncParent func(int) error) error {
	if !validRelative(stagedName) || !validRelative(finalName) || filepath.Base(stagedName) != stagedName || filepath.Base(finalName) != finalName || stagedName == finalName {
		return ErrUnsafePath
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.dir == nil {
		return ErrClosed
	}
	parent := int(r.dir.Fd())
	if err := r.checkOutputLocked(); err != nil {
		return err
	}
	probe, initial, err := probeAt(parent, stagedName)
	if err != nil {
		return err
	}
	defer unix.Close(probe)
	if initial.Uid != uint32(os.Geteuid()) {
		return ErrPermission
	}
	directory := initial.Mode&unix.S_IFMT == unix.S_IFDIR
	if !directory && (initial.Mode&unix.S_IFMT != unix.S_IFREG || initial.Nlink != 1) {
		return ErrNotRegular
	}
	if initial.Mode&0077 != 0 || initial.Mode&unix.S_ISUID != 0 || (!directory && initial.Mode&(0111|unix.S_ISGID) != 0) {
		return ErrInvalidMode
	}
	stage, err := reopenPinned(probe, directory)
	if err != nil {
		return err
	}
	defer unix.Close(stage)
	if err := unix.Fsync(stage); err != nil {
		return ErrSync
	}
	current, currentStat, err := probeAt(parent, stagedName)
	if err != nil {
		return ErrChanged
	}
	unix.Close(current)
	if !unchangedFile(initial, currentStat) {
		return ErrChanged
	}
	if err := unix.Renameat2(parent, stagedName, parent, finalName, unix.RENAME_NOREPLACE); err != nil {
		return safeError(err)
	}
	final, finalStat, err := probeAt(parent, finalName)
	if err != nil {
		return ErrChanged
	}
	unix.Close(final)
	if !sameObject(initial, finalStat) {
		return ErrChanged
	}
	if initial.Mode != finalStat.Mode || initial.Nlink != finalStat.Nlink || initial.Size != finalStat.Size || initial.Mtim != finalStat.Mtim {
		return ErrChanged
	}
	if err := syncParent(parent); err != nil {
		return ErrSync
	}
	if err := r.checkOutputLocked(); err != nil {
		return err
	}
	after, afterStat, err := probeAt(parent, finalName)
	if err != nil {
		return ErrChanged
	}
	unix.Close(after)
	if !unchangedFile(finalStat, afterStat) {
		return ErrChanged
	}
	return nil
}
