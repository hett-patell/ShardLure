//go:build linux

package safefile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

type Root struct {
	mu   sync.RWMutex
	dir  *os.File
	path string
}

// CheckWritable probes access without creating/removing a test file. Explicit
// owner-read-only mode remains unavailable even to a privileged process.
func (r *Root) CheckWritable() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.dir == nil {
		return ErrClosed
	}
	if err := r.checkOutputLocked(); err != nil {
		return err
	}
	info, err := r.dir.Stat()
	if err != nil {
		return ErrIO
	}
	if info.Mode().Perm()&0200 == 0 {
		return ErrPermission
	}
	return safeError(unix.Faccessat2(int(r.dir.Fd()), ".", unix.R_OK|unix.W_OK|unix.X_OK, unix.AT_EACCESS))
}

// Stat inspects metadata through O_PATH, never a regular data descriptor. This
// lets backup inventory exclude active SQLite inodes before opening contents.
func (r *Root) Stat(name string) (fs.FileInfo, error) {
	if !validRelative(name) {
		return nil, ErrUnsafePath
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.dir == nil {
		return nil, ErrClosed
	}
	fd, _, err := probeAt(int(r.dir.Fd()), name)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "confined-metadata")
	defer f.Close()
	info, err := f.Stat()
	return info, safeError(err)
}

func (r *Root) Info() (fs.FileInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.dir == nil {
		return nil, ErrClosed
	}
	info, err := r.dir.Stat()
	return info, safeError(err)
}

func (r *Root) Sync() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.dir == nil {
		return ErrClosed
	}
	if err := r.checkOutputLocked(); err != nil {
		return err
	}
	if err := unix.Fsync(int(r.dir.Fd())); err != nil {
		return ErrSync
	}
	return nil
}

func (r *Root) AvailableBytes() (uint64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.dir == nil {
		return 0, ErrClosed
	}
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(r.dir.Fd()), &st); err != nil {
		return 0, safeError(err)
	}
	if st.Bsize <= 0 || uint64(st.Bavail) > ^uint64(0)/uint64(st.Bsize) {
		return 0, ErrIO
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

func (r *Root) OpenDirectory(name string) (*Root, error) {
	if !validRelative(name) {
		return nil, ErrUnsafePath
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.dir == nil {
		return nil, ErrClosed
	}
	fd, err := unix.Openat2(int(r.dir.Fd()), name, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK), Resolve: confinedResolve})
	if err != nil {
		return nil, safeError(err)
	}
	return &Root{dir: os.NewFile(uintptr(fd), "confined-directory"), path: filepath.Join(r.path, name)}, nil
}

func (r *Root) CreateDirectory(name string) (*Root, error) {
	if !validRelative(name) || filepath.Base(name) != name {
		return nil, ErrUnsafePath
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.dir == nil {
		return nil, ErrClosed
	}
	if err := r.checkOutputLocked(); err != nil {
		return nil, err
	}
	if err := unix.Mkdirat(int(r.dir.Fd()), name, 0700); err != nil {
		return nil, safeError(err)
	}
	fd, err := unix.Openat2(int(r.dir.Fd()), name, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW), Resolve: confinedResolve})
	if err != nil {
		return nil, safeError(err)
	}
	child := &Root{dir: os.NewFile(uintptr(fd), "confined-directory"), path: filepath.Join(r.path, name)}
	if err := child.CheckOutput(); err != nil {
		child.Close()
		return nil, err
	}
	if err := unix.Fsync(int(r.dir.Fd())); err != nil {
		child.Close()
		return nil, ErrSync
	}
	return child, nil
}

// RemoveIfUnchanged first moves the selected entry into a private holding
// directory, then checks its identity again before unlinking. A raced-in file
// is restored without replacing any newer source entry; if restoration is
// impossible, its bytes remain in the private holding directory for recovery.
func (r *Root) RemoveIfUnchanged(name string, expected fs.FileInfo) error {
	if !validRelative(name) || filepath.Base(name) != name || expected == nil {
		return ErrUnsafePath
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.dir == nil {
		return ErrClosed
	}
	parent := int(r.dir.Fd())
	fd, st, err := probeAt(parent, name)
	if err != nil {
		return err
	}
	probe := os.NewFile(uintptr(fd), "confined-retention")
	before, statErr := probe.Stat()
	probe.Close()
	if statErr != nil {
		return ErrIO
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || !SameFileState(expected, before) {
		return ErrChanged
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ErrIO
	}
	holdName := ".shardlure-retention-" + hex.EncodeToString(nonce[:])
	if err := unix.Mkdirat(parent, holdName, 0700); err != nil {
		return safeError(err)
	}
	hold, err := unix.Openat2(parent, holdName, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW), Resolve: confinedResolve})
	if err != nil {
		return safeError(err)
	}
	defer unix.Close(hold)
	var holdInfo unix.Stat_t
	if unix.Fstat(hold, &holdInfo) != nil || holdInfo.Uid != uint32(os.Geteuid()) || holdInfo.Mode&0077 != 0 {
		return ErrPermission
	}
	defer func() {
		current, currentInfo, err := probeAt(parent, holdName)
		if err == nil {
			unix.Close(current)
			if sameObject(holdInfo, currentInfo) {
				_ = unix.Unlinkat(parent, holdName, unix.AT_REMOVEDIR)
			}
		}
	}()
	if err := unix.Renameat2(parent, name, hold, "entry", unix.RENAME_NOREPLACE); err != nil {
		return safeError(err)
	}
	moved, movedInfo, err := probeAt(hold, "entry")
	if err == nil {
		unix.Close(moved)
	}
	// Rename changes ctime; all other identity/content metadata must match the
	// descriptor checked immediately before moving the entry.
	unchanged := err == nil && sameObject(st, movedInfo) && st.Mode == movedInfo.Mode && st.Nlink == movedInfo.Nlink && st.Size == movedInfo.Size && st.Mtim == movedInfo.Mtim
	if !unchanged {
		_ = unix.Renameat2(hold, "entry", parent, name, unix.RENAME_NOREPLACE)
		_ = unix.Fsync(hold)
		_ = unix.Fsync(parent)
		return ErrChanged
	}
	if err := unix.Unlinkat(hold, "entry", 0); err != nil {
		return safeError(err)
	}
	if unix.Fsync(hold) != nil || unix.Fsync(parent) != nil {
		return ErrSync
	}
	return nil
}

// ReadNames streams names only. DirEntry.Info would reopen through a pathname
// and lose descriptor confinement; callers use OpenRegular for authoritative
// metadata and bytes instead.
func (r *Root) ReadNames(limit int) ([]string, error) {
	if limit <= 0 || limit > 256 {
		limit = 64
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.dir == nil {
		return nil, ErrClosed
	}
	names, err := r.dir.Readdirnames(limit)
	if err == io.EOF {
		return names, io.EOF
	}
	return names, safeError(err)
}

// EnsureDirectory creates missing owner-only directories through protected
// parent descriptors. It never follows a supplied symlink or chmods an existing
// foreign/shared directory to make it acceptable.
func EnsureDirectory(path string) (*Root, error) {
	if path == "" || strings.ContainsRune(path, 0) || !utf8.ValidString(path) {
		return nil, ErrUnsafePath
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrUnsafePath
	}
	if r, err := OpenRoot(abs); err == nil {
		if err := r.CheckOutput(); err != nil {
			r.Close()
			return nil, err
		}
		return r, nil
	} else if !errors.Is(err, ErrNotExist) {
		return nil, err
	}
	parentPath := filepath.Dir(abs)
	if parentPath == abs {
		return nil, ErrUnsafePath
	}
	parent, err := EnsureDirectory(parentPath)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	parent.mu.RLock()
	defer parent.mu.RUnlock()
	if err := parent.checkOutputLocked(); err != nil {
		return nil, err
	}
	if err := unix.Mkdirat(int(parent.dir.Fd()), filepath.Base(abs), 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, safeError(err)
	}
	if err := unix.Fsync(int(parent.dir.Fd())); err != nil {
		return nil, ErrSync
	}
	r, err := OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	if err := r.CheckOutput(); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

// RemoveCreated removes only a caller-created temporary entry in a protected
// output directory. A replacement entry is never deleted as cleanup.
func (r *Root) RemoveCreated(name string, created fs.FileInfo) error {
	if !validRelative(name) || filepath.Base(name) != name || created == nil {
		return ErrUnsafePath
	}
	expected, ok := created.Sys().(*syscall.Stat_t)
	if !ok {
		return ErrUnsupported
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.dir == nil {
		return ErrClosed
	}
	if err := r.checkOutputLocked(); err != nil {
		return err
	}
	fd, st, err := probeAt(int(r.dir.Fd()), name)
	if errors.Is(err, ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Dev != uint64(expected.Dev) || st.Ino != uint64(expected.Ino) {
		return ErrChanged
	}
	if err := unix.Unlinkat(int(r.dir.Fd()), name, 0); err != nil {
		return safeError(err)
	}
	return nil
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
	// Temporary diagnostic: log the filesystem magic number so we can identify
	// what type systemd's mount namespace presents under ProtectSystem=strict.
	log.Printf("safefile: filesystem magic=0x%x path-fd=%d", uint64(uint32(st.Type)), fd)
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
		// Temporary diagnostic: log the raw errno from openat2 to identify
		// why path resolution fails under systemd's ProtectSystem=strict namespace.
		log.Printf("safefile: OpenRoot openat2 failed errno=%d path-hidden", int(err.(unix.Errno)))
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

// SameFileState detects in-place changes even when an mtime is restored.
func SameFileState(a, b fs.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Size() != b.Size() || a.Mode() != b.Mode() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	x, ok := a.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	y, ok := b.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return x.Ctim == y.Ctim && x.Nlink == y.Nlink && x.Uid == y.Uid && x.Gid == y.Gid
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

func (r *Root) PublishNoReplace(stagedName, finalName string) error {
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
