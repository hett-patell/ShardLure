//go:build unix

package store

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"
)

// CheckDatabaseOwner performs metadata-only checks before SQLite can migrate,
// chmod, or create sidecars. It intentionally does not open/close an extra DB
// descriptor: closing one can release this process's existing SQLite POSIX locks.
func CheckDatabaseOwner(path string) error {
	return checkDatabaseOwner(path, os.Lstat, os.Geteuid())
}

func databaseStat(info fs.FileInfo) (*syscall.Stat_t, error) {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, ErrDatabaseUnsupported
	}
	return s, nil
}

func checkDatabaseOwner(path string, stat func(string) (fs.FileInfo, error), uid int) error {
	if path == "" || strings.ContainsRune(path, 0) || !utf8.ValidString(path) || uid < 0 {
		return ErrDatabaseUnsafe
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return ErrDatabaseUnsafe
	}
	var components []string
	for p := abs; ; p = filepath.Dir(p) {
		components = append(components, p)
		if filepath.Dir(p) == p {
			break
		}
	}
	var parent fs.FileInfo
	mainExists := false
	for i := len(components) - 1; i >= 0; i-- {
		info, err := stat(components[i])
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return ErrDatabaseAccess
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrDatabaseUnsafe
		}
		s, err := databaseStat(info)
		if err != nil {
			return err
		}
		if i == 0 {
			mainExists = true
			if !info.Mode().IsRegular() || s.Nlink != 1 {
				return ErrDatabaseUnsafe
			}
			if s.Uid != uint32(uid) {
				return ErrDatabaseOwner
			}
			if info.Mode().Perm()&0022 != 0 {
				return ErrDatabaseUnsafe
			}
			continue
		}
		if !info.IsDir() {
			return ErrDatabaseUnsafe
		}
		// Ancestors can be system-owned; another untrusted owner or a writable
		// non-sticky ancestor could replace the supposedly private parent.
		if s.Uid != 0 && s.Uid != uint32(uid) {
			return ErrDatabaseOwner
		}
		if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return ErrDatabaseUnsafe
		}
		parent = info
	}
	if parent == nil {
		return ErrDatabaseUnsafe
	}
	ps, err := databaseStat(parent)
	if err != nil {
		return err
	}
	// A shared/sticky directory is not suitable as the immediate DB parent:
	// another account could precreate a WAL/SHM filename there.
	if ps.Uid != uint32(uid) {
		return ErrDatabaseOwner
	}
	if parent.Mode().Perm()&0022 != 0 {
		return ErrDatabaseUnsafe
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		info, err := stat(abs + suffix)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return ErrDatabaseAccess
		}
		if !mainExists || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return ErrDatabaseUnsafe
		}
		s, err := databaseStat(info)
		if err != nil {
			return err
		}
		if s.Uid != uint32(uid) {
			return ErrDatabaseOwner
		}
		if s.Nlink != 1 || info.Mode().Perm()&0022 != 0 {
			return ErrDatabaseUnsafe
		}
	}
	return nil
}
