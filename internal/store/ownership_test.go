//go:build unix

package store

import (
	"bytes"
	"database/sql"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestOwnershipSQLiteFilenameIsEncodedLiterally(t *testing.T) {
	path := filepath.Join(t.TempDir(), "literal?#name with % and &.db")
	info, statErr := os.Stat(filepath.Dir(path))
	if statErr != nil {
		t.Fatal(statErr)
	}
	t.Logf("fixture UID=%d EUID=%d mode=%v", info.Sys().(*syscall.Stat_t).Uid, os.Geteuid(), info.Mode())
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("CREATE TABLE ownership_marker(value TEXT); INSERT INTO ownership_marker VALUES('persisted')"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("SQLite opened a different filename: %v", err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var value string
	if err := s.db.QueryRow("SELECT value FROM ownership_marker").Scan(&value); err != nil || value != "persisted" {
		t.Fatalf("literal filename lost data: %q %v", value, err)
	}
}

func TestOwnershipUnsafePathsRejectBeforeMutation(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "shared-parent", "sidecar-symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "private-db-name.db")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("CREATE TABLE marker(value TEXT); INSERT INTO marker VALUES('inert')"); err != nil {
				t.Fatal(err)
			}
			db.Close()
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			actual := path
			switch kind {
			case "symlink":
				actual = filepath.Join(dir, "alias.db")
				if err := os.Symlink(path, actual); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(dir, "second.db")); err != nil {
					t.Fatal(err)
				}
			case "shared-parent":
				if err := os.Chmod(dir, 0777); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(dir, 0700)
			case "sidecar-symlink":
				if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), path+"-wal"); err != nil {
					t.Fatal(err)
				}
			}
			s, err := Open(actual)
			if err == nil {
				s.Close()
				t.Fatalf("unsafe %s accepted", kind)
			}
			if strings.Contains(err.Error(), "private-db-name") || strings.Contains(err.Error(), dir) {
				t.Fatalf("path leaked in ownership error: %v", err)
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(original, after) {
				t.Fatalf("rejected database was changed: %v", readErr)
			}
			if _, err := os.Lstat(path + "-shm"); !os.IsNotExist(err) {
				t.Fatalf("sidecar created before rejection: %v", err)
			}
		})
	}
}

type ownershipFileInfo struct {
	fs.FileInfo
	metadata *syscall.Stat_t
}

func (i ownershipFileInfo) Sys() any { return i.metadata }

func TestOwnershipWrongAccountRejectedBeforeOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE marker(value TEXT); INSERT INTO marker VALUES('inert')"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Inject only OS metadata: the real ownership policy and store-opening
	// workflow still run. No file on this host changes owner.
	stat := func(name string) (fs.FileInfo, error) {
		i, err := os.Lstat(name)
		if err != nil {
			return nil, err
		}
		if name == path {
			raw := *(i.Sys().(*syscall.Stat_t))
			raw.Uid = uint32(os.Geteuid() + 1)
			return ownershipFileInfo{i, &raw}, nil
		}
		return i, nil
	}
	check := func(name string) error { return checkDatabaseOwner(name, stat, os.Geteuid()) }
	s, err := openWithOwnerCheck(path, check)
	if s != nil {
		s.Close()
	}
	if !errors.Is(err, ErrDatabaseOwner) {
		t.Fatalf("wrong account=%v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatalf("wrong-owner open mutated DB: %v", err)
	}
	current, err := os.Stat(path)
	if err != nil || current.Mode() != info.Mode() {
		t.Fatalf("wrong-owner open chmodded DB: %v", err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			t.Fatalf("wrong-owner sidecar %s: %v", suffix, err)
		}
	}
}
