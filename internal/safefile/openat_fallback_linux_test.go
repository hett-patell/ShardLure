//go:build linux

package safefile

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Regression (whole-branch review): the openat fallback used when openat2 is
// unavailable (kernel < 5.6, or seccomp returning ENOSYS) set dirfd to
// AT_FDCWD for an absolute path and then dropped the leading "/", so every
// component resolved relative to the process working directory. It only
// worked by accident under systemd, whose units start in "/".
func TestOpenatNoFollowAbsolutePathIgnoresWorkingDirectory(t *testing.T) {
	target := t.TempDir()
	if err := os.Mkdir(filepath.Join(target, "marker-dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	decoy := t.TempDir()
	// A decoy tree under the working directory that shadows the absolute
	// path's components, so a cwd-relative walk would "succeed" wrongly.
	if err := os.MkdirAll(filepath.Join(decoy, target), 0o700); err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(decoy); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	fd, err := openatNoFollow(unix.AT_FDCWD, target, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatalf("absolute open failed: %v", err)
	}
	defer unix.Close(fd)
	if _, err := unix.Openat(fd, "marker-dir", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err != nil {
		t.Fatalf("opened the cwd-relative decoy instead of %s: %v", target, err)
	}
}
