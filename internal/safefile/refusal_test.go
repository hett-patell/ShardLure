//go:build linux

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A refused output ancestor must say which directory failed and why, so an
// operator can pick a safe location instead of guessing. Error() itself stays
// path-free (package contract); the path travels only in the typed field.
func TestCheckOutputNamesRefusedAncestorAndReason(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ownership/permission refusal test must run as a non-root user")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0770); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(parent, 0700) })
	dir := filepath.Join(parent, "private-child")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	err = r.CheckOutput()
	if !errors.Is(err, ErrPermission) {
		t.Fatalf("refusal lost its category: %v", err)
	}
	var refusal *PathRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("refusal is not a *PathRefusal: %v", err)
	}
	if refusal.Path != parent {
		t.Fatalf("refused path = %q, want the group-writable ancestor %q", refusal.Path, parent)
	}
	if !strings.Contains(refusal.Reason, "writable by group or others") || !strings.Contains(err.Error(), refusal.Reason) {
		t.Fatalf("reason missing: reason=%q err=%v", refusal.Reason, err)
	}
	if strings.Contains(err.Error(), parent) {
		t.Fatalf("Error() leaked a path: %v", err)
	}
}

func TestOpenRootNamesSymlinkComponent(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	_, err := OpenRoot(filepath.Join(link, "x", ".."))
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink component accepted or recategorised: %v", err)
	}
	var refusal *PathRefusal
	if !errors.As(err, &refusal) || !strings.Contains(refusal.Reason, "symlink") {
		t.Fatalf("symlink refusal has no reason: %v", err)
	}
}
