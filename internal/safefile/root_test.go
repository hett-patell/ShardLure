//go:build linux

package safefile

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestConfinedRegularAndUnsafeNames(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nested", "inert"), []byte("inert bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	f, err := r.OpenRegular("nested/inert")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(f)
	f.Close()
	if err != nil || string(body) != "inert bytes" {
		t.Fatalf("read=%q err=%v", body, err)
	}
	for _, name := range []string{"", ".", "..", "../outside", "/etc/passwd", "nested/../nested/inert", "nested//inert", "nested/./inert", "private\x00name"} {
		f, err := r.OpenRegular(name)
		if err == nil {
			f.Close()
			t.Errorf("unsafe/aliased name accepted: %q", name)
		} else if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), dir) {
			t.Errorf("path leaked: %v", err)
		}
	}
}

func TestConfinedRejectsSymlinksAndHardlinks(t *testing.T) {
	for _, kind := range []string{"contained", "escaping", "parent-symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("outside inert bytes"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "inert"), []byte("inside"), 0600); err != nil {
				t.Fatal(err)
			}
			rel := "link"
			switch kind {
			case "contained":
				if err := os.Symlink("inert", filepath.Join(dir, rel)); err != nil {
					t.Fatal(err)
				}
			case "escaping":
				if err := os.Symlink(outside, filepath.Join(dir, rel)); err != nil {
					t.Fatal(err)
				}
			case "parent-symlink":
				if err := os.Symlink(filepath.Dir(outside), filepath.Join(dir, rel)); err != nil {
					t.Fatal(err)
				}
				rel = "link/outside"
			case "hardlink":
				if err := os.Link(filepath.Join(dir, "inert"), filepath.Join(dir, rel)); err != nil {
					t.Fatal(err)
				}
			}
			r, err := OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if f, err := r.OpenRegular(rel); err == nil {
				f.Close()
				t.Fatalf("%s accepted", kind)
			} else if strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), outside) {
				t.Fatalf("private path leaked: %v", err)
			}
		})
	}
}

func TestConfinedRejectsFIFOWithoutBlockingAndDevice(t *testing.T) {
	dir := t.TempDir()
	if err := unix.Mkfifo(filepath.Join(dir, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	done := make(chan error, 1)
	go func() {
		f, err := r.OpenRegular("pipe")
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO open blocked")
	}
	dev, err := OpenRoot("/dev")
	if err != nil {
		t.Fatalf("device-root check unavailable: %v", err)
	}
	defer dev.Close()
	if f, err := dev.OpenRegular("null"); err == nil {
		f.Close()
		t.Fatal("device accepted")
	}
}

func TestConfinedRootRejectsSymlinkComponents(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.MkdirAll(filepath.Join(real, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filepath.Join(dir, "alias"), filepath.Join(dir, "alias", "child")} {
		if r, err := OpenRoot(name); err == nil {
			r.Close()
			t.Fatalf("symlink root accepted: %q", name)
		}
	}
}

func TestConfinedCreateIsExclusiveAndOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	var diagnostic unix.Stat_t
	if err := unix.Stat(dir, &diagnostic); err != nil {
		t.Fatal(err)
	}
	t.Logf("fixture UID=%d EUID=%d mode=%o", diagnostic.Uid, os.Geteuid(), diagnostic.Mode)
	r, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	f, err := r.CreateExclusive("output", 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("original"); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if f, err := r.CreateExclusive("output", 0600); err == nil {
		f.Close()
		t.Fatal("existing output overwritten")
	}
	got, err := os.ReadFile(filepath.Join(dir, "output"))
	if err != nil || string(got) != "original" {
		t.Fatalf("existing bytes changed %q %v", got, err)
	}
	info, err := os.Stat(filepath.Join(dir, "output"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("output permissions=%v err=%v", info, err)
	}
	if f, err := r.CreateExclusive("unsafe-mode", 0777); err == nil {
		f.Close()
		t.Fatal("unsafe output permissions accepted")
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if f, err := r.CreateExclusive("link/outside", 0600); err == nil {
		f.Close()
		t.Fatal("output escaped through parent symlink")
	}
}

func TestPublishNoReplacePreservesExistingDestination(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "staged"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "staged", "data"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "final"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "final", "data"), []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := PublishNoReplace(dir, "staged", "final"); !errors.Is(err, ErrExists) {
		t.Fatalf("existing destination=%v", err)
	}
	for name, want := range map[string]string{"staged": "new", "final": "existing"} {
		got, err := os.ReadFile(filepath.Join(dir, name, "data"))
		if err != nil || string(got) != want {
			t.Fatalf("%s changed: %q %v", name, got, err)
		}
	}
	if err := PublishNoReplace(dir, "staged", "published"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "staged")); !os.IsNotExist(err) {
		t.Fatalf("staging still present: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "published", "data")); err != nil || string(got) != "new" {
		t.Fatalf("published=%q %v", got, err)
	}
	for _, pair := range [][2]string{{"final", "final"}, {"final", "final/child"}, {"../outside", "out"}} {
		if err := PublishNoReplace(dir, pair[0], pair[1]); err == nil {
			t.Fatalf("overlap/escape accepted: %v", pair)
		}
	}
}

func TestConfinedReplacementNeverReadsOutside(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside-private-marker")
	if err := os.WriteFile(outside, []byte("outside forbidden"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "inert"), []byte("inside allowed"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := os.Symlink(outside, filepath.Join(dir, "symlink-swap")); err != nil {
				t.Error(err)
				return
			}
			if err := os.Rename(filepath.Join(dir, "symlink-swap"), filepath.Join(dir, "entry")); err != nil {
				t.Error(err)
				return
			}
			f, err := os.OpenFile(filepath.Join(dir, "regular-swap"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Error(err)
				return
			}
			_, err = f.WriteString("inside allowed")
			f.Close()
			if err != nil {
				t.Error(err)
				return
			}
			if err := os.Rename(filepath.Join(dir, "regular-swap"), filepath.Join(dir, "entry")); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for i := 0; i < 300; i++ {
		f, err := r.OpenRegular("entry")
		if err != nil {
			continue
		}
		b, err := io.ReadAll(f)
		f.Close()
		if err == nil && !bytes.Equal(b, []byte("inside allowed")) {
			close(stop)
			wg.Wait()
			t.Fatalf("replacement escaped root: %q", b)
		}
	}
	close(stop)
	wg.Wait()
}

func TestPublishNoReplaceRejectsEmptyDirectoryAndFileTargets(t *testing.T) {
	for _, kind := range []string{"directory", "file"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			stage := filepath.Join(dir, "stage")
			target := filepath.Join(dir, "target")
			if kind == "directory" {
				if err := os.Mkdir(stage, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(stage, []byte("new"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, []byte("existing"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			if err := PublishNoReplace(dir, "stage", "target"); !errors.Is(err, ErrExists) {
				t.Fatalf("existing %s target replaced: %v", kind, err)
			}
			after, err := os.Stat(target)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("destination identity changed: %v", err)
			}
			if kind == "file" {
				b, err := os.ReadFile(target)
				if err != nil || string(b) != "existing" {
					t.Fatalf("destination bytes changed: %q %v", b, err)
				}
			}
		})
	}
}

func TestPublishLateSyncFailureNeverReportsSuccessOrDeletesBytes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "stage"), []byte("recoverable"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	err = r.publishNoReplace("stage", "final", func(int) error { return unix.ENOSPC })
	if !errors.Is(err, ErrSync) {
		t.Fatalf("late durability failure=%v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "final"))
	if err != nil || string(body) != "recoverable" {
		t.Fatalf("failed publication destroyed output: %q %v", body, err)
	}
}

func TestConfinedRootDescriptorDoesNotFollowReplacementDirectory(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "root")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "inert"), []byte("original root"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := os.Rename(dir, filepath.Join(parent, "original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "inert"), []byte("replacement root"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := r.OpenRegular("inert")
	if err != nil {
		return
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil || string(b) != "original root" {
		t.Fatalf("descriptor silently switched roots: %q %v", b, err)
	}
}

func TestConfinedOutputRejectsSharedWritableDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	r, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.CheckOutput(); err == nil {
		t.Fatal("unsafe existing-output adoption would be allowed")
	}
	if f, err := r.CreateExclusive("private-output", 0600); err == nil {
		f.Close()
		t.Fatal("untrusted users can replace output entries")
	}
	if err := os.WriteFile(filepath.Join(dir, "stage"), []byte("inert"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := PublishNoReplace(dir, "stage", "final"); err == nil {
		t.Fatal("publication accepted unsafe writable parent")
	}
}

func TestConfinedOutputRejectsReplaceableAncestor(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0700)
	dir := filepath.Join(parent, "private-child")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.CheckOutput(); err == nil {
		t.Fatal("private child accepted below replaceable ancestor")
	}
}

func TestPublishRejectsUnsafeStagePermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0644, 0700, 0666} {
		t.Run(mode.String(), func(t *testing.T) {
			dir := t.TempDir()
			stage := filepath.Join(dir, "stage")
			if err := os.WriteFile(stage, []byte("inert"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(stage, mode); err != nil {
				t.Fatal(err)
			}
			if err := PublishNoReplace(dir, "stage", "final"); err == nil {
				t.Fatalf("unsafe stage permissions %o published", mode)
			}
			if _, err := os.Lstat(filepath.Join(dir, "final")); !os.IsNotExist(err) {
				t.Fatalf("unsafe output created: %v", err)
			}
		})
	}
}

func TestPublishDetectsReplacementDuringParentSync(t *testing.T) {
	for _, replace := range []string{"file", "parent"} {
		t.Run(replace, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "root")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "stage"), []byte("original bytes"), 0600); err != nil {
				t.Fatal(err)
			}
			r, err := OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			err = r.publishNoReplace("stage", "final", func(int) error {
				if replace == "file" {
					if err := os.Rename(filepath.Join(dir, "final"), filepath.Join(dir, "saved")); err != nil {
						return err
					}
					return os.WriteFile(filepath.Join(dir, "final"), []byte("replacement"), 0600)
				}
				if err := os.Rename(dir, filepath.Join(base, "saved-root")); err != nil {
					return err
				}
				return os.Mkdir(dir, 0700)
			})
			if !errors.Is(err, ErrChanged) {
				t.Fatalf("%s replacement reported as successful: %v", replace, err)
			}
		})
	}
}

func TestConfinedSparseLargeFile(t *testing.T) {
	r, err := OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	f, err := r.CreateExclusive("large-sparse", 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	const offset = int64(1<<31) + 123
	if n, err := f.WriteAt([]byte{'A'}, offset); err != nil || n != 1 {
		t.Fatalf("large-file write=%d err=%v", n, err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if info, err := f.Stat(); err != nil || info.Size() != offset+1 {
		t.Fatalf("large-file size=%v err=%v", info, err)
	}
	read, err := r.OpenRegular("large-sparse")
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	var b [1]byte
	if n, err := read.ReadAt(b[:], offset); err != nil || n != 1 || b[0] != 'A' {
		t.Fatalf("large-file read=%q n=%d err=%v", b, n, err)
	}
}

func TestConfinedDescriptorLifetimeAndLeaks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "inert"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	f, err := r.OpenRegular("inert")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		f, err := r.OpenRegular("inert")
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		if f, err := r.OpenRegular("../invalid"); err == nil {
			f.Close()
			t.Fatal("invalid open succeeded")
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) > len(before)+2 {
		t.Fatalf("descriptor leak: before=%d after=%d", len(before), len(after))
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if f, err := r.OpenRegular("inert"); !errors.Is(err, ErrClosed) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("closed root reused: %v", err)
	}
}
