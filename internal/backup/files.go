package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/networkshard/shardlure/internal/safefile"
)

type fileOperations struct {
	openFile func(*safefile.Root, string) (*os.File, error)
	copy     func(context.Context, string, io.Writer, io.Reader, int64) (int64, error)
	syncFile func(*os.File) error
	syncDir  func(*safefile.Root) error
	publish  func(*safefile.Root, string, string) error
	space    func(*safefile.Root) (uint64, error)
}

func nativeOperations() fileOperations {
	return fileOperations{
		openFile: func(root *safefile.Root, name string) (*os.File, error) { return root.OpenRegular(name) },
		copy: func(ctx context.Context, _ string, w io.Writer, r io.Reader, n int64) (int64, error) {
			return copyN(ctx, w, r, n)
		},
		syncFile: func(f *os.File) error { return f.Sync() }, syncDir: func(r *safefile.Root) error { return r.Sync() },
		publish: func(r *safefile.Root, a, b string) error { return r.PublishNoReplace(a, b) }, space: func(r *safefile.Root) (uint64, error) { return r.AvailableBytes() },
	}
}

func copyN(ctx context.Context, out io.Writer, in io.Reader, remaining int64) (int64, error) {
	var total int64
	buf := make([]byte, 64<<10)
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := in.Read(buf[:min(int64(len(buf)), remaining)])
		if n > 0 {
			written, writeErr := out.Write(buf[:n])
			total += int64(written)
			remaining -= int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF && remaining == 0 {
				return total, nil
			}
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}

func hashOpenFile(ctx context.Context, f *os.File, n int64) (string, error) {
	h := sha256.New()
	if _, err := copyN(ctx, h, io.NewSectionReader(f, 0, n), n); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func hashEntry(ctx context.Context, root *safefile.Root, name, role string) (Entry, error) {
	return hashEntryWithOperations(ctx, root, name, role, nativeOperations())
}
func hashEntryWithOperations(ctx context.Context, root *safefile.Root, name, role string, ops fileOperations) (Entry, error) {
	f, err := ops.openFile(root, name)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return Entry{}, err
	}
	sum, err := hashOpenFile(ctx, f, before.Size())
	if err != nil {
		return Entry{}, err
	}
	after, err := f.Stat()
	if err != nil || !safefile.SameFileState(before, after) {
		return Entry{}, ErrSourceChanged
	}
	named, err := root.Stat(name)
	if err != nil || !safefile.SameFileState(after, named) {
		return Entry{}, ErrSourceChanged
	}
	return Entry{Path: name, Role: role, SHA256: sum, Bytes: before.Size()}, nil
}

// walkRoot keeps one 64-name batch per level, pins every directory, and never
// opens regular contents merely to classify an entry. The depth bound also
// bounds simultaneously open directory descriptors for adversarial trees.
func walkRoot(ctx context.Context, root *safefile.Root, prefix string, depth int, visit func(string, fs.FileInfo) error) error {
	if depth > 64 {
		return ErrManifestLimit
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		names, readErr := root.ReadNames(64)
		for _, name := range names {
			rel := path.Join(prefix, name)
			if !relativeName(rel) {
				return ErrUnsafePath
			}
			info, err := root.Stat(name)
			if err != nil {
				return err
			}
			if err := visit(rel, info); err != nil {
				return err
			}
			if info.IsDir() {
				child, err := root.OpenDirectory(name)
				if err != nil {
					return err
				}
				err = walkRoot(ctx, child, rel, depth+1, visit)
				child.Close()
				if err != nil {
					return err
				}
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func ensureRelativeDirectory(root *safefile.Root, name string) (*safefile.Root, error) {
	if name == "." {
		return nil, ErrUnsafePath
	}
	if !relativeName(name) {
		return nil, ErrUnsafePath
	}
	current := root
	owned := false
	for _, component := range strings.Split(name, "/") {
		next, err := current.OpenDirectory(component)
		if errors.Is(err, safefile.ErrNotExist) {
			next, err = current.CreateDirectory(component)
		}
		if owned {
			current.Close()
		}
		if err != nil {
			return nil, err
		}
		if err := next.CheckOutput(); err != nil {
			next.Close()
			return nil, err
		}
		current = next
		owned = true
	}
	return current, nil
}

func writePrivate(root *safefile.Root, name string, b []byte, ops fileOperations) error {
	f, err := root.CreateExclusive(name, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(b)
	syncErr := ops.syncFile(f)
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	return ops.syncDir(root)
}

func within(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func pathsOverlap(a, b string) bool {
	if within(a, b) || within(b, a) {
		return true
	}
	// Also reject existing inode aliases (including bind-mounted root aliases).
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		info, err := os.Lstat(pair[0])
		if err != nil {
			continue
		}
		for p := pair[1]; ; p = filepath.Dir(p) {
			other, err := os.Lstat(p)
			if err == nil && os.SameFile(info, other) {
				return true
			}
			if p == filepath.Dir(p) {
				break
			}
		}
	}
	return false
}

func mapEvidencePath(root, name string) (string, error) {
	absolute, err := filepath.Abs(name)
	if err != nil || !within(root, absolute) {
		return "", ErrUnsafePath
	}
	rel, err := filepath.Rel(root, absolute)
	if err != nil || !relativeName(filepath.ToSlash(rel)) {
		return "", ErrUnsafePath
	}
	return "files/evidence/" + filepath.ToSlash(rel), nil
}
