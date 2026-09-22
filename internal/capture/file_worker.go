package capture

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/networkshard/shardlure/internal/safefile"
	"github.com/networkshard/shardlure/internal/store"
)

type FileWorker struct {
	st                          *store.Store
	downloadsRoot, evidenceRoot string
	maxBytes                    int64
	now                         func() time.Time
	mu                          sync.Mutex
}

func NewFileWorker(st *store.Store, downloadsRoot, evidenceRoot string, maxBytes int64) *FileWorker {
	return &FileWorker{st: st, downloadsRoot: downloadsRoot, evidenceRoot: evidenceRoot, maxBytes: maxBytes, now: time.Now}
}

func (w *FileWorker) Run(ctx context.Context) {
	for ctx.Err() == nil {
		n, err := w.tick(ctx)
		if err != nil && ctx.Err() == nil {
			log.Print("file-capture: operation failed")
		}
		gap := time.Second
		if n > 0 {
			gap = 10 * time.Millisecond
		}
		timer := time.NewTimer(gap)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func captureRootsOverlap(source, target string) bool {
	a, err := filepath.Abs(source)
	if err != nil {
		return true
	}
	b, err := filepath.Abs(target)
	if err != nil {
		return true
	}
	within := func(parent, child string) bool {
		rel, err := filepath.Rel(parent, child)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	if within(a, b) || within(b, a) {
		return true
	}
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		info, err := os.Stat(pair[0])
		if err != nil {
			continue
		}
		for p := pair[1]; ; p = filepath.Dir(p) {
			other, err := os.Stat(p)
			if err == nil && os.SameFile(info, other) {
				return true
			}
			if filepath.Dir(p) == p {
				break
			}
		}
	}
	return false
}

func (w *FileWorker) tick(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if !w.mu.TryLock() {
		return 0, nil
	}
	defer w.mu.Unlock()
	output := filepath.Join(w.evidenceRoot, "cowrie")
	if captureRootsOverlap(w.downloadsRoot, output) {
		return 0, safeCaptureError(nil, "file capture roots overlap")
	}
	now := w.now().UTC()
	jobs, err := w.st.ClaimFileCaptures(ctx, now, 1, 2*time.Minute)
	if err != nil {
		return 0, safeCaptureError(err, "file capture claim failed")
	}
	if len(jobs) == 0 {
		return 0, nil
	}
	job := jobs[0]
	work, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	archived, err := w.archive(work, job, output)
	if err == nil {
		return 1, nil
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if archived {
		return 0, safeCaptureError(err, "file capture result recording failed")
	} // publication happened; leave bytes for retry/adoption
	reason, status := store.FileCaptureReadFailure, store.FileCaptureRetry
	switch {
	case errors.Is(err, safefile.ErrNotExist):
		reason = store.FileCaptureMissingSource
	case errors.Is(err, ErrEmptyArtifact):
		reason, status = store.FileCaptureEmpty, store.FileCaptureRejected
	case errors.Is(err, errFileTooLarge):
		reason, status = store.FileCaptureTooLarge, store.FileCaptureRejected
	case errors.Is(err, errFileHashMismatch):
		reason, status = store.FileCaptureHashMismatch, store.FileCaptureRejected
	case errors.Is(err, safefile.ErrChanged):
		reason = store.FileCaptureSourceChanged
	case errors.Is(err, safefile.ErrUnsafePath), errors.Is(err, safefile.ErrNotRegular):
		reason, status = store.FileCaptureInvalidSource, store.FileCaptureRejected
	case errors.Is(err, safefile.ErrPermission), errors.Is(err, safefile.ErrSync), errors.Is(err, safefile.ErrNoSpace):
		reason = store.FileCaptureWriteFailure
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		reason = store.FileCaptureCanceled
	}
	if err := w.st.CompleteFileCapture(ctx, job, w.now().UTC(), store.FileCaptureResult{Status: status, Reason: reason}); err != nil {
		return 0, safeCaptureError(err, "file capture result recording failed")
	}
	return 0, nil
}

var errFileTooLarge = errors.New("file capture: size limit exceeded")
var errFileHashMismatch = errors.New("file capture: hash mismatch")

func hashCaptureFile(ctx context.Context, f *os.File, maxBytes int64) (string, int64, error) {
	before, err := f.Stat()
	if err != nil {
		return "", 0, safefile.ErrIO
	}
	if before.Size() == 0 {
		return "", 0, ErrEmptyArtifact
	}
	if maxBytes > 0 && before.Size() > maxBytes {
		return "", 0, errFileTooLarge
	}
	h := sha256.New()
	n, err := copyCaptureBytes(ctx, h, f, maxBytes)
	if err != nil {
		return "", 0, err
	}
	after, err := f.Stat()
	if err != nil || !captureFileUnchanged(before, after) {
		return "", 0, safefile.ErrChanged
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func captureFileUnchanged(before, after os.FileInfo) bool {
	return safefile.SameFileState(before, after)
}

func copyCaptureBytes(ctx context.Context, out io.Writer, in io.Reader, maxBytes int64) (int64, error) {
	buffer := make([]byte, 32<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, readErr := in.Read(buffer)
		if n > 0 {
			if maxBytes > 0 && total+int64(n) > maxBytes {
				return total, errFileTooLarge
			}
			written, err := out.Write(buffer[:n])
			total += int64(written)
			if err != nil {
				return total, safefile.ErrIO
			}
			if written != n {
				return total, safefile.ErrIO
			}
		}
		if readErr == io.EOF {
			return total, nil
		}
		if readErr != nil {
			return total, safefile.ErrIO
		}
	}
}

func verifyCaptureBlob(ctx context.Context, root *safefile.Root, name string, maxBytes int64) (int64, error) {
	if err := root.CheckOutput(); err != nil {
		return 0, err
	}
	f, err := root.OpenRegular(name)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sum, n, err := hashCaptureFile(ctx, f, maxBytes)
	if err != nil {
		return 0, err
	}
	if sum != name {
		return 0, errFileHashMismatch
	}
	return n, nil
}

func (w *FileWorker) archive(ctx context.Context, job store.FileCaptureJob, output string) (bool, error) {
	dest, err := safefile.EnsureDirectory(output)
	if err != nil {
		return false, err
	}
	defer dest.Close()
	if job.ExpectedSHA256 != "" {
		adopted := false
		err := w.st.WithCaptureFileAccess(ctx, func() error {
			n, err := verifyCaptureBlob(ctx, dest, job.ExpectedSHA256, w.maxBytes)
			if errors.Is(err, safefile.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			adopted = true
			return w.st.CompleteFileCapture(ctx, job, w.now().UTC(), store.FileCaptureResult{Status: store.FileCaptureArchived, LocalPath: filepath.Join(output, job.ExpectedSHA256), SHA256: job.ExpectedSHA256, SizeBytes: n})
		})
		if err != nil || adopted {
			return adopted, err
		}
	}
	source, err := safefile.OpenRoot(w.downloadsRoot)
	if err != nil {
		return false, err
	}
	defer source.Close()
	in, err := source.OpenRegular(job.SourceName)
	if err != nil {
		return false, err
	}
	defer in.Close()
	before, err := in.Stat()
	if err != nil {
		return false, safefile.ErrIO
	}
	if before.Size() == 0 {
		return false, ErrEmptyArtifact
	}
	if w.maxBytes > 0 && before.Size() > w.maxBytes {
		return false, errFileTooLarge
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return false, safefile.ErrIO
	}
	tempName := ".capture-" + hex.EncodeToString(random[:])
	tmp, err := dest.CreateExclusive(tempName, 0600)
	if err != nil {
		return false, err
	}
	created, err := tmp.Stat()
	if err != nil {
		tmp.Close()
		return false, safefile.ErrIO
	}
	defer func() { tmp.Close(); _ = dest.RemoveCreated(tempName, created) }()
	h := sha256.New()
	n, err := copyCaptureBytes(ctx, io.MultiWriter(tmp, h), in, w.maxBytes)
	if err != nil {
		return false, err
	}
	after, err := in.Stat()
	if err != nil || !captureFileUnchanged(before, after) {
		return false, safefile.ErrChanged
	}
	check, err := source.OpenRegular(job.SourceName)
	if err != nil {
		return false, safefile.ErrChanged
	}
	current, statErr := check.Stat()
	check.Close()
	if statErr != nil || !captureFileUnchanged(before, current) {
		return false, safefile.ErrChanged
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if job.ExpectedSHA256 != "" && sum != job.ExpectedSHA256 {
		return false, errFileHashMismatch
	}
	if err := tmp.Sync(); err != nil {
		return false, safefile.ErrSync
	}
	if err := tmp.Close(); err != nil {
		return false, safefile.ErrIO
	}
	published := false
	err = w.st.WithCaptureFileAccess(ctx, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := safefile.PublishNoReplace(output, tempName, sum)
		if errors.Is(err, safefile.ErrExists) {
			var size int64
			size, err = verifyCaptureBlob(ctx, dest, sum, w.maxBytes)
			if err == nil && size != n {
				err = errFileHashMismatch
			}
		}
		if err != nil {
			return err
		}
		published = true
		return w.st.CompleteFileCapture(ctx, job, w.now().UTC(), store.FileCaptureResult{Status: store.FileCaptureArchived, LocalPath: filepath.Join(output, sum), SHA256: sum, SizeBytes: n})
	})
	return published, err
}
