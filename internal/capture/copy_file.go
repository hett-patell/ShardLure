package capture

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"github.com/networkshard/shardlure/internal/safefile"
)

// copyArtifact preserves the older callers' API, with confined descriptor
// access and no-replace publication. Existing bytes must match exactly.
func copyArtifact(src, dest string, maxBytes int64) (string, int64, error) {
	return copyArtifactContext(context.Background(), src, dest, maxBytes)
}

func copyArtifactContext(ctx context.Context, src, dest string, maxBytes int64) (string, int64, error) {
	return copyArtifactExpected(ctx, src, dest, maxBytes, "")
}

func copyArtifactExpected(ctx context.Context, src, dest string, maxBytes int64, expected string) (string, int64, error) {
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	input, err := safefile.OpenRoot(filepath.Dir(src))
	if err != nil {
		return "", 0, err
	}
	defer input.Close()
	in, err := input.OpenRegular(filepath.Base(src))
	if err != nil {
		return "", 0, err
	}
	defer in.Close()
	before, err := in.Stat()
	if err != nil {
		return "", 0, safefile.ErrIO
	}
	if before.Size() == 0 {
		return "", 0, ErrEmptyArtifact
	}
	if maxBytes > 0 && before.Size() > maxBytes {
		return "", 0, errFileTooLarge
	}
	output, err := safefile.EnsureDirectory(filepath.Dir(dest))
	if err != nil {
		return "", 0, err
	}
	defer output.Close()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", 0, safefile.ErrIO
	}
	tempName := ".copy-" + hex.EncodeToString(nonce[:])
	tmp, err := output.CreateExclusive(tempName, 0600)
	if err != nil {
		return "", 0, err
	}
	created, err := tmp.Stat()
	if err != nil {
		tmp.Close()
		return "", 0, safefile.ErrIO
	}
	defer func() { tmp.Close(); _ = output.RemoveCreated(tempName, created) }()
	h := sha256.New()
	n, err := copyCaptureBytes(ctx, io.MultiWriter(tmp, h), in, maxBytes)
	if err != nil {
		return "", 0, err
	}
	after, err := in.Stat()
	if err != nil || !captureFileUnchanged(before, after) {
		return "", 0, safefile.ErrChanged
	}
	current, err := input.OpenRegular(filepath.Base(src))
	if err != nil {
		return "", 0, safefile.ErrChanged
	}
	info, statErr := current.Stat()
	current.Close()
	if statErr != nil || !captureFileUnchanged(before, info) {
		return "", 0, safefile.ErrChanged
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if expected != "" && !strings.EqualFold(sum, expected) {
		return "", 0, errFileHashMismatch
	}
	if err := tmp.Sync(); err != nil {
		return "", 0, safefile.ErrSync
	}
	if err := tmp.Close(); err != nil {
		return "", 0, safefile.ErrIO
	}
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	err = safefile.PublishNoReplace(filepath.Dir(dest), tempName, filepath.Base(dest))
	if errors.Is(err, safefile.ErrExists) {
		existing, openErr := output.OpenRegular(filepath.Base(dest))
		if openErr != nil {
			return "", 0, openErr
		}
		oldHash, oldSize, hashErr := hashCaptureFile(ctx, existing, maxBytes)
		existing.Close()
		if hashErr != nil {
			return "", 0, hashErr
		}
		if oldHash != sum || oldSize != n {
			return "", 0, errFileHashMismatch
		}
		err = nil
	}
	if err != nil {
		return "", 0, err
	}
	return sum, n, nil
}
