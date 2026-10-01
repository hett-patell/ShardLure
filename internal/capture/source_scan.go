package capture

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"

	"github.com/networkshard/shardlure/internal/safefile"
	"github.com/networkshard/shardlure/internal/store"
)

// errSpacePaused stops a directory pass when the free-space gate closes
// partway through. It is not a failure: the remaining entries are left
// unrecorded (or, for a TTY transcript, unpublished) and the next pass after
// space returns picks them up.
var errSpacePaused = errors.New("capture paused: evidence free space below floor")

func (r *Runner) syncCowrieDownloads() (int, error) {
	return r.syncCowrieSources(context.Background(), false)
}
func (r *Runner) syncCowrieTTY() (int, error) { return r.syncCowrieSources(context.Background(), true) }

// Directory scans keep only one bounded batch. Durable rows, not an unbounded
// process memo, decide whether an entry has already been archived.
func (r *Runner) syncCowrieSources(ctx context.Context, tty bool) (int, error) {
	dir, prefix, origin, sub := r.cowrieDownloadsDir(), "cowrie-download:", "cowrie_download", "cowrie"
	if tty {
		dir, prefix, origin, sub = r.cowrieTTYDir(), "cowrie-tty:", "cowrie_tty", "cowrie-tty"
	}
	source, err := safefile.OpenRoot(dir)
	if errors.Is(err, safefile.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, safeCaptureError(err, "capture source directory unavailable")
	}
	defer source.Close()
	output := filepath.Join(r.fetch.EvidenceDir, sub)
	if captureRootsOverlap(dir, output) {
		return 0, safeCaptureError(nil, "capture roots overlap")
	}
	dest, err := safefile.EnsureDirectory(output)
	if err != nil {
		return 0, safeCaptureError(err, "capture output directory unavailable")
	}
	defer dest.Close()
	n := 0
	var firstErr error
	for {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		names, readErr := source.ReadNames(64)
		for _, name := range names {
			if !looksLikeSHA256(name) {
				continue
			}
			key := prefix + name
			err := r.st.WithCaptureFileAccess(ctx, func() error {
				exists, session, err := r.st.ArtifactCaptureRecord(key)
				if err != nil {
					return safeCaptureError(err, "capture ledger lookup failed")
				}
				f, err := source.OpenRegular(name)
				if err != nil {
					return safeCaptureError(err, "capture source access failed")
				}
				info, err := f.Stat()
				f.Close()
				if err != nil {
					return safeCaptureError(err, "capture source metadata failed")
				}
				if exists {
					if err := r.st.TouchArtifactTS(key, info.ModTime().UTC()); err != nil {
						return safeCaptureError(err, "capture observation recording failed")
					}
					if tty && session == "" {
						sid, err := r.st.SessionIDForCowrieTTYShasum(name)
						if err != nil {
							return safeCaptureError(err, "capture session lookup failed")
						}
						if sid != "" {
							if err := r.st.SetArtifactSessionByURL(key, sid); err != nil {
								return safeCaptureError(err, "capture session recording failed")
							}
						}
					}
					if tty {
						return ensureTTYTranscript(ctx, dest, name, info.Size(), r.space)
					}
					return nil
				}
				// Re-checked per file, not just per pass: the first pass after
				// a pause ends would otherwise copy the whole backlog Cowrie
				// accumulated meanwhile (up to max_bytes each) and could drive
				// the disk straight back to 100%.
				if !r.space.Allow() {
					return errSpacePaused
				}
				path := filepath.Join(output, name)
				expected := ""
				if !tty {
					expected = name
				}
				sum, size, err := copyArtifactExpected(ctx, filepath.Join(dir, name), path, r.cfg.Capture.MaxBytes, expected)
				status := "fetched"
				if errors.Is(err, ErrEmptyArtifact) {
					status = "empty"
					path = ""
					err = nil
				}
				if err != nil {
					return safeCaptureError(err, "capture file copy failed")
				}
				if tty {
					sid, err := r.st.SessionIDForCowrieTTYShasum(name)
					if err != nil {
						return safeCaptureError(err, "capture session lookup failed")
					}
					session = sid
				}
				if err := r.st.RecordArtifactObservation(store.Artifact{TS: info.ModTime().UTC(), URL: key, Origin: origin, Status: status, LocalPath: path, SHA256: sum, SizeBytes: size, SessionID: session}); err != nil {
					return safeCaptureError(err, "capture artifact recording failed")
				}
				if status == "fetched" {
					n++
				}
				if tty && status == "fetched" && size <= 8<<20 {
					return ensureTTYTranscript(ctx, dest, name, size, r.space)
				}
				return nil
			})
			if errors.Is(err, errSpacePaused) {
				return n, firstErr
			}
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return n, safeCaptureError(readErr, "capture directory enumeration failed")
		}
	}
	return n, firstErr
}

// A derivative is optional evidence, but a failed write must be retried even
// after the raw artifact row exists. Only atomically completed files get their
// final name; a failed partial write can never be mistaken for completion.
// space is consulted only once a transcript actually needs writing, so an
// already-published transcript never stops a paused pass.
func ensureTTYTranscript(ctx context.Context, dest *safefile.Root, name string, size int64, space *SpaceGate) error {
	if size <= 0 || size > 8<<20 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	existing, err := dest.OpenRegular(name + ".txt")
	if err == nil {
		return existing.Close()
	}
	if !errors.Is(err, safefile.ErrNotExist) {
		return safeCaptureError(err, "capture transcript access failed")
	}
	raw, err := dest.OpenRegular(name)
	if err != nil {
		return safeCaptureError(err, "capture transcript source failed")
	}
	frames, decodeErr := decodeTTYReader(io.LimitReader(raw, 8<<20))
	raw.Close()
	if decodeErr != nil {
		return safeCaptureError(decodeErr, "capture transcript decode failed")
	}
	if !space.Allow() {
		return errSpacePaused
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return safeCaptureError(err, "capture transcript creation failed")
	}
	tempName := ".transcript-" + hex.EncodeToString(nonce[:])
	tmp, err := dest.CreateExclusive(tempName, 0600)
	if err != nil {
		return safeCaptureError(err, "capture transcript creation failed")
	}
	created, err := tmp.Stat()
	if err != nil {
		tmp.Close()
		return safeCaptureError(err, "capture transcript metadata failed")
	}
	defer func() { tmp.Close(); _ = dest.RemoveCreated(tempName, created) }()
	if _, err := tmp.WriteString(RenderTranscript(frames, DefaultTranscriptOptions())); err != nil {
		return safeCaptureError(err, "capture transcript persistence failed")
	}
	if err := tmp.Sync(); err != nil {
		return safeCaptureError(err, "capture transcript persistence failed")
	}
	if err := tmp.Close(); err != nil {
		return safeCaptureError(err, "capture transcript persistence failed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := dest.PublishNoReplace(tempName, name+".txt"); err != nil {
		return safeCaptureError(err, "capture transcript publication failed")
	}
	return nil
}
