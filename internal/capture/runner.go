package capture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/store"
)

// Runner archives attacker payloads: Cowrie downloads + quarantine URL fetches.
type Runner struct {
	st         *store.Store
	cfg        config.Config
	fetch      *SafeFetcher
	ttyIndexed bool // one-shot backfill flag for the sha->session table
}

func NewRunner(st *store.Store, cfg config.Config) *Runner {
	capCfg := cfg.Capture
	evidence := capCfg.EvidenceDir
	if evidence == "" {
		evidence = filepath.Join(cfg.DataDir, "evidence")
	}
	return &Runner{
		st:  st,
		cfg: cfg,
		fetch: NewSafeFetcher(
			evidence,
			capCfg.MaxBytes,
			time.Duration(capCfg.TimeoutSec)*time.Second,
			cfg.AdminIPs,
		),
	}
}

// Run processes recent command events and syncs Cowrie download artifacts.
func (r *Runner) Run(ctx context.Context) (int, error) {
	if !r.cfg.Capture.Enabled {
		return 0, nil
	}
	if err := os.MkdirAll(r.fetch.EvidenceDir, 0o700); err != nil {
		return 0, err
	}
	for _, sub := range []string{"quarantine", "cowrie", "cowrie-tty", "meta"} {
		if err := os.MkdirAll(filepath.Join(r.fetch.EvidenceDir, sub), 0o700); err != nil {
			return 0, err
		}
	}

	n := 0
	if r.cfg.Capture.QuarantineFetch {
		c, err := r.fetchFromCommands(ctx)
		if err != nil {
			return n, err
		}
		n += c
	}
	c, err := r.syncCowrieDownloads()
	if err != nil {
		return n, err
	}
	n += c
	c2, err := r.archiveFileDownloadEvents()
	if err != nil {
		return n + c2, err
	}
	n += c2
	// One-shot: backfill the sha->session index from all available
	// cowrie.json (current + rotated) log files so the cowrie-tty
	// artifacts captured before the index existed get bound to the
	// right session on the next sync pass. Cheap (line scan, only
	// looks at cowrie.log.closed) and idempotent.
	if !r.ttyIndexed {
		r.backfillCowrieTTYIndex()
		r.ttyIndexed = true
	}
	c3, err := r.syncCowrieTTY()
	return n + c3, err
}

// backfillCowrieTTYIndex scans the cowrie.json log (and rotated
// siblings) for `cowrie.log.closed` events and records the sha->session
// binding for each. Safe to call repeatedly thanks to the ON CONFLICT
// UPDATE on the index row; we gate it behind ttyIndexed so it only
// fires once per process lifetime.
func (r *Runner) backfillCowrieTTYIndex() {
	path := r.cfg.Cowrie.JSONLog
	if path == "" {
		return
	}
	candidates := []string{path}
	if matches, err := filepath.Glob(path + ".*"); err == nil {
		candidates = append(candidates, matches...)
	}
	for _, p := range candidates {
		_ = indexTTYBindingsFromFile(r.st, p)
	}
}

// syncCowrieTTY copies cowrie ttylog session recordings into the evidence
// directory and decodes each into a plain-text transcript next to the raw
// binary. Each session is registered once in the artifacts table keyed by
// the ttylog filename (which Cowrie names by sha256 of the input stream).
func (r *Runner) syncCowrieTTY() (int, error) {
	src := r.cowrieTTYDir()
	if src == "" {
		return 0, nil
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	dest := filepath.Join(r.fetch.EvidenceDir, "cowrie-tty")
	var n int
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		// Cowrie renames closed ttylogs to <sha256>; in-progress logs
		// have the form YYYYMMDD-HHMMSS-...-i.log. Skip the latter so
		// we don't ingest a half-written file that will be renamed in
		// a moment anyway.
		if !looksLikeSHA256(name) {
			continue
		}
		urlKey := "cowrie-tty:" + name
		exists, err := r.st.ArtifactURLRecorded(urlKey)
		if err != nil {
			return n, err
		}
		if exists {
			// Best-effort backfill: artifact rows recorded before
			// session binding existed have empty session_id. Try
			// to resolve and stamp it so the intel session view can
			// surface the transcript. We just LOOK UP -- no copy.
			if sid, _ := r.st.SessionIDForCowrieTTYShasum(name); sid != "" {
				_ = r.st.SetArtifactSessionByURL(urlKey, sid)
			}
			continue
		}
		srcPath := filepath.Join(src, name)
		dstRaw := filepath.Join(dest, name)
		sum, size, err := copyArtifact(srcPath, dstRaw, r.cfg.Capture.MaxBytes)
		if err != nil {
			// Don't silently skip — an operator needs to know a TTY capture was
			// dropped (e.g. oversized, or a transient I/O error), since it means
			// missing evidence.
			log.Printf("capture: skip cowrie-tty %s: %v", name, err)
			continue
		}
		// Best-effort transcript. A decode failure should not block
		// recording the raw artifact -- the dashboard can still link
		// to the binary file.
		if frames, derr := DecodeTTYLog(srcPath); derr == nil {
			transcript := RenderTranscript(frames, DefaultTranscriptOptions())
			_ = os.WriteFile(dstRaw+".txt", []byte(transcript), 0o600)
		}
		// Best-effort: resolve the session id from the
		// cowrie.log.closed event that names this shasum so the
		// intel UI can attach the transcript to the right session.
		sessionID, _ := r.st.SessionIDForCowrieTTYShasum(name)
		if err := r.st.RecordArtifact(store.Artifact{
			TS:        time.Now().UTC(),
			SessionID: sessionID,
			URL:       urlKey,
			LocalPath: dstRaw,
			SHA256:    sum,
			SizeBytes: size,
			Origin:    "cowrie_tty",
			Status:    "fetched",
		}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (r *Runner) cowrieTTYDir() string {
	home := r.cfg.Cowrie.Home
	if home == "" {
		home = filepath.Join(r.cfg.DataDir, "cowrie")
	}
	return filepath.Join(home, "var", "lib", "cowrie", "tty")
}

// looksLikeSHA256 reports whether s is a 64-character hex string.
func looksLikeSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func (r *Runner) fetchFromCommands(ctx context.Context) (int, error) {
	events, err := r.st.RecentCommandEvents(500)
	if err != nil {
		return 0, err
	}
	var n int
	for _, e := range events {
		for _, rawURL := range ExtractURLs(e.Command) {
			exists, err := r.st.ArtifactURLRecorded(rawURL)
			if err != nil || exists {
				continue
			}
			pending := store.Artifact{
				TS:        e.TS,
				SrcIP:     e.SrcIP,
				SessionID: e.SessionID,
				ActorID:   e.ActorID,
				URL:       rawURL,
				Origin:    "quarantine_fetch",
				Status:    "capturing",
			}
			if err := r.st.UpsertArtifact(pending); err != nil {
				return n, err
			}
			res, err := r.fetch.Fetch(ctx, rawURL)
			art := pending
			art.Status = "failed"
			if res != nil {
				art.LocalPath = res.LocalPath
				art.SHA256 = res.SHA256
				art.SizeBytes = res.Size
				art.Status = res.Status
				art.Detail = res.Detail
			}
			if err != nil && art.Detail == "" {
				art.Detail = err.Error()
			}
			if err := r.st.UpsertArtifact(art); err != nil {
				return n, err
			}
			if art.Status == "fetched" {
				n++
			}
		}
	}
	return n, nil
}

func (r *Runner) syncCowrieDownloads() (int, error) {
	dl := r.cowrieDownloadsDir()
	if dl == "" {
		return 0, nil
	}
	entries, err := os.ReadDir(dl)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	dest := filepath.Join(r.fetch.EvidenceDir, "cowrie")
	var n int
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		// Dedup BEFORE the expensive copy+hash: urlKey is derived from the
		// filename, which we already have, so an already-archived download
		// can be skipped without re-reading and re-hashing it every tick.
		urlKey := "cowrie-download:" + ent.Name()
		exists, err := r.st.ArtifactURLRecorded(urlKey)
		if err != nil || exists {
			continue
		}
		src := filepath.Join(dl, ent.Name())
		sum, size, err := copyArtifact(src, filepath.Join(dest, ent.Name()), r.cfg.Capture.MaxBytes)
		if err != nil {
			// Surface skips (e.g. oversized download rejected by the size cap)
			// instead of silently dropping the artifact.
			log.Printf("capture: skip cowrie download %s: %v", ent.Name(), err)
			continue
		}
		if err := r.st.RecordArtifact(store.Artifact{
			TS:        time.Now().UTC(),
			URL:       urlKey,
			LocalPath: filepath.Join(dest, ent.Name()),
			SHA256:    sum,
			SizeBytes: size,
			Origin:    "cowrie_download",
			Status:    "fetched",
		}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (r *Runner) archiveFileDownloadEvents() (int, error) {
	events, err := r.st.RecentFileDownloadEvents(200)
	if err != nil {
		return 0, err
	}
	var n int
	for _, e := range events {
		if e.Filename == "" {
			continue
		}
		// e.Filename comes from cowrie JSON (attacker-influenced telemetry).
		// Always resolve it relative to the cowrie downloads dir using only
		// the basename, even when the recorded value is absolute — otherwise a
		// crafted absolute path (e.g. /etc/shadow) would be copied into the
		// evidence dir and could later be shipped to MalwareBazaar.
		// Dedup BEFORE the expensive copy+hash: urlKey needs nothing from the
		// file, and without this the 200 newest downloads were re-read,
		// re-hashed, and rewritten on every 5s tick (GB/min of write
		// amplification). Mirrors syncCowrieDownloads.
		urlKey := e.Command
		if urlKey == "" {
			urlKey = "cowrie-event:" + fmt.Sprint(e.ID)
		}
		exists, err := r.st.ArtifactURLRecorded(urlKey)
		if err != nil || exists {
			continue
		}
		src := filepath.Join(r.cowrieDownloadsDir(), filepath.Base(e.Filename))
		if _, err := os.Stat(src); err != nil {
			continue
		}
		base := e.SHA256
		if base == "" {
			base = filepath.Base(src)
		}
		dest := filepath.Join(r.fetch.EvidenceDir, "cowrie", base)
		sum, size, err := copyArtifact(src, dest, r.cfg.Capture.MaxBytes)
		if err != nil {
			// Surface skips (e.g. oversized file rejected by the size cap)
			// instead of silently dropping the artifact.
			log.Printf("capture: skip cowrie file_download %s: %v", base, err)
			continue
		}
		if err := r.st.RecordArtifact(store.Artifact{
			TS:        e.TS,
			SrcIP:     e.SrcIP,
			SessionID: e.SessionID,
			ActorID:   e.ActorID,
			URL:       urlKey,
			LocalPath: dest,
			SHA256:    sum,
			SizeBytes: size,
			Origin:    "cowrie_file_download",
			Status:    "fetched",
		}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (r *Runner) cowrieDownloadsDir() string {
	home := r.cfg.Cowrie.Home
	if home == "" {
		home = filepath.Join(r.cfg.DataDir, "cowrie")
	}
	return filepath.Join(home, "var", "lib", "cowrie", "downloads")
}

// PurgeOldSourceFiles deletes regular files older than retentionDays from
// Cowrie's own downloads and ttylog directories. Cowrie never cleans these and
// the store-level purge only deletes DB rows, so without this: (a) the dirs
// grow without bound, and (b) once a tracked artifact's row is purged, the
// surviving source file makes the next 5s tick re-copy and re-record it (the
// "resurrection" that permanently defeats retention). retentionDays <= 0
// disables purging, matching Store.MaintenancePurge.
func (r *Runner) PurgeOldSourceFiles(retentionDays int) int {
	if retentionDays <= 0 {
		return 0
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	removed := 0
	for _, dir := range []string{r.cowrieDownloadsDir(), r.cowrieTTYDir()} {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			if ent.IsDir() || ent.Type()&os.ModeSymlink != 0 {
				continue
			}
			info, err := ent.Info()
			if err != nil || !info.Mode().IsRegular() || !info.ModTime().Before(cutoff) {
				continue
			}
			if err := os.Remove(filepath.Join(dir, ent.Name())); err == nil {
				removed++
			}
		}
	}
	return removed
}

// copyArtifact copies src->dest, hashing as it goes. maxBytes caps the copy so
// an attacker-controlled cowrie download / TTY log can't exhaust disk; a source
// exceeding the cap is rejected (not silently truncated, which would corrupt the
// sha). maxBytes <= 0 means unlimited (caller opted out).
func copyArtifact(src, dest string, maxBytes int64) (sha string, size int64, err error) {
	in, err := os.Open(src)
	if err != nil {
		return "", 0, err
	}
	defer in.Close()
	if maxBytes > 0 {
		if fi, statErr := in.Stat(); statErr == nil && fi.Size() > maxBytes {
			return "", 0, fmt.Errorf("artifact %s exceeds max size (%d > %d bytes)", filepath.Base(src), fi.Size(), maxBytes)
		}
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return "", 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".copy-*")
	if err != nil {
		return "", 0, err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	h := sha256.New()
	// Read at most maxBytes+1: if we get more than maxBytes the source grew
	// between Stat and read (or is a growing file) — reject rather than truncate.
	reader := io.Reader(in)
	if maxBytes > 0 {
		reader = io.LimitReader(in, maxBytes+1)
	}
	n, err := io.Copy(tmp, io.TeeReader(reader, h))
	if err != nil {
		return "", 0, err
	}
	if maxBytes > 0 && n > maxBytes {
		return "", 0, fmt.Errorf("artifact %s exceeds max size (>%d bytes)", filepath.Base(src), maxBytes)
	}
	if err := tmp.Close(); err != nil {
		return "", 0, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if err := os.Rename(tmpPath, dest); err != nil {
		if fileExists(dest) {
			_ = os.Remove(tmpPath)
		} else {
			return "", 0, err
		}
	}
	_ = os.Chmod(dest, 0o600)
	return sum, n, nil
}
