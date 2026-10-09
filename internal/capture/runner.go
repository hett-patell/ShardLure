package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/safefile"
	"github.com/networkshard/shardlure/internal/store"
)

// Runner archives attacker payloads: Cowrie downloads + quarantine URL fetches.
type Runner struct {
	st         *store.Store
	cfg        config.Config
	fetch      *SafeFetcher
	ttyIndexed bool // one-shot backfill flag for the sha->session table
	space      *SpaceGate
	hosts      *HostGate
	// harvestErr is the last harvest failure's text, so a failure that
	// repeats every 5 s run is logged once per streak, and recovery once.
	harvestErr string
	// harvestOutside is set while recorded payload paths fall outside the
	// evidence root, so that is logged once per streak, and recovery once.
	harvestOutside bool
}

func NewRunner(st *store.Store, cfg config.Config) *Runner {
	capCfg := cfg.Capture
	evidence := capCfg.EvidenceDir
	if evidence == "" {
		evidence = filepath.Join(cfg.DataDir, "evidence")
	}
	st.SetCaptureRetentionPolicy(store.CaptureRetentionPolicy{CommandsEnabled: cfg.Capture.Enabled && cfg.Capture.QuarantineFetch, FilesEnabled: cfg.Capture.Enabled, EvidenceRoot: evidence})
	return &Runner{
		st:  st,
		cfg: cfg,
		fetch: NewSafeFetcher(
			evidence,
			capCfg.MaxBytes,
			time.Duration(capCfg.TimeoutSec)*time.Second,
			cfg.AdminIPs,
		),
		space: NewSpaceGate(evidence, uint64(capCfg.MinFreeBytes)),
		hosts: NewHostGate(),
	}
}

// SpaceGate is the runner's free-space guard, shared with the URL and file
// workers so one pause covers every capture write path.
func (r *Runner) SpaceGate() *SpaceGate { return r.space }

// HostGate is the runner's per-host fetch gate, shared by the URL capture
// worker and the re-fetch worker so the two never fetch from one attacker
// server at the same time.
func (r *Runner) HostGate() *HostGate { return r.hosts }

// urlKeyDone reports whether key is already recorded in the DB.
// The DB is the sole source of truth — the UNIQUE index on url makes
// this an O(log n) lookup that is fast enough for steady-state ticks.
func (r *Runner) urlKeyDone(key string) (bool, error) {
	return r.st.ArtifactURLRecorded(key)
}

// Run processes recent command events and syncs Cowrie download artifacts.
func (r *Runner) Run(ctx context.Context) (int, error) {
	if !r.cfg.Capture.Enabled {
		return 0, nil
	}
	for _, source := range []string{r.cowrieDownloadsDir(), r.cowrieTTYDir()} {
		if captureRootsOverlap(source, r.fetch.EvidenceDir) {
			return 0, safeCaptureError(nil, "capture roots overlap")
		}
	}
	for _, sub := range []string{"quarantine", "cowrie", "cowrie-tty", "meta"} {
		root, err := safefile.EnsureDirectory(filepath.Join(r.fetch.EvidenceDir, sub))
		if err != nil {
			return 0, safeCaptureError(err, "capture output initialization failed")
		}
		if err := root.Close(); err != nil {
			return 0, safeCaptureError(err, "capture output initialization failed")
		}
	}

	n := 0
	if r.cfg.Capture.QuarantineFetch {
		c, err := r.fetchFromCommands(ctx)
		if err != nil {
			return n, err
		}
		n += c
		// Second-stage harvesting reads fetched scripts as text and only
		// queues rows (the ArtifactWorker fetches them later), so like
		// discovery it runs while the space gate is paused.
		// An unreadable source is skipped (logged by id and hash); only an
		// unusable evidence root or a store error keeps the cursor. Either
		// way a failed harvest must not stop the Cowrie syncs below, so only
		// cancellation ends Run.
		if r.cfg.Capture.HarvestScripts {
			_, err := r.harvestScripts(ctx)
			if ctxErr := ctx.Err(); ctxErr != nil {
				return n, ctxErr
			}
			r.reportHarvestError(err)
		}
	}
	// Discovery only writes database rows, so it keeps running while paused;
	// the directory syncs copy bytes into evidence and wait for space.
	if r.space.Allow() {
		c, err := r.syncCowrieSources(ctx, false)
		if err != nil {
			return n, err
		}
		n += c
	}
	if _, err := r.st.DiscoverFileCaptures(ctx, 2000); err != nil {
		return n, err
	}
	// Bounded catch-up for uploads the downloads-only cursor passed; a no-op
	// read once it reaches its ceiling.
	if _, err := r.st.BackfillUploadCaptures(ctx, 2000); err != nil {
		return n, err
	}
	// One-shot: backfill the sha->session index from all available
	// cowrie.json (current + rotated) log files so the cowrie-tty
	// artifacts captured before the index existed get bound to the
	// right session on the next sync pass. Cheap (line scan, only
	// looks at cowrie.log.closed) and idempotent.
	if !r.ttyIndexed {
		if err := r.backfillCowrieTTYIndexContext(ctx); err != nil {
			return n, err
		}
		r.ttyIndexed = true
	}
	if !r.space.Allow() {
		return n, nil
	}
	c3, err := r.syncCowrieSources(ctx, true)
	return n + c3, err
}

// reportHarvestError logs a harvest failure once per streak, by its safe
// category text only (never a path or URL), and once on recovery.
func (r *Runner) reportHarvestError(err error) {
	switch {
	case err != nil:
		msg := safeCaptureError(err, "capture harvest failed").detail
		if msg != r.harvestErr {
			log.Printf("capture: second-stage harvest failed: %s; retrying every run", msg)
			r.harvestErr = msg
		}
	case r.harvestErr != "":
		log.Print("capture: second-stage harvest recovered")
		r.harvestErr = ""
	}
}

// backfillCowrieTTYIndex scans the cowrie.json log (and rotated
// siblings) for `cowrie.log.closed` events and records the sha->session
// binding for each. Safe to call repeatedly thanks to the ON CONFLICT
// UPDATE on the index row; we gate it behind ttyIndexed so it only
// fires once per process lifetime.
func (r *Runner) backfillCowrieTTYIndexContext(ctx context.Context) error {
	path := r.cfg.Cowrie.JSONLog
	if path == "" {
		return nil
	}
	root, err := safefile.OpenRoot(filepath.Dir(path))
	if errors.Is(err, safefile.ErrNotExist) {
		return nil
	}
	if err != nil {
		return safeCaptureError(err, "capture TTY index directory failed")
	}
	defer root.Close()
	base := filepath.Base(path)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		names, readErr := root.ReadNames(64)
		for _, name := range names {
			if name != base && !strings.HasPrefix(name, base+".") {
				continue
			}
			if err := indexTTYBindingsFromRoot(ctx, r.st, root, name); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return safeCaptureError(readErr, "capture TTY enumeration failed")
		}
	}
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
	return r.st.DiscoverCommandArtifacts(ctx, 2000, ExtractURLs)
}

func (r *Runner) cowrieDownloadsDir() string {
	home := r.cfg.Cowrie.Home
	if home == "" {
		home = filepath.Join(r.cfg.DataDir, "cowrie")
	}
	return filepath.Join(home, "var", "lib", "cowrie", "downloads")
}

// PurgeOldSourceFiles retains the compatibility wrapper. Live mode uses the
// cancellable form and reports errors; no failed unlink is counted as removal.
func (r *Runner) PurgeOldSourceFiles(retentionDays int) int {
	n, err := r.PurgeOldSourceFilesContext(context.Background(), retentionDays)
	if err != nil {
		log.Print("capture: source retention failed")
	}
	return n
}

func (r *Runner) PurgeOldSourceFilesContext(ctx context.Context, retentionDays int) (int, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	removed := 0
	for _, dir := range []string{r.cowrieDownloadsDir(), r.cowrieTTYDir()} {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		root, err := safefile.OpenRoot(dir)
		if errors.Is(err, safefile.ErrNotExist) {
			continue
		}
		if err != nil {
			return removed, safeCaptureError(err, "capture source retention access failed")
		}
		scanErr := func() error {
			defer root.Close()
			for {
				names, readErr := root.ReadNames(64)
				for _, name := range names {
					if err := ctx.Err(); err != nil {
						return err
					}
					// Closed Cowrie downloads/TTY recordings are content-addressed names.
					// Never sweep an unrelated administrative file or an in-progress log.
					if !looksLikeSHA256(name) {
						continue
					}
					f, err := root.OpenRegular(name)
					if errors.Is(err, safefile.ErrNotExist) || errors.Is(err, safefile.ErrNotRegular) || errors.Is(err, safefile.ErrUnsafePath) {
						continue
					}
					if err != nil {
						return safeCaptureError(err, "capture source retention read failed")
					}
					info, err := f.Stat()
					f.Close()
					if err != nil {
						return safeCaptureError(err, "capture source retention metadata failed")
					}
					if !info.ModTime().Before(cutoff) {
						continue
					}
					deleted, err := r.st.RemoveCaptureSourceIfSafe(ctx, name, func() (bool, error) {
						err := root.RemoveIfUnchanged(name, info)
						if errors.Is(err, safefile.ErrNotExist) {
							return false, nil
						}
						return err == nil, err
					})
					if err != nil {
						return safeCaptureError(err, "capture source retention decision failed")
					}
					if deleted {
						removed++
					}
				}
				if readErr == io.EOF {
					return nil
				}
				if readErr != nil {
					return safeCaptureError(readErr, "capture source retention enumeration failed")
				}
			}
		}()
		if scanErr != nil {
			return removed, scanErr
		}
	}
	return removed, nil
}

// ErrEmptyArtifact is returned by copyArtifact for a zero-byte source. Cowrie
// leaves plenty of empty files behind (SFTP `touch`-style probes, abandoned
// transfers); recording them as "fetched" pollutes the archive — measured at
// 92 zero-byte rows on the reference deployment. Callers record them with
// status "empty" (deduped, visible, never shareable) instead of copying.
var ErrEmptyArtifact = fmt.Errorf("zero-byte artifact")

// Fetch returns the runner's SafeFetcher so it can be shared with the
// artifact retry worker without creating a second evidence directory.
func (r *Runner) Fetch() *SafeFetcher {
	return r.fetch
}

func (r *Runner) FileWorker() *FileWorker {
	fw := NewFileWorker(r.st, r.cowrieDownloadsDir(), r.fetch.EvidenceDir, r.cfg.Capture.MaxBytes)
	fw.space = r.space
	return fw
}
