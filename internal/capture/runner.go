package capture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/store"
)

// Runner archives attacker payloads: Cowrie downloads + quarantine URL fetches.
type Runner struct {
	st   *store.Store
	cfg  config.Config
	fetch *SafeFetcher
}

func NewRunner(st *store.Store, cfg config.Config) *Runner {
	cap := cfg.Capture
	evidence := cap.EvidenceDir
	if evidence == "" {
		evidence = filepath.Join(cfg.DataDir, "evidence")
	}
	return &Runner{
		st:  st,
		cfg: cfg,
		fetch: NewSafeFetcher(
			evidence,
			cap.MaxBytes,
			time.Duration(cap.TimeoutSec)*time.Second,
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
	for _, sub := range []string{"quarantine", "cowrie", "meta"} {
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
	var c2 int
	c2, err = r.archiveFileDownloadEvents()
	return n + c2, err
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
		src := filepath.Join(dl, ent.Name())
		sum, size, err := copyArtifact(src, filepath.Join(dest, ent.Name()))
		if err != nil {
			continue
		}
		urlKey := "cowrie-download:" + ent.Name()
		exists, err := r.st.ArtifactURLRecorded(urlKey)
		if err != nil || exists {
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
		src := e.Filename
		if !filepath.IsAbs(src) {
			src = filepath.Join(r.cowrieDownloadsDir(), filepath.Base(src))
		}
		if _, err := os.Stat(src); err != nil {
			continue
		}
		base := e.SHA256
		if base == "" {
			base = filepath.Base(src)
		}
		dest := filepath.Join(r.fetch.EvidenceDir, "cowrie", base)
		sum, size, err := copyArtifact(src, dest)
		if err != nil {
			continue
		}
		urlKey := e.Command
		if urlKey == "" {
			urlKey = "cowrie-event:" + fmt.Sprint(e.ID)
		}
		exists, err := r.st.ArtifactURLRecorded(urlKey)
		if err != nil || exists {
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

func copyArtifact(src, dest string) (sha string, size int64, err error) {
	in, err := os.Open(src)
	if err != nil {
		return "", 0, err
	}
	defer in.Close()
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
	n, err := io.Copy(tmp, io.TeeReader(in, h))
	if err != nil {
		return "", 0, err
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


