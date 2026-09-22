package capture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func TestCaptureRetentionKeepsLeasedDownloadBytes(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "capture.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := config.Config{DataDir: dir}
	cfg.Capture.Enabled = true
	r := NewRunner(st, cfg)
	if err := os.MkdirAll(r.cowrieDownloadsDir(), 0700); err != nil {
		t.Fatal(err)
	}
	body := []byte("inert source bytes that a leased worker still needs")
	hash := sha256.Sum256(body)
	name := hex.EncodeToString(hash[:])
	source := filepath.Join(r.cowrieDownloadsDir(), name)
	if err := os.WriteFile(source, body, 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(source, old, old); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertEvent(&models.Event{TS: old, Source: models.SourceCowrie, Kind: models.KindFileDown, Filename: name, SHA256: name, Command: "https://example.test/inert"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DiscoverFileCaptures(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	jobs, err := st.ClaimFileCaptures(context.Background(), time.Now(), 1, time.Minute)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim=%+v %v", jobs, err)
	}
	if err := st.MaintenancePurge(1); err != nil {
		t.Fatal(err)
	}
	r.PurgeOldSourceFiles(1)
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(after, body) {
		t.Fatalf("retention removed leased input: %q err=%v", after, err)
	}
	if jobs[0].SourceName != name || !jobs[0].ObservedAt.Equal(old.UTC()) {
		t.Fatalf("required provenance lost: %+v", jobs[0])
	}
}

func newFileArchiveFixture(t *testing.T) (*store.Store, *FileWorker, string, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "capture.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	downloads := filepath.Join(dir, "downloads")
	if err := os.Mkdir(downloads, 0700); err != nil {
		t.Fatal(err)
	}
	body := []byte(strings.Repeat("inert archive bytes ", 10))
	digest := sha256.Sum256(body)
	name := hex.EncodeToString(digest[:])
	source := filepath.Join(downloads, name)
	if err := os.WriteFile(source, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertEvent(&models.Event{TS: time.Now().Add(-time.Hour), Source: models.SourceCowrie, Kind: models.KindFileDown, Filename: name, SHA256: name}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DiscoverFileCaptures(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	w := NewFileWorker(st, downloads, filepath.Join(dir, "evidence"), 1024)
	return st, w, source, filepath.Join(dir, "evidence", "cowrie", name), body
}

func TestFileArchiveCrashAfterPublicationAdoptsVerifiedBlob(t *testing.T) {
	st, w, source, dest, body := newFileArchiveFixture(t)
	now := time.Now().UTC()
	w.now = func() time.Time { return now }
	if err := st.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec("CREATE TRIGGER reject_file_result BEFORE INSERT ON artifacts WHEN NEW.origin='cowrie_file_download' BEGIN SELECT RAISE(ABORT,'inert rejection'); END")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := w.tick(context.Background()); err == nil || n != 0 {
		t.Fatalf("recording failure reported success: %d %v", n, err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("published bytes lost on DB failure: %v", err)
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTx(func(tx *sql.Tx) error { _, err := tx.Exec("DROP TRIGGER reject_file_result"); return err }); err != nil {
		t.Fatal(err)
	}
	now = now.Add(3 * time.Minute)
	restarted := NewFileWorker(st, w.downloadsRoot, w.evidenceRoot, 1024)
	restarted.now = func() time.Time { return now }
	if n, err := restarted.tick(context.Background()); err != nil || n != 1 {
		t.Fatalf("published blob not recovered without source: %d %v", n, err)
	}
}

func TestFileArchiveDuplicateHashKeepsIndependentAssociations(t *testing.T) {
	st, w, source, dest, body := newFileArchiveFixture(t)
	name := filepath.Base(source)
	if err := st.InsertEvent(&models.Event{TS: time.Now(), Source: models.SourceCowrie, Kind: models.KindFileDown, Filename: name, SHA256: name, SessionID: "second"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DiscoverFileCaptures(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if n, err := w.tick(context.Background()); err != nil || n != 1 {
			t.Fatalf("archive %d=%d %v", i, n, err)
		}
	}
	if n := captureScalar(t, st, "SELECT COUNT(*) FROM artifacts WHERE url LIKE 'cowrie-event:%'"); n != 2 {
		t.Fatalf("per-event association lost: %d", n)
	}
	entries, err := os.ReadDir(filepath.Dir(dest))
	if err != nil || len(entries) != 1 {
		t.Fatalf("duplicate blobs/temporary leak: %d %v", len(entries), err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("duplicate changed bytes: %v", err)
	}
}

func TestFileArchiveCancellationDoesNotClaimOrPublish(t *testing.T) {
	st, w, _, dest, _ := newFileArchiveFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n, err := w.tick(ctx); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%d %v", n, err)
	}
	if n := captureScalar(t, st, "SELECT COUNT(*) FROM capture_file_jobs WHERE state='pending' AND attempts=0"); n != 1 {
		t.Fatalf("cancellation changed job: %d", n)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("cancelled worker published: %v", err)
	}
}

func TestFileArchiveRejectsSymlinkAndExistingWrongBytes(t *testing.T) {
	for _, kind := range []string{"source-symlink", "wrong-existing-blob"} {
		t.Run(kind, func(t *testing.T) {
			st, w, source, dest, body := newFileArchiveFixture(t)
			if kind == "source-symlink" {
				outside := filepath.Join(t.TempDir(), "outside")
				if err := os.WriteFile(outside, body, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(source); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, source); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(dest, []byte("existing unrelated bytes"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if n, err := w.tick(context.Background()); err != nil || n != 0 {
				t.Fatalf("unsafe bytes archived: %d %v", n, err)
			}
			if n := captureScalar(t, st, "SELECT COUNT(*) FROM capture_file_jobs WHERE state='rejected'"); n != 1 {
				t.Fatalf("unsafe source not diagnosed: %d", n)
			}
			if kind == "wrong-existing-blob" {
				got, err := os.ReadFile(dest)
				if err != nil || string(got) != "existing unrelated bytes" {
					t.Fatalf("existing evidence overwritten: %q %v", got, err)
				}
			}
		})
	}
}

func TestFileArchiveDetectsChangeDespiteRestoredMtime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(path, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("after!"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if captureFileUnchanged(before, after) {
		t.Fatal("same-size replacement with restored mtime was accepted")
	}
}

func TestFileArchiveLegacyCopyRejectsSymlinkAndPreservesDestination(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "source")
	dest := filepath.Join(dir, "dest")
	if err := os.Symlink(outside, source); err != nil {
		t.Fatal(err)
	}
	if _, _, err := copyArtifact(source, dest, 1024); err == nil {
		t.Error("legacy copy followed a source symlink")
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("new bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("existing bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := copyArtifact(source, dest, 1024); err == nil {
		t.Error("legacy copy accepted mismatched existing destination")
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "existing bytes" {
		t.Fatalf("legacy copy overwrote evidence: %q %v", got, err)
	}
}

func TestFileArchiveRawDirectoryObservationDoesNotInventFetchTime(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "capture.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := config.Config{DataDir: dir}
	cfg.Capture.Enabled = true
	r := NewRunner(st, cfg)
	if err := os.MkdirAll(r.cowrieDownloadsDir(), 0700); err != nil {
		t.Fatal(err)
	}
	body := []byte(strings.Repeat("inert", 20))
	digest := sha256.Sum256(body)
	name := hex.EncodeToString(digest[:])
	source := filepath.Join(r.cowrieDownloadsDir(), name)
	if err := os.WriteFile(source, body, 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-30 * 24 * time.Hour)
	if err := os.Chtimes(source, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	var fetched sql.NullString
	if err := st.QueryRows("SELECT last_successful_fetch_at FROM artifacts WHERE url=?", []any{"cowrie-download:" + name}, func(scan func(...any) error) error { return scan(&fetched) }); err != nil {
		t.Fatal(err)
	}
	if fetched.Valid {
		t.Fatalf("directory scan invented remote-fetch proof: %+v", fetched)
	}
}

func TestFileArchiveTTYMemoCannotHidePurgedArtifact(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "capture.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := config.Config{DataDir: dir}
	cfg.Capture.Enabled = true
	r := NewRunner(st, cfg)
	if err := os.MkdirAll(r.cowrieTTYDir(), 0700); err != nil {
		t.Fatal(err)
	}
	name := strings.Repeat("a", 64)
	key := "cowrie-tty:" + name
	if err := os.WriteFile(filepath.Join(r.cowrieTTYDir(), name), []byte("inert short tty"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordCowrieTTYBinding(name, "session", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTx(func(tx *sql.Tx) error { _, err := tx.Exec("DELETE FROM artifacts WHERE url=?", key); return err }); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := captureScalar(t, st, "SELECT COUNT(*) FROM artifacts WHERE url=?", key); n != 1 {
		t.Fatalf("process memo hid purged durable state: %d", n)
	}
}

func TestFileArchiveRawHashMismatchDoesNotPublish(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "capture.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := config.Config{DataDir: dir}
	cfg.Capture.Enabled = true
	r := NewRunner(st, cfg)
	if err := os.MkdirAll(r.cowrieDownloadsDir(), 0700); err != nil {
		t.Fatal(err)
	}
	name := strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(r.cowrieDownloadsDir(), name), []byte("bytes do not match this recorded name"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(context.Background()); err == nil {
		t.Fatal("hash mismatch was ignored")
	}
	if _, err := os.Stat(filepath.Join(r.fetch.EvidenceDir, "cowrie", name)); !os.IsNotExist(err) {
		t.Fatalf("incorrect bytes poisoned hash namespace: %v", err)
	}
}

func TestFileArchiveUnsafeOutputFailsBeforeDirectoryMutation(t *testing.T) {
	base := t.TempDir()
	st, err := store.Open(filepath.Join(base, "capture.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	outside := t.TempDir()
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(outside, alias); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DataDir: base}
	cfg.Capture.Enabled = true
	cfg.Capture.EvidenceDir = filepath.Join(alias, "evidence")
	r := NewRunner(st, cfg)
	if _, err := r.Run(context.Background()); err == nil {
		t.Fatal("unsafe output root accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "evidence")); !os.IsNotExist(err) {
		t.Fatalf("created through unsafe output alias: %v", err)
	}
}

func captureScalar(t *testing.T, st *store.Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := st.QueryRows(query, args, func(scan func(...any) error) error { return scan(&n) }); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestFileArchiveBurstAcrossTicksAndReopen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "capture.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { st.Close() }()
	cfg := config.Config{DataDir: dir}
	cfg.Capture.Enabled = true
	cfg.Capture.MaxBytes = 1024
	r := NewRunner(st, cfg)
	if err := os.MkdirAll(r.cowrieDownloadsDir(), 0700); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour)
	var events []*models.Event
	expected := map[string][]byte{}
	for i := 0; i < 406; i++ {
		body := []byte(fmt.Sprintf("inert download %d %s", i, strings.Repeat("x", 80)))
		hash := sha256.Sum256(body)
		name := hex.EncodeToString(hash[:])
		expected[name] = body
		if err := os.WriteFile(filepath.Join(r.cowrieDownloadsDir(), name), body, 0600); err != nil {
			t.Fatal(err)
		}
		at := base.Add(time.Duration(i) * time.Second)
		if i == 405 {
			at = base.Add(-24 * time.Hour)
		}
		events = append(events, &models.Event{TS: at, Source: models.SourceCowrie, Kind: models.KindFileDown, Filename: name, SHA256: name, Command: "https://example.test/" + name})
	}
	if err := st.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	w := NewFileWorker(st, r.cowrieDownloadsDir(), r.fetch.EvidenceDir, 1024)
	for i := 0; i < 430; i++ {
		if i == 100 {
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			st, err = store.Open(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			r = NewRunner(st, cfg)
			w = NewFileWorker(st, r.cowrieDownloadsDir(), r.fetch.EvidenceDir, 1024)
			if _, err := r.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := w.tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := captureScalar(t, st, "SELECT COUNT(*) FROM capture_file_jobs WHERE state='archived'"); n != 406 {
		t.Fatalf("durable file outcomes=%d want 406", n)
	}
	if n := captureScalar(t, st, "SELECT COUNT(*) FROM artifacts WHERE url LIKE 'cowrie-event:%'"); n != 406 {
		t.Fatalf("event associations=%d want 406", n)
	}
	for name, body := range expected {
		got, err := os.ReadFile(filepath.Join(r.cowrieDownloadsDir(), name))
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("source bytes changed: %v", err)
		}
	}
}

func TestFileArchiveDelayedSourceRetriesWithoutFalseSuccess(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "capture.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	downloads := filepath.Join(dir, "downloads")
	if err := os.Mkdir(downloads, 0700); err != nil {
		t.Fatal(err)
	}
	body := []byte(strings.Repeat("inert", 20))
	hash := sha256.Sum256(body)
	name := hex.EncodeToString(hash[:])
	now := time.Now().UTC()
	if err := st.InsertEvent(&models.Event{TS: now.Add(-time.Hour), Source: models.SourceCowrie, Kind: models.KindFileDown, Filename: name, SHA256: name}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DiscoverFileCaptures(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	w := NewFileWorker(st, downloads, filepath.Join(dir, "evidence"), 1024)
	w.now = func() time.Time { return now }
	if n, err := w.tick(context.Background()); err != nil || n != 0 {
		t.Fatalf("missing source marked captured: %d %v", n, err)
	}
	if n := captureScalar(t, st, "SELECT COUNT(*) FROM capture_file_jobs WHERE state='retry' AND reason='missing_source'"); n != 1 {
		t.Fatalf("missing retry=%d", n)
	}
	if err := os.WriteFile(filepath.Join(downloads, name), body, 0600); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if n, err := w.tick(context.Background()); err != nil || n != 1 {
		t.Fatalf("delayed source not archived: %d %v", n, err)
	}
}
