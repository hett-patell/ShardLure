package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func snapshotTestDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	uri, err := sqliteFileURI(path, url.Values{"mode": {"ro"}, "immutable": {"1"}})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestSnapshotLiveWALKeepsCommittedPrefixAndMetadata(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source ?#% space.db")
	st, err := Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	at := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	if err := st.UpsertActor(&models.Actor{ID: "cowrie:inert", Source: "cowrie", FirstSeen: at, LastSeen: at, Notes: "operator note", Campaigns: "operator campaign"}); err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("a", 64)
	if err := st.UpsertArtifact(Artifact{TS: at, URL: "inert:artifact", LocalPath: filepath.Join(dir, "evidence", "blob"), SHA256: hash, SizeBytes: 17}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordBazaarUpload(BazaarUpload{SHA256: hash, UploadedAt: at, ResponseStatus: "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordURLhausSubmission("https://example.test/inert", "ok", at); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTx(func(tx *sql.Tx) error {
		for i := 0; i < 700; i++ {
			if _, err := tx.Exec("INSERT INTO events(ts,source,kind,command) VALUES(?,'cowrie','command',?)", at.Format(time.RFC3339Nano), strings.Repeat("inert", 1000)); err != nil {
				return err
			}
		}
		_, err := tx.Exec("INSERT INTO app_settings(key,value,updated_at) VALUES('snapshot-count','700',?),('sentinel','never-send-fixture-value',?)", captureTime(at), captureTime(at))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	start := make(chan struct{})
	go func() {
		<-start
		for i := 0; i < 40; i++ {
			if err := st.WithTx(func(tx *sql.Tx) error {
				if _, err := tx.Exec("INSERT INTO events(ts,source,kind) VALUES(?,'cowrie','connect')", captureTime(at)); err != nil {
					return err
				}
				_, err := tx.Exec("UPDATE app_settings SET value=CAST(value AS INTEGER)+1 WHERE key='snapshot-count'")
				return err
			}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	close(start)
	dest := filepath.Join(t.TempDir(), "snapshot.db")
	info, err := SnapshotDatabase(context.Background(), source, dest)
	if writerErr := <-done; writerErr != nil {
		t.Fatal(writerErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	checked, err := InspectSnapshot(context.Background(), dest)
	if err != nil || !reflect.DeepEqual(info, checked) {
		t.Fatalf("inspection mismatch: %+v %+v %v", info, checked, err)
	}
	if info.Schema != 24 || info.TableCounts["events"] < 700 || info.TableCounts["events"] > 740 || info.TableCounts["bazaar_uploads"] != 1 || info.TableCounts["urlhaus_submissions"] != 1 {
		t.Fatalf("snapshot counts %+v", info)
	}
	db := snapshotTestDB(t, dest)
	var count int64
	if err := db.QueryRow("SELECT value FROM app_settings WHERE key='snapshot-count'").Scan(&count); err != nil || count != info.TableCounts["events"] {
		t.Fatalf("torn committed prefix: %d %v", count, err)
	}
	var notes, campaigns, secret string
	if err := db.QueryRow("SELECT notes,campaigns FROM actors WHERE id='cowrie:inert'").Scan(&notes, &campaigns); err != nil || notes != "operator note" || campaigns != "operator campaign" {
		t.Fatalf("annotations lost: %v", err)
	}
	if err := db.QueryRow("SELECT value FROM app_settings WHERE key='sentinel'").Scan(&secret); err != nil || secret != "never-send-fixture-value" {
		t.Fatal("settings lost")
	}
	f, err := os.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var refs []EvidenceReference
	if err := IterateSnapshotEvidence(context.Background(), f, func(ref EvidenceReference) error { refs = append(refs, ref); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].SHA256 != hash || refs[0].SizeBytes != 17 {
		t.Fatalf("evidence metadata %+v", refs)
	}
	var untouched int
	if err := st.db.QueryRow("SELECT COUNT(*) FROM events WHERE ts_unix_ns IS NULL").Scan(&untouched); err != nil || untouched != 740 {
		t.Fatalf("snapshot ran source backfill: %d %v", untouched, err)
	}
}

func TestSnapshotInspectionIsReadOnlyAndDescriptorPinned(t *testing.T) {
	st := newTestStore(t, "source.db")
	dest := filepath.Join(t.TempDir(), "snapshot.db")
	if _, err := SnapshotDatabase(context.Background(), st.path, dest); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	entriesBefore, err := os.ReadDir(filepath.Dir(dest))
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i := 0; i < 10; i++ {
		if _, err := InspectSnapshotFile(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadFile(dest)
	if err != nil || sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatalf("verification changed source: %v", err)
	}
	entriesAfter, err := os.ReadDir(filepath.Dir(dest))
	if err != nil || len(entriesBefore) != len(entriesAfter) {
		t.Fatalf("verification created sidecars: %v", err)
	}
	if err := os.Rename(dest, dest+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("malicious replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectSnapshotFile(context.Background(), f); err != nil {
		t.Fatalf("descriptor reopened through name: %v", err)
	}
	if _, err := f.Stat(); err != nil {
		t.Fatalf("caller descriptor closed: %v", err)
	}
	if _, err := InspectSnapshot(context.Background(), dest); err == nil {
		t.Fatal("corrupt replacement accepted")
	}
}

func TestSnapshotSupportsOlderSchemasWithoutMigration(t *testing.T) {
	source := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT); INSERT INTO schema_migrations VALUES(1,'2026-09-21T00:00:00Z'); CREATE TABLE events(id INTEGER PRIMARY KEY,ts TEXT); INSERT INTO events VALUES(1,'inert preserved'); CREATE TABLE actors(id TEXT PRIMARY KEY,notes TEXT); INSERT INTO actors VALUES('inert','old annotation')"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	dest := filepath.Join(t.TempDir(), "old-snapshot.db")
	got, err := SnapshotDatabase(context.Background(), source, dest)
	if err != nil || got.Schema != 1 || got.TableCounts["events"] != 1 {
		t.Fatalf("old snapshot=%+v %v", got, err)
	}
	orig := snapshotTestDB(t, source)
	var version int
	if err := orig.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version); err != nil || version != 1 {
		t.Fatalf("source migrated: %d %v", version, err)
	}
	snap := snapshotTestDB(t, dest)
	var tables int
	if err := snap.QueryRow("SELECT COUNT(*) FROM sqlite_schema WHERE type='table'").Scan(&tables); err != nil || tables != 3 {
		t.Fatalf("snapshot migrated: %d %v", tables, err)
	}
}

func TestSnapshotRefusesUnsafeExistingFutureAndCanceledInputs(t *testing.T) {
	st := newTestStore(t, "source.db")
	dest := filepath.Join(t.TempDir(), "exists.db")
	if err := os.WriteFile(dest, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := SnapshotDatabase(context.Background(), st.path, dest); err == nil {
		t.Fatal("overwrote destination")
	}
	if b, err := os.ReadFile(dest); err != nil || string(b) != "keep" {
		t.Fatalf("existing bytes changed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SnapshotDatabase(ctx, st.path, dest+".cancelled"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if _, err := os.Stat(dest + ".cancelled"); !os.IsNotExist(err) {
		t.Fatal("cancelled operation created file")
	}
	if _, err := SnapshotDatabase(context.Background(), dest+".missing", dest+".new"); err == nil {
		t.Fatal("missing source accepted")
	}
	if _, err := InspectSnapshot(context.Background(), st.path); err == nil {
		t.Fatal("live WAL database accepted as standalone")
	}
	if _, err := st.db.Exec("INSERT INTO schema_migrations VALUES(999,'future')"); err != nil {
		t.Fatal(err)
	}
	if _, err := SnapshotDatabase(context.Background(), st.path, dest+".future"); err == nil {
		t.Fatal("future schema accepted")
	}
}

func TestSnapshotEvidenceRejectsMalformedMetadataAndStopsOnVisitorError(t *testing.T) {
	for _, kind := range []string{"invalid-hash", "invalid-size", "invalid-path", "visitor"} {
		t.Run(kind, func(t *testing.T) {
			st := newTestStore(t, "source.db")
			if err := st.UpsertArtifact(Artifact{TS: time.Now(), URL: "inert:blob", LocalPath: "/inert/blob", SHA256: strings.Repeat("a", 64), SizeBytes: 17}); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "invalid-hash":
				_, _ = st.db.Exec("UPDATE artifacts SET sha256='inert-private-hash'")
			case "invalid-size":
				_, _ = st.db.Exec("UPDATE artifacts SET size_bytes=-1")
			case "invalid-path":
				_, _ = st.db.Exec("UPDATE artifacts SET local_path=?", "inert\x00private-path")
			}
			dest := filepath.Join(t.TempDir(), "snapshot.db")
			if _, err := SnapshotDatabase(context.Background(), st.path, dest); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(dest)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			sentinel := errors.New("visitor stopped")
			calls := 0
			err = IterateSnapshotEvidence(context.Background(), f, func(EvidenceReference) error { calls++; return sentinel })
			if kind == "visitor" {
				if !errors.Is(err, sentinel) || calls != 1 {
					t.Fatalf("visitor cancellation lost: %v calls=%d", err, calls)
				}
			} else if err == nil || strings.Contains(err.Error(), "inert-private") || calls != 0 {
				t.Fatalf("invalid metadata escaped: %v calls=%d", err, calls)
			}
		})
	}
}

type snapshotStepError int

func (e snapshotStepError) Error() string { return fmt.Sprint("inert sqlite ", int(e)) }
func (e snapshotStepError) Code() int     { return int(e) }

type scriptedSnapshotBackup struct {
	steps    int
	errs     []error
	finish   error
	finished bool
}

func (b *scriptedSnapshotBackup) Step(int32) (bool, error) {
	b.steps++
	if b.steps <= len(b.errs) {
		return true, b.errs[b.steps-1]
	}
	return false, nil
}
func (b *scriptedSnapshotBackup) Finish() error { b.finished = true; return b.finish }

func TestSnapshotBackupBusyCancellationAndFinishErrors(t *testing.T) {
	for _, code := range []int{5, 6, 10} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			b := &scriptedSnapshotBackup{errs: []error{snapshotStepError(code)}}
			err := runSnapshotBackup(context.Background(), b)
			if !b.finished {
				t.Fatal("backup handle leaked")
			}
			if code == 10 {
				if err == nil || b.steps != 1 {
					t.Fatalf("retried non-busy error: %v %d", err, b.steps)
				}
			} else if err != nil || b.steps != 2 {
				t.Fatalf("busy retry=%d %v", b.steps, err)
			}
		})
	}
	sentinel := errors.New("inert finish failure")
	b := &scriptedSnapshotBackup{finish: sentinel}
	if err := runSnapshotBackup(context.Background(), b); !errors.Is(err, sentinel) {
		t.Fatalf("Finish error ignored: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	b = &scriptedSnapshotBackup{errs: []error{snapshotStepError(5)}}
	if err := runSnapshotBackup(ctx, b); !errors.Is(err, context.DeadlineExceeded) || !b.finished || b.steps != 1 {
		t.Fatalf("busy cancellation=%v %+v", err, b)
	}
}

func TestSnapshotIncludesDurableFileJobStorageReferences(t *testing.T) {
	st := newTestStore(t, "file-job.db")
	if err := st.InsertEvent(&models.Event{TS: time.Now(), Source: models.SourceCowrie, Kind: models.KindFileDown, Filename: "inert"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DiscoverFileCaptures(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	jobs, err := st.ClaimFileCaptures(context.Background(), time.Now(), 1, time.Minute)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim %v", err)
	}
	if err := st.CompleteFileCapture(context.Background(), jobs[0], time.Now(), FileCaptureResult{Status: FileCaptureArchived, LocalPath: "/inert/job-only", SHA256: strings.Repeat("a", 64), SizeBytes: 17}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("DELETE FROM artifacts"); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "snapshot.db")
	if _, err := SnapshotDatabase(context.Background(), st.path, dest); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var refs []EvidenceReference
	if err := IterateSnapshotEvidence(context.Background(), f, func(ref EvidenceReference) error { refs = append(refs, ref); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].Path != "/inert/job-only" || refs[0].SizeBytes != 17 {
		t.Fatalf("lost durable file job reference: %+v", refs)
	}
}

func TestSnapshotVFSAdmissionAndConcurrentCleanup(t *testing.T) {
	st := newTestStore(t, "source.db")
	dest := filepath.Join(t.TempDir(), "snapshot.db")
	if _, err := SnapshotDatabase(context.Background(), st.path, dest); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	releases := make([]func(), 0, 8)
	for i := 0; i < 8; i++ {
		_, _, release, err := snapshotVFS.register(context.Background(), snapshotFileFS{f, info})
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	if _, err := InspectSnapshotFile(ctx, f); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("admission ignored cancellation: %v", err)
	}
	cancel()
	for _, release := range releases {
		release()
	}
	results := make(chan error, 24)
	for i := 0; i < 24; i++ {
		go func() { _, err := InspectSnapshotFile(context.Background(), f); results <- err }()
	}
	for i := 0; i < 24; i++ {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	snapshotVFS.mu.RLock()
	remaining := len(snapshotVFS.files)
	snapshotVFS.mu.RUnlock()
	if remaining != 0 || len(snapshotVFS.slots) != 0 {
		t.Fatalf("inspection resources leaked: %d", remaining)
	}
	if err := os.Chmod(filepath.Dir(dest), 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(filepath.Dir(dest), 0700)
	if _, err := InspectSnapshot(context.Background(), dest); err != nil {
		t.Fatalf("read-only bundle verification failed: %v", err)
	}
}
