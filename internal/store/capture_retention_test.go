package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestCaptureRetentionHasNoImplicitFileDeletionAuthority(t *testing.T) {
	s := newTestStore(t, "unscoped.db")
	path := filepath.Join(t.TempDir(), "unrelated")
	if err := os.WriteFile(path, []byte("retain me"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertArtifact(Artifact{TS: time.Now().Add(-72 * time.Hour), URL: "inert:unscoped", LocalPath: path}); err != nil {
		t.Fatal(err)
	}
	if err := s.MaintenancePurge(1); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "retain me" {
		t.Fatalf("DB path granted deletion authority: %q %v", b, err)
	}
}

func TestCaptureRetentionConfinesEvidenceAndProtectsSharedTranscript(t *testing.T) {
	for _, kind := range []string{"outside", "symlink-parent", "shared-transcript", "database"} {
		t.Run(kind, func(t *testing.T) {
			s := newTestStore(t, "confined.db")
			root := t.TempDir()
			path := filepath.Join(root, "blob")
			body := []byte("inert retained bytes")
			if kind == "outside" || kind == "symlink-parent" {
				path = filepath.Join(t.TempDir(), "blob")
			}
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "symlink-parent" {
				if err := os.Symlink(filepath.Dir(path), filepath.Join(root, "alias")); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(root, "alias", "blob")
			}
			if kind == "database" {
				root = filepath.Dir(s.path)
				path = s.path
			}
			s.SetCaptureRetentionPolicy(CaptureRetentionPolicy{EvidenceRoot: root})
			if err := s.UpsertArtifact(Artifact{TS: time.Now().Add(-72 * time.Hour), URL: "inert:old", LocalPath: path}); err != nil {
				t.Fatal(err)
			}
			if kind == "shared-transcript" {
				if err := os.WriteFile(path+".txt", body, 0600); err != nil {
					t.Fatal(err)
				}
				if err := s.UpsertArtifact(Artifact{TS: time.Now(), URL: "inert:new", LocalPath: path}); err != nil {
					t.Fatal(err)
				}
			}
			err := s.MaintenancePurge(1)
			if kind == "shared-transcript" {
				if err != nil {
					t.Fatal(err)
				}
				if b, err := os.ReadFile(path + ".txt"); err != nil || string(b) != string(body) {
					t.Fatalf("shared derivative deleted: %q %v", b, err)
				}
			} else if err == nil {
				t.Fatal("unsafe retention path not diagnosed")
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("protected bytes disappeared: %v", err)
			}
			if err := s.db.Ping(); err != nil {
				t.Fatalf("store damaged: %v", err)
			}
		})
	}
}

func TestCaptureRetentionCoordinatesPublicationAndRecording(t *testing.T) {
	s := newTestStore(t, "publication.db")
	root := t.TempDir()
	path := filepath.Join(root, "blob")
	s.SetCaptureRetentionPolicy(CaptureRetentionPolicy{EvidenceRoot: root})
	if err := os.WriteFile(path, []byte("inert"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertArtifact(Artifact{TS: time.Now().Add(-72 * time.Hour), URL: "inert:old", LocalPath: path}); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	completed := make(chan error, 1)
	go func() {
		completed <- s.WithCaptureFileAccess(context.Background(), func() error {
			close(entered)
			<-release
			return s.UpsertArtifact(Artifact{TS: time.Now(), URL: "inert:current", LocalPath: path})
		})
	}()
	<-entered
	purged := make(chan error, 1)
	go func() { purged <- s.MaintenancePurge(1) }()
	close(release)
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
	if err := <-purged; err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "inert" {
		t.Fatalf("publication lost between bytes and recording: %q %v", b, err)
	}
}

func TestCaptureRetentionArtifactPagesCommitBeforeLaterFailure(t *testing.T) {
	s := newTestStore(t, "pages.db")
	if err := s.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-72 * time.Hour).Format(time.RFC3339Nano)
	if err := s.WithTx(func(tx *sql.Tx) error {
		for i := 0; i < 1300; i++ {
			if _, err := tx.Exec("INSERT INTO artifacts(ts,url,origin,status,created_at) VALUES(?,?,'test','fetched',?)", old, fmt.Sprint("inert:", i), old); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("CREATE TRIGGER stop_late_purge BEFORE DELETE ON artifacts WHEN OLD.id=1200 BEGIN SELECT RAISE(ABORT,'inert stop'); END"); err != nil {
		t.Fatal(err)
	}
	if err := s.MaintenancePurge(1); err == nil {
		t.Fatal("expected injected late failure")
	}
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM artifacts").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n >= 1300 || n < 101 {
		t.Fatalf("purge did not retain bounded committed progress: remaining=%d", n)
	}
	if _, err := s.db.Exec("DROP TRIGGER stop_late_purge"); err != nil {
		t.Fatal(err)
	}
	if err := s.MaintenancePurge(1); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM artifacts").Scan(&n); err != nil || n != 0 {
		t.Fatalf("resume=%d %v", n, err)
	}
}

func TestCaptureRetentionKeepsQueuedURLWork(t *testing.T) {
	s := newTestStore(t, "urls.db")
	for _, state := range []string{"pending", "capturing", "failed"} {
		if err := s.UpsertArtifact(Artifact{TS: time.Now().Add(-72 * time.Hour), URL: "inert:" + state, Origin: "quarantine_fetch", Status: state}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.MaintenancePurge(1); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM artifacts").Scan(&n); err != nil || n != 3 {
		t.Fatalf("pending work lost: %d %v", n, err)
	}
}

func TestCaptureRetentionRetiresOnlyExpiredTerminalDiagnostics(t *testing.T) {
	s := newTestStore(t, "terminal.db")
	old := time.Now().Add(-72 * time.Hour)
	for i := 0; i < 4; i++ {
		if err := s.InsertEvent(&models.Event{TS: old, Source: models.SourceCowrie, Kind: models.KindFileDown, Filename: fmt.Sprint("source", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DiscoverFileCaptures(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.ClaimFileCaptures(context.Background(), time.Now(), 3, time.Minute)
	if err != nil || len(jobs) != 3 {
		t.Fatalf("claim %v %v", jobs, err)
	}
	for _, j := range jobs {
		if err := s.CompleteFileCapture(context.Background(), j, time.Now(), FileCaptureResult{Status: FileCaptureRejected, Reason: FileCaptureInvalidSource}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec("UPDATE capture_file_jobs SET updated_at=? WHERE id IN (1,2)", captureTime(old)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("INSERT INTO capture_discovery_errors(event_id,kind,reason,created_at) VALUES(1,'command','invalid_metadata',?),(2,'command','invalid_metadata',?)", captureTime(old), captureTime(time.Now())); err != nil {
		t.Fatal(err)
	}
	if err := s.MaintenancePurge(1); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM capture_file_jobs").Scan(&n); err != nil || n != 2 {
		t.Fatalf("terminal retention=%d %v; want recent rejection + pending", n, err)
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM capture_discovery_errors").Scan(&n); err != nil || n != 1 {
		t.Fatalf("diagnostic retention=%d %v", n, err)
	}
	if held, err := s.CaptureFileProtected(context.Background(), "source3"); err != nil || !held {
		t.Fatalf("pending source hold lost: %v %v", held, err)
	}
}

func TestCaptureRetentionKeepsRecentArchivedJobEvidence(t *testing.T) {
	s := newTestStore(t, "recent-result.db")
	root := t.TempDir()
	path := filepath.Join(root, "blob")
	if err := os.WriteFile(path, []byte("inert"), 0600); err != nil {
		t.Fatal(err)
	}
	s.SetCaptureRetentionPolicy(CaptureRetentionPolicy{EvidenceRoot: root})
	old := time.Now().Add(-72 * time.Hour)
	if err := s.InsertEvent(&models.Event{TS: old, Source: models.SourceCowrie, Kind: models.KindFileDown, Filename: "inert"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DiscoverFileCaptures(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.ClaimFileCaptures(context.Background(), time.Now(), 1, time.Minute)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim %v", err)
	}
	if err := s.CompleteFileCapture(context.Background(), jobs[0], time.Now(), FileCaptureResult{Status: FileCaptureArchived, LocalPath: path, SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", SizeBytes: 5}); err != nil {
		t.Fatal(err)
	}
	if err := s.MaintenancePurge(1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fresh durable result now points to deleted bytes: %v", err)
	}
	if _, err := s.db.Exec("UPDATE capture_file_jobs SET updated_at=?", captureTime(old)); err != nil {
		t.Fatal(err)
	}
	if err := s.MaintenancePurge(1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expired result pinned evidence forever: %v", err)
	}
}

func TestCaptureRetentionPreservesOperatorNoteOnlyOrphan(t *testing.T) {
	s := newTestStore(t, "retention-notes.db")
	old := time.Now().Add(-72 * time.Hour)
	for _, note := range []string{"operator note", "2 events, 0 usernames"} {
		id := "cowrie:" + note
		if err := s.UpsertActor(&models.Actor{ID: id, Source: models.SourceCowrie, FirstSeen: old, LastSeen: old, Notes: note}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.MaintenancePurge(1); err != nil {
		t.Fatal(err)
	}
	for _, note := range []string{"operator note", "2 events, 0 usernames"} {
		a, err := s.GetActor("cowrie:" + note)
		if err != nil || a.Notes != note {
			t.Errorf("retention erased annotation: %+v err=%v", a, err)
		}
	}
}

func TestCaptureRetentionProtectsUndiscoveredEvents(t *testing.T) {
	s := newTestStore(t, "undiscovered.db")
	s.SetCaptureRetentionPolicy(CaptureRetentionPolicy{CommandsEnabled: true, FilesEnabled: true})
	old := time.Now().Add(-72 * time.Hour)
	var events []*models.Event
	for i := 0; i < 5; i++ {
		events = append(events, &models.Event{TS: old, Source: models.SourceCowrie, Kind: models.KindFileDown, Filename: "inert", SHA256: "", Command: "https://example.test/inert"})
	}
	if err := s.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.MaintenancePurge(1); err != nil {
		t.Fatal(err)
	}
	if n, err := s.EventCount(); err != nil || n != 5 {
		t.Fatalf("missing checkpoints did not hold events: %d %v", n, err)
	}
	if _, err := s.DiscoverFileCaptures(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DiscoverCommandArtifacts(context.Background(), 5, func(string) []string { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.MaintenancePurge(1); err != nil {
		t.Fatal(err)
	}
	if n, err := s.EventCount(); err != nil || n != 3 {
		t.Fatalf("purge crossed the minimum active checkpoint: %d %v", n, err)
	}
	// Disabling discovery releases never-discovered history, but queued work
	// and its saved provenance remain protected and recoverable.
	s.SetCaptureRetentionPolicy(CaptureRetentionPolicy{})
	if err := s.MaintenancePurge(1); err != nil {
		t.Fatal(err)
	}
	if n, err := s.EventCount(); err != nil || n != 0 {
		t.Fatalf("disabled discovery pinned history: %d %v", n, err)
	}
	if held, err := s.CaptureFileProtected(context.Background(), "inert"); err != nil || !held {
		t.Fatalf("disabled capture discarded queued source hold: %v %v", held, err)
	}
	var jobs int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM capture_file_jobs WHERE observed_at IS NOT NULL").Scan(&jobs); err != nil || jobs != 2 {
		t.Fatalf("queued provenance lost: %d %v", jobs, err)
	}
}

func TestCaptureRetentionSourceDecisionSharesDiscoveryGuard(t *testing.T) {
	s := newTestStore(t, "source-guard.db")
	s.SetCaptureRetentionPolicy(CaptureRetentionPolicy{FilesEnabled: true})
	e := &models.Event{TS: time.Now().Add(-72 * time.Hour), Source: models.SourceCowrie, Kind: models.KindFileDown, Filename: "source"}
	if err := s.InsertEvent(e); err != nil {
		t.Fatal(err)
	}
	called := false
	remove := func() (bool, error) { called = true; return true, nil }
	if deleted, err := s.RemoveCaptureSourceIfSafe(context.Background(), "source", remove); err != nil || deleted || called {
		t.Fatalf("undiscovered source removed=%v called=%v err=%v", deleted, called, err)
	}
	if _, err := s.DiscoverFileCaptures(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	if deleted, err := s.RemoveCaptureSourceIfSafe(context.Background(), "source", remove); err != nil || deleted || called {
		t.Fatalf("pending source removed=%v called=%v err=%v", deleted, called, err)
	}
	jobs, err := s.ClaimFileCaptures(context.Background(), time.Now(), 1, time.Minute)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim=%+v %v", jobs, err)
	}
	if err := s.CompleteFileCapture(context.Background(), jobs[0], time.Now(), FileCaptureResult{Status: FileCaptureRejected, Reason: FileCaptureInvalidSource}); err != nil {
		t.Fatal(err)
	}
	if deleted, err := s.RemoveCaptureSourceIfSafe(context.Background(), "source", remove); err != nil || !deleted || !called {
		t.Fatalf("terminal source still pinned=%v called=%v err=%v", deleted, called, err)
	}
}
