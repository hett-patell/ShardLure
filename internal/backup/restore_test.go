package backup

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/ingest/cowrie"
	"github.com/networkshard/shardlure/internal/safefile"
	"github.com/networkshard/shardlure/internal/store"
)

func TestRestoreReplayRebasesCursorWithoutDuplicatingEvents(t *testing.T) {
	f := newFixture(t)
	log := `{"eventid":"cowrie.command.input","input":"echo inert","session":"inert-session","src_ip":"192.0.2.23","timestamp":"2026-09-21T01:00:00Z"}` + "\n"
	if err := os.WriteFile(f.SourceLog, []byte(log), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := cowrie.IngestFileAppend(f.Store, f.SourceLog, nil); err != nil {
		t.Fatal(err)
	}
	before, err := f.Store.EventCount()
	if err != nil || before != 4 {
		t.Fatalf("fixture ingest=%d %v", before, err)
	}
	bundle := filepath.Join(t.TempDir(), "backup")
	if _, err := Create(context.Background(), CreateOptions{ConfigPath: f.Config, Output: bundle}); err != nil {
		t.Fatal(err)
	}
	to := filepath.Join(t.TempDir(), "restore")
	if _, err := Restore(context.Background(), RestoreOptions{Input: bundle, To: to}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(to, "shardlure.recovery.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := store.Open(filepath.Join(to, "shardlure.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if _, err := cowrie.IngestFileAppend(restored, cfg.Cowrie.JSONLog, nil); err != nil {
		t.Fatal(err)
	}
	after, err := restored.EventCount()
	if err != nil || after != 4 {
		t.Fatalf("recovery replay duplicated history: %d %v", after, err)
	}
}

func TestBackupHonorsExplicitOperationDeadline(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	ops := nativeOperations()
	nativeCopy := ops.copy
	ops.copy = func(ctx context.Context, role string, w io.Writer, r io.Reader, n int64) (int64, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) < time.Hour {
			return 0, errors.New("explicit deadline was shortened")
		}
		return nativeCopy(ctx, role, w, r, n)
	}
	if _, err := createWithOperations(ctx, CreateOptions{ConfigPath: f.Config, Output: filepath.Join(t.TempDir(), "backup")}, ops); err != nil {
		t.Fatalf("--timeout override ignored: %v", err)
	}
}

func TestRestoreRoundTripPreservesLogicalData(t *testing.T) {
	f := newFixture(t)
	bundle := filepath.Join(t.TempDir(), "backup")
	m, err := Create(context.Background(), CreateOptions{ConfigPath: f.Config, Output: bundle})
	if err != nil {
		t.Fatal(err)
	}
	to := filepath.Join(t.TempDir(), "recovered")
	report, err := Restore(context.Background(), RestoreOptions{Input: bundle, To: to})
	if err != nil || report.TableCounts["events"] != 3 {
		t.Fatalf("restore %+v %v", report, err)
	}
	b, err := os.ReadFile(filepath.Join(to, "evidence", "quarantine", fixtureHash()))
	if err != nil || string(b) != inertEvidence {
		t.Fatal("restored evidence differs")
	}
	db, err := sql.Open("sqlite", filepath.Join(to, "shardlure.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var note, value, local string
	var events, ledger int
	if err := db.QueryRow("SELECT notes FROM actors").Scan(&note); err != nil || note != "operator note" {
		t.Fatal("operator annotation lost")
	}
	if err := db.QueryRow("SELECT value FROM app_settings WHERE key='fixture.key'").Scan(&value); err != nil || value != "never-send-fixture-value" {
		t.Fatal("settings modified")
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM events").Scan(&events); err != nil || events != 3 {
		t.Fatal("events lost")
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM urlhaus_submissions").Scan(&ledger); err != nil || ledger != 1 {
		t.Fatal("submission ledger lost")
	}
	if err := db.QueryRow("SELECT local_path FROM artifacts LIMIT 1").Scan(&local); err != nil || local != filepath.Join(to, "evidence", "quarantine", fixtureHash()) {
		t.Fatalf("dangling old evidence path %q %v", local, err)
	}
	cfg, err := config.Load(filepath.Join(to, "shardlure.recovery.yaml"))
	if err != nil || cfg.DataDir != to || cfg.Capture.Enabled || cfg.RetentionDays != 0 {
		t.Fatalf("unsafe recovery configuration: %v", err)
	}
	original, err := os.ReadFile(f.Config)
	if err != nil {
		t.Fatal(err)
	}
	preserved, err := os.ReadFile(filepath.Join(to, "metadata", "config.yaml"))
	if err != nil || string(original) != string(preserved) {
		t.Fatal("original config not preserved")
	}
	if _, err := os.Stat(filepath.Join(to, "recovery-report.json")); err != nil {
		t.Fatal(err)
	}
	checked, err := Verify(context.Background(), bundle)
	if err != nil || checked.Schema != m.Schema || checked.TableCounts["events"] != 3 {
		t.Fatalf("source bundle modified: %v", err)
	}
}

func TestRestoreDryRunAndDestinationSafety(t *testing.T) {
	f := newFixture(t)
	bundle := filepath.Join(t.TempDir(), "backup")
	if _, err := Create(context.Background(), CreateOptions{ConfigPath: f.Config, Output: bundle}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHARDLURE_CONFIG", "/inert/not/a/config")
	for _, kind := range []string{"dry-run", "empty", "existing", "inside-bundle", "inside-source", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			to := filepath.Join(t.TempDir(), "new")
			opts := RestoreOptions{Input: bundle, To: to}
			ctx := context.Background()
			switch kind {
			case "dry-run":
				opts.DryRun = true
			case "empty", "existing":
				if err := os.Mkdir(to, 0700); err != nil {
					t.Fatal(err)
				}
				if kind == "existing" {
					if err := os.WriteFile(filepath.Join(to, "keep"), []byte("keep"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "inside-bundle":
				opts.To = filepath.Join(bundle, "new")
			case "inside-source":
				opts.To = filepath.Join(f.Evidence, "new")
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			_, err := Restore(ctx, opts)
			if kind == "dry-run" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(to); !os.IsNotExist(err) {
					t.Fatal("dry-run created output")
				}
				return
			}
			if err == nil {
				t.Fatal("unsafe restore succeeded")
			}
			if kind == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel identity %v", err)
			}
			if kind == "existing" {
				if b, err := os.ReadFile(filepath.Join(to, "keep")); err != nil || string(b) != "keep" {
					t.Fatal("existing data overwritten")
				}
			}
		})
	}
}

func TestRestoreLatePublicationFailureStaysIncomplete(t *testing.T) {
	f := newFixture(t)
	bundle := filepath.Join(t.TempDir(), "backup")
	if _, err := Create(context.Background(), CreateOptions{ConfigPath: f.Config, Output: bundle}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "restore")
	ops := nativeOperations()
	ops.publish = func(root *safefile.Root, a, b string) error {
		if err := root.PublishNoReplace(a, b); err != nil {
			return err
		}
		return safefile.ErrSync
	}
	_, err := restoreWithOperations(context.Background(), RestoreOptions{Input: bundle, To: out}, ops)
	if err == nil {
		t.Fatal("late restore failure reported success")
	}
	if _, err := os.Stat(filepath.Join(out, incompleteName)); err != nil {
		t.Fatal("uncertain restore lost its marker")
	}
	if _, err := Verify(context.Background(), bundle); err != nil {
		t.Fatal("failed restore changed source")
	}
}
