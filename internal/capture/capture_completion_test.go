package capture

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/store"
)

func TestFileArchiveHashlessRecoveryNeverGuessesMissingSource(t *testing.T) {
	st, w, source, dest, body := newFileArchiveFixture(t)
	if err := st.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec("UPDATE capture_file_jobs SET expected_sha256=''; CREATE TRIGGER stop_result BEFORE INSERT ON artifacts BEGIN SELECT RAISE(ABORT,'inert stop'); END")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	w.now = func() time.Time { return now }
	if _, err := w.tick(context.Background()); err == nil {
		t.Fatal("lost recording failure")
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTx(func(tx *sql.Tx) error { _, err := tx.Exec("DROP TRIGGER stop_result"); return err }); err != nil {
		t.Fatal(err)
	}
	now = now.Add(3 * time.Minute)
	if n, err := w.tick(context.Background()); err != nil || n != 0 {
		t.Fatalf("guessed association: %d %v", n, err)
	}
	if n := captureScalar(t, st, "SELECT COUNT(*) FROM capture_file_jobs WHERE state='retry' AND reason='missing_source'"); n != 1 {
		t.Fatalf("missing source not recoverably diagnosed: %d", n)
	}
	if b, err := os.ReadFile(dest); err != nil || string(b) != string(body) {
		t.Fatalf("unassociated bytes lost: %v", err)
	}
}

func TestFileArchiveTTYIndexFailureIsRetried(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "capture.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := config.Config{DataDir: dir}
	cfg.Capture.Enabled = true
	cfg.Cowrie.JSONLog = filepath.Join(dir, "cowrie.json")
	name := strings.Repeat("a", 64)
	line := `{"eventid":"cowrie.log.closed","session":"inert-session","shasum":"` + name + `","timestamp":"2026-09-21T00:00:00Z"}` + "\n"
	if err := os.WriteFile(cfg.Cowrie.JSONLog, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordCowrieTTYBinding(strings.Repeat("b", 64), "seed", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec("CREATE TRIGGER stop_tty BEFORE INSERT ON cowrie_tty_index BEGIN SELECT RAISE(ABORT,'private path sentinel'); END")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r := NewRunner(st, cfg)
	if _, err := r.Run(context.Background()); err == nil {
		t.Error("TTY persistence failure hidden")
	} else if strings.Contains(err.Error(), "sentinel") {
		t.Error("private DB diagnostic leaked")
	}
	if err := st.WithTx(func(tx *sql.Tx) error { _, err := tx.Exec("DROP TRIGGER stop_tty"); return err }); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sid, err := st.SessionIDForCowrieTTYShasum(name); err != nil || sid != "inert-session" {
		t.Fatalf("failed backfill never retried: %q %v", sid, err)
	}
}

func TestFileArchiveTranscriptFailureCannotBecomeSuccess(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "capture.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := config.Config{DataDir: dir}
	cfg.Capture.Enabled = true
	r := NewRunner(st, cfg)
	name := strings.Repeat("c", 64)
	if err := os.MkdirAll(r.cowrieTTYDir(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.cowrieTTYDir(), name), []byte("inert short tty"), 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(r.fetch.EvidenceDir, "cowrie-tty")
	if err := os.MkdirAll(filepath.Join(out, name+".txt"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(context.Background()); err == nil {
		t.Error("invalid existing transcript accepted")
	}
	if err := os.Remove(filepath.Join(out, name+".txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, name+".txt")); err != nil {
		t.Fatalf("failed derivative never retried: %v", err)
	}
}

func TestCaptureFetchNeverOverwritesExistingBlob(t *testing.T) {
	_, _, _, dest, body := newFileArchiveFixture(t)
	dir := filepath.Dir(filepath.Dir(dest))
	out := filepath.Join(dir, "quarantine", filepath.Base(dest))
	if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte("preserve existing mismatched bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
	defer server.Close()
	f := NewSafeFetcher(dir, 1024, time.Second, nil)
	f.TestLoopback = true
	res, err := f.Fetch(context.Background(), server.URL)
	if err == nil && res != nil && res.Status == "fetched" {
		t.Error("mismatched existing evidence accepted")
	}
	if b, err := os.ReadFile(out); err != nil || string(b) != "preserve existing mismatched bytes" {
		t.Fatalf("existing evidence overwritten: %q %v", b, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.Fetch(ctx, server.URL); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation identity lost: %v", err)
	}
}
