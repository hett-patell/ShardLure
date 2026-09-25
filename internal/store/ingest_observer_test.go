package store

import (
	"context"
	"errors"
	"github.com/networkshard/shardlure/pkg/models"
	"testing"
	"time"
)

func TestIngestObserverCountsOnlyCommittedRows(t *testing.T) {
	s := newTestStore(t, "observer.db")
	committed, failed := 0, 0
	s.SetIngestObserver(func(source models.Source, n int, err error) {
		if err != nil {
			failed++
		} else {
			committed += n
		}
	})
	if _, err := s.db.Exec("CREATE TRIGGER reject_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'inert'); END"); err != nil {
		t.Fatal(err)
	}
	events := []*models.Event{{TS: time.Now(), Source: models.SourceCowrie, Kind: models.KindConnect}}
	if err := s.AppendEventsAndUpsertActorsAgg(events, nil); err == nil {
		t.Fatal("fixture did not fail")
	}
	if committed != 0 || failed != 1 {
		t.Fatalf("rollback counted: %d %d", committed, failed)
	}
	if _, err := s.db.Exec("DROP TRIGGER reject_event"); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatal(err)
	}
	journal := &models.Event{TS: time.Now(), Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: "192.0.2.1", Username: "inert"}
	if _, err := s.AppendJournalEventsAtomic([]*models.Event{journal, journal}); err != nil {
		t.Fatal(err)
	}
	if committed != 2 {
		t.Fatalf("dedup counted as new commit: %d", committed)
	}
}

func TestIngestContextCancelsWhileWaitingForWriter(t *testing.T) {
	s := newTestStore(t, "writer-context.db")
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := s.AppendJournalEventsAtomicContext(ctx, []*models.Event{{TS: time.Now(), Source: models.SourceJournal, Kind: models.KindFailedPass}})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("writer cancel=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled ingest waited indefinitely for writer")
	}
}
