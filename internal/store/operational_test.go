package store

import (
	"context"
	"errors"
	"github.com/networkshard/shardlure/pkg/models"
	"testing"
	"time"
)

func TestOperationalSnapshotQueueAndCancellation(t *testing.T) {
	s := newTestStore(t, "operations.db")
	s.SetCaptureRetentionPolicy(CaptureRetentionPolicy{FilesEnabled: true})
	for i := 0; i < 3; i++ {
		if err := s.InsertEvent(&models.Event{TS: time.Now(), Source: models.SourceCowrie, Kind: models.KindFileDown, Filename: "inert"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DiscoverFileCaptures(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimFileCaptures(context.Background(), time.Now(), 1, time.Minute); err != nil {
		t.Fatal(err)
	}
	stats, err := s.OperationalSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.FilePending != 1 || stats.FileLeased != 1 || stats.FileDiscoveryLag != 1 || stats.ProtectedFileJobs != 2 {
		t.Fatalf("wrong bounded operational state: %+v", stats)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.OperationalSnapshot(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel ignored: %v", err)
	}
	s.captureMu.Lock()
	_, err = s.OperationalSnapshot(context.Background())
	s.captureMu.Unlock()
	if err == nil {
		t.Fatal("busy retention guard blocked or claimed valid snapshot")
	}
}

func TestOperationalProbeBoundsPoolWait(t *testing.T) {
	s := newTestStore(t, "pool-probe.db")
	s.db.SetMaxOpenConns(1)
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = s.Probe(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("pool wait was unbounded: %v", err)
	}
}
