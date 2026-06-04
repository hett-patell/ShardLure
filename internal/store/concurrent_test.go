package store

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// TestReadPoolAllowsConcurrency asserts the connection pool is NOT capped at 1.
// Writes are serialized by Store.writeMu (not by a 1-connection pool), so WAL
// readers can run concurrently with the single writer — a 1-conn pool would let
// one slow analytics query stall live ingest. The behavioral guarantee (no
// dropped writes under concurrency) is covered by TestConcurrentWritersNoLockErrors.
func TestReadPoolAllowsConcurrency(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "pool.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if got := st.db.Stats().MaxOpenConnections; got <= 1 {
		t.Fatalf("MaxOpenConnections = %d, want >1 (reads must run concurrently with the serialized writer)", got)
	}
}

// TestConcurrentWritersNoLockErrors mirrors the live-mode contention: several
// goroutines (journal tail, cowrie ingest ticker, enrichment writes, retention
// purge) hammer one *Store at once. Every write must succeed and the run must
// be data-race clean under -race. Together with TestWritePoolIsSerialized this
// covers both the mechanism (single connection) and the behavior (no errors
// under concurrency).
func TestConcurrentWritersNoLockErrors(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "concurrent.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	const (
		workers = 8
		perWork = 60
	)
	var wg sync.WaitGroup
	errCh := make(chan error, workers*perWork)
	start := make(chan struct{})

	mkEvent := func(w, i int) *models.Event {
		return &models.Event{
			TS:       time.Now().Add(time.Duration(w*1000+i) * time.Millisecond),
			Source:   models.SourceCowrie,
			Kind:     models.KindFailedPass,
			SrcIP:    fmt.Sprintf("198.51.100.%d", w),
			Username: fmt.Sprintf("user%d", i%5),
			SessionID: fmt.Sprintf("s-%d-%d", w, i),
			Raw:      "{}",
		}
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < perWork; i++ {
				switch w % 4 {
				case 0: // direct event insert (journal-tail-like)
					if err := st.InsertEvent(mkEvent(w, i)); err != nil {
						errCh <- fmt.Errorf("insert w%d i%d: %w", w, i, err)
					}
				case 1: // batched append + actor replace (cowrie ingest tick)
					ev := mkEvent(w, i)
					if err := st.AppendEventsAndReplaceActorsAgg(models.SourceCowrie, []*models.Event{ev}, nil); err != nil {
						errCh <- fmt.Errorf("append w%d i%d: %w", w, i, err)
					}
				case 2: // enrichment cache write (geo resolver)
					ip := fmt.Sprintf("203.0.113.%d", i%64)
					if err := st.PutEnrichment(ip, "geo", `{"ok":true}`); err != nil {
						errCh <- fmt.Errorf("enrich w%d i%d: %w", w, i, err)
					}
				case 3: // periodic purge (retention goroutine)
					if err := st.MaintenancePurge(90); err != nil {
						errCh <- fmt.Errorf("purge w%d i%d: %w", w, i, err)
					}
				}
			}
		}(w)
	}

	close(start)
	wg.Wait()
	close(errCh)

	var errs []error
	for e := range errCh {
		errs = append(errs, e)
	}
	if len(errs) > 0 {
		t.Fatalf("%d concurrent write error(s); first: %v", len(errs), errs[0])
	}
}

// TestSlowReadDoesNotBlockWrites is the regression guard for the review's HIGH
// finding: with SetMaxOpenConns(1) a long-running analytics read held the only
// connection and stalled live ingest. With a multi-conn pool + writeMu, a read
// in flight must NOT block a concurrent write.
func TestSlowReadDoesNotBlockWrites(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "slowread.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	// Seed some events so a read has rows to iterate.
	for i := 0; i < 500; i++ {
		if err := st.InsertEvent(&models.Event{
			TS: time.Now().Add(time.Duration(i) * time.Second), Source: models.SourceCowrie,
			Kind: models.KindFailedPass, SrcIP: "1.2.3.4", Raw: "{}",
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// Open a read and hold its rows open (simulating a slow streaming scan that
	// keeps a connection checked out).
	rows, err := st.db.Query(`SELECT id FROM events`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	rows.Next() // hold the connection mid-iteration
	defer rows.Close()

	// A write must complete promptly despite the read holding a connection.
	done := make(chan error, 1)
	go func() {
		done <- st.InsertEvent(&models.Event{
			TS: time.Now(), Source: models.SourceCowrie, Kind: models.KindCommand,
			SrcIP: "5.6.7.8", Command: "id", Raw: "{}",
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("write during slow read failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("write blocked by an in-flight read (pool starvation regression)")
	}
}
