package store

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// TestWritePoolIsSerialized asserts the connection pool is pinned to a single
// connection. This is the deterministic guard for the SetMaxOpenConns(1) fix:
// SQLite is single-writer, and capping the pool serializes every statement
// through one connection so the live-mode writer goroutines never race for the
// write lock (which under the default unbounded pool surfaces as intermittent
// "database is locked" after busy_timeout, silently dropping ingest batches).
func TestWritePoolIsSerialized(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "pool.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if got := st.db.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("MaxOpenConnections = %d, want 1 (writes must be serialized)", got)
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
