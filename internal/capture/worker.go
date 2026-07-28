package capture

import (
	"context"
	"log"
	"math"
	"sync"
	"time"

	"github.com/networkshard/shardlure/internal/store"
)

// ArtifactWorker is a capacity-one coalescing worker that polls the store for
// due artifact captures and processes them one at a time. It replaces the
// process-lifetime doneKeys memo with durable DB-backed retry state.
type ArtifactWorker struct {
	st          *store.Store
	fetch       *SafeFetcher
	maxAttempts int
	leaseDur    time.Duration
	mu          sync.Mutex
	busy        bool // coalesce: one in-flight fetch at a time
}

// NewArtifactWorker creates a worker bound to the given store and fetcher.
// maxAttempts caps the retry budget; leaseDur is the per-claim lease window.
func NewArtifactWorker(st *store.Store, fetch *SafeFetcher, maxAttempts int, leaseDur time.Duration) *ArtifactWorker {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if leaseDur <= 0 {
		leaseDur = 2 * time.Minute
	}
	return &ArtifactWorker{
		st:          st,
		fetch:       fetch,
		maxAttempts: maxAttempts,
		leaseDur:    leaseDur,
	}
}

// Run starts the polling loop. It returns when ctx is cancelled.
func (w *ArtifactWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

func (w *ArtifactWorker) tick(ctx context.Context) {
	w.mu.Lock()
	if w.busy {
		w.mu.Unlock()
		return
	}
	w.busy = true
	w.mu.Unlock()

	defer func() {
		w.mu.Lock()
		w.busy = false
		w.mu.Unlock()
	}()

	now := time.Now().UTC()
	urls, err := w.st.DueArtifactCaptures(now, 1, w.maxAttempts)
	if err != nil {
		log.Printf("capture-worker: query due: %v", err)
		return
	}
	if len(urls) == 0 {
		return
	}
	url := urls[0]

	// We don't know the current attempt_count from the query above, so read
	// it from the row. If the row disappeared or changed, the claim will fail
	// with ErrClaimStale and we move on.
	attempt := w.currentAttempt(url)
	leaseUntil := now.Add(w.leaseDur)
	if err := w.st.ClaimArtifactCapture(url, now, leaseUntil, attempt); err != nil {
		if err != store.ErrClaimStale {
			log.Printf("capture-worker: claim %s: %v", url, err)
		}
		return
	}

	deadline, cancel := context.WithTimeout(ctx, w.leaseDur)
	defer cancel()

	res, fetchErr := w.fetch.Fetch(deadline, url)
	nextAttempt := attempt + 1
	if res != nil && res.Status == "fetched" {
		if err := w.st.CompleteArtifactCapture(url, nextAttempt, "fetched", res.Detail, res.LocalPath, res.SHA256, res.Size, nil); err != nil {
			log.Printf("capture-worker: complete %s: %v", url, err)
		}
		return
	}

	// Failure: schedule retry with exponential backoff or mark permanent.
	detail := ""
	if res != nil {
		detail = res.Detail
	}
	if fetchErr != nil && detail == "" {
		detail = fetchErr.Error()
	}

	if nextAttempt >= w.maxAttempts {
		// Budget exhausted — mark as permanently failed (no more retries).
		_ = w.st.CompleteArtifactCapture(url, nextAttempt, "failed_permanently", detail, "", "", 0, nil)
		return
	}

	// Exponential backoff: 30s, 60s, 120s, 240s, … capped at 1h.
	backoff := time.Duration(math.Min(
		float64(time.Hour),
		float64(30*time.Second)*math.Pow(2, float64(attempt)),
	))
	next := time.Now().UTC().Add(backoff)
	if err := w.st.CompleteArtifactCapture(url, nextAttempt, "failed", detail, "", "", 0, &next); err != nil {
		log.Printf("capture-worker: schedule retry %s: %v", url, err)
	}
}

// currentAttempt reads the current attempt_count for a URL. Returns 0 if the
// row doesn't exist (the claim will fail anyway).
func (w *ArtifactWorker) currentAttempt(url string) int {
	var n int
	err := w.st.ArtifactAttemptCount(url, &n)
	if err != nil {
		return 0
	}
	return n
}
