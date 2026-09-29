package web

import (
	"context"
	"net/http"
	"sync"
)

// stop closes admission before waiting, so no WaitGroup Add can race Wait.
// Request handlers retain access to the store/MMDB until the last one exits.
type handlerDrain struct {
	mu       sync.Mutex
	stopping bool
	wg       sync.WaitGroup
	// ctx is cancelled by stop: background cache refreshes run their store
	// reads on it, so a shutdown interrupts an in-flight scan (modernc calls
	// sqlite3_interrupt when the context is done) instead of RunContext
	// waiting for it, and nothing keeps reading a store about to close.
	// Created lazily so the zero value works (bg is a value field of Server).
	once   sync.Once
	ctx    context.Context
	cancel context.CancelFunc
}

// context returns the drain's context: live until stop, cancelled after.
func (d *handlerDrain) context() context.Context {
	d.once.Do(func() { d.ctx, d.cancel = context.WithCancel(context.Background()) })
	return d.ctx
}

func (d *handlerDrain) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		if d.stopping {
			d.mu.Unlock()
			http.Error(w, "shutting down", http.StatusServiceUnavailable)
			return
		}
		d.wg.Add(1)
		d.mu.Unlock()
		defer d.wg.Done()
		next.ServeHTTP(w, r)
	})
}
func (d *handlerDrain) stop() {
	d.mu.Lock()
	d.stopping = true
	d.mu.Unlock()
	d.context() // ensure created, so a later context() call sees it cancelled
	d.cancel()
}

// enter admits one unit of background work unless stopping; leave ends it.
func (d *handlerDrain) enter() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopping {
		return false
	}
	d.wg.Add(1)
	return true
}
func (d *handlerDrain) leave() { d.wg.Done() }
func (d *handlerDrain) wait()  { d.wg.Wait() }
