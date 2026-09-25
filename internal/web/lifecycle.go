package web

import (
	"net/http"
	"sync"
)

// stop closes admission before waiting, so no WaitGroup Add can race Wait.
// Request handlers retain access to the store/MMDB until the last one exits.
type handlerDrain struct {
	mu       sync.Mutex
	stopping bool
	wg       sync.WaitGroup
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
func (d *handlerDrain) stop() { d.mu.Lock(); d.stopping = true; d.mu.Unlock() }
func (d *handlerDrain) wait() { d.wg.Wait() }
