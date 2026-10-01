package web

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestShutdownCancelsFirstLoadCompute pins fix-D M1: a cache's FIRST value is
// computed synchronously inside a request handler on the drain's context. A
// shutdown must cancel that context before waiting for handlers, or
// srv.Shutdown sits out its whole 30 s window (and handlers.wait() the rest
// of the scan) behind one cold dashboard request.
func TestShutdownCancelsFirstLoadCompute(t *testing.T) {
	t.Setenv("SHARDLURE_DASH_TOKEN", "")
	s := newAuthTestServer(t, "")
	s.addr = "127.0.0.1:0"
	var c swrCache[int]
	started := make(chan struct{})
	s.testRoutes = func(mux *http.ServeMux) {
		mux.HandleFunc("/test/cold", func(w http.ResponseWriter, r *http.Request) {
			_, err := c.get(&s.bg, time.Minute, func(ctx context.Context) (int, time.Time, error) {
				close(started)
				<-ctx.Done() // a long first scan, interrupted only by shutdown
				return 0, time.Time{}, ctx.Err()
			})
			if err != nil {
				http.Error(w, "cancelled", http.StatusServiceUnavailable)
			}
		})
	}
	bound := make(chan string, 1)
	s.onListening = func(a net.Addr) { bound <- a.String() }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.RunContext(ctx) }()
	var addr string
	select {
	case addr = <-bound:
	case err := <-done:
		t.Fatalf("listener failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("listener not announced")
	}
	go func() {
		resp, err := (&http.Client{Timeout: 40 * time.Second}).Get("http://" + addr + "/test/cold")
		if err == nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first compute never started")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown waited on the in-flight first-load compute instead of cancelling it")
	}
}
