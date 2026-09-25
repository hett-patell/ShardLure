package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTailscaleDoesNotPermitTokenlessWildcard(t *testing.T) {
	t.Setenv("SHARDLURE_DASH_TOKEN", "")
	s := New(nil, newAuthTestServer(t, "").keys, "0.0.0.0:0", Options{TailscaleMode: true})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.RunContext(ctx); err == nil || !strings.Contains(err.Error(), "WILDCARD") {
		t.Fatalf("wildcard bind accepted: %v", err)
	}
}

func TestHandlerDrainRejectsNewWorkAndJoinsInFlight(t *testing.T) {
	var drain handlerDrain
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	h := drain.wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-release }))
	go func() { h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil)); close(finished) }()
	<-entered
	drain.stop()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("new request status=%d", rec.Code)
	}
	select {
	case <-finished:
		t.Fatal("handler returned before release")
	default:
	}
	close(release)
	drain.wait()
	<-finished
}
