package web

import (
	"context"
	"github.com/networkshard/shardlure/internal/observability"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStartupGatePreservesAuthMethodsAndOperationalAccess(t *testing.T) {
	s := newAuthTestServer(t, "inert-token")
	s.monitor = observability.New(time.Now, 0)
	called := false
	handler := s.guardRead(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(200) })
	for _, tc := range []struct {
		method, token string
		want          int
	}{{"GET", "", 401}, {"GET", "inert-token", 503}, {"POST", "inert-token", 405}} {
		r := httptest.NewRequest(tc.method, "/api/inert", nil)
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != tc.want {
			t.Errorf("startup %s=%d want %d", tc.method, w.Code, tc.want)
		}
		if w.Code == 503 && w.Header().Get("Retry-After") == "" {
			t.Error("startup retry guidance missing")
		}
	}
	if called {
		t.Fatal("application handler entered while seeding")
	}
	r := httptest.NewRequest("GET", "/healthz", nil)
	r.Header.Set("Authorization", "Bearer inert-token")
	w := httptest.NewRecorder()
	s.guardOperationalRead(s.handleHealth)(w, r)
	if w.Code != 200 {
		t.Fatal("startup hid operational liveness")
	}
	s.monitor.SetPhase(observability.Serving)
	r = httptest.NewRequest("GET", "/api/inert", nil)
	r.Header.Set("Authorization", "Bearer inert-token")
	handler(httptest.NewRecorder(), r)
	if !called {
		t.Fatal("serving application still gated")
	}
}

func TestStartupListenerExposesPrivateOperationsBeforeReadiness(t *testing.T) {
	s := newAuthTestServer(t, "inert-token")
	s.addr = "127.0.0.1:0"
	s.monitor = observability.New(time.Now, 0)
	bound := make(chan string, 1)
	s.onListening = func(addr net.Addr) { bound <- addr.String() }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.RunContext(ctx) }()
	var addr string
	select {
	case addr = <-bound:
	case err := <-done:
		t.Fatalf("listener failed: %v", err)
	case <-time.After(time.Second):
		t.Fatal("listener not announced")
	}
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: time.Second, Transport: transport}
	for _, tc := range []struct {
		path string
		want int
	}{{"/healthz", 200}, {"/readyz", 503}, {"/api/dashboard", 503}} {
		req, _ := http.NewRequest("GET", "http://"+addr+tc.path, nil)
		req.Header.Set("Authorization", "Bearer inert-token")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Fatalf("startup route %s=%d", tc.path, resp.StatusCode)
		}
	}
	transport.CloseIdleConnections()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server failed to join")
	}
}
