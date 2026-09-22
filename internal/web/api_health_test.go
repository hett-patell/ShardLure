package web

import (
	"github.com/networkshard/shardlure/internal/observability"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestOperationalAuthMethodsAndReadiness(t *testing.T) {
	for _, token := range []string{"", "inert-token"} {
		t.Run(token, func(t *testing.T) {
			s := newAuthTestServer(t, token)
			m := observability.New(time.Now, 0)
			s.monitor = m
			for _, endpoint := range []struct {
				path    string
				handler http.HandlerFunc
			}{{"/healthz", s.handleHealth}, {"/readyz", s.handleReady}, {"/metrics", s.handleMetrics}} {
				for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
					r := httptest.NewRequest(method, endpoint.path, nil)
					r.RemoteAddr = "127.0.0.1:1234"
					if token != "" {
						r.Header.Set("Authorization", "Bearer "+token)
					}
					w := httptest.NewRecorder()
					s.guardOperationalRead(endpoint.handler)(w, r)
					want := http.StatusOK
					if endpoint.path == "/readyz" {
						want = 503
					}
					if method == http.MethodPost {
						want = 405
						if w.Header().Get("Allow") != "GET, HEAD" {
							t.Fatal("missing Allow")
						}
					}
					if w.Code != want {
						t.Fatalf("%s %s=%d", method, endpoint.path, w.Code)
					}
					if method == http.MethodHead && w.Body.Len() != 0 {
						t.Fatal("HEAD response has body")
					}
				}
				r := httptest.NewRequest("GET", endpoint.path+"?token=inert-token", nil)
				r.RemoteAddr = "127.0.0.1:1234"
				w := httptest.NewRecorder()
				s.guardOperationalRead(endpoint.handler)(w, r)
				if w.Code == 200 {
					t.Fatal("query token accepted")
				}
				r = httptest.NewRequest("GET", endpoint.path, nil)
				r.RemoteAddr = "192.0.2.10:99"
				w = httptest.NewRecorder()
				s.guardOperationalRead(endpoint.handler)(w, r)
				if w.Code != 401 && w.Code != 403 {
					t.Fatal("anonymous remote operational access")
				}
			}
			m.SetPhase(observability.Serving)
			m.RecordSample(observability.Sample{At: time.Now(), DatabaseUp: true, DataAccessible: true})
			var wg sync.WaitGroup
			for i := 0; i < 30; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					r := httptest.NewRequest("GET", "/readyz", nil)
					w := httptest.NewRecorder()
					s.handleReady(w, r)
					if w.Code != 200 {
						t.Error("ready scrape failed")
					}
				}()
			}
			wg.Wait()
			m.SetPhase(observability.Draining)
			w := httptest.NewRecorder()
			s.handleHealth(w, httptest.NewRequest("GET", "/healthz", nil))
			if w.Code != 503 {
				t.Fatal("draining process claims health")
			}
		})
	}
}
