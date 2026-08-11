package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGuardDebug locks in the /debug/* policy: in token-less "open mode" the
// profiling endpoints must NOT ride along with the open dashboard — they leak
// process memory, file paths, and flag values. Open mode only admits loopback
// peers; with a token configured, guardDebug behaves exactly like guard.
func TestGuardDebug(t *testing.T) {
	okHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	cases := []struct {
		name       string
		token      string // "" = open mode
		remoteAddr string
		header     string // bearer token sent
		wantCode   int
	}{
		{"open mode loopback allowed", "", "127.0.0.1:54321", "", http.StatusOK},
		{"open mode loopback v6 allowed", "", "[::1]:54321", "", http.StatusOK},
		{"open mode tailnet denied", "", "100.64.0.7:54321", "", http.StatusForbidden},
		{"open mode lan denied", "", "192.168.1.50:54321", "", http.StatusForbidden},
		{"token mode valid token remote allowed", "tok", "100.64.0.7:54321", "tok", http.StatusOK},
		{"token mode bad token remote denied", "tok", "100.64.0.7:54321", "wrong", http.StatusUnauthorized},
		{"token mode no token loopback denied", "tok", "127.0.0.1:54321", "", http.StatusUnauthorized},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newAuthTestServer(t, c.token)
			h := s.guardDebug(okHandler)
			r := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
			r.RemoteAddr = c.remoteAddr
			if c.header != "" {
				r.Header.Set("Authorization", "Bearer "+c.header)
			}
			w := httptest.NewRecorder()
			h(w, r)
			if w.Code != c.wantCode {
				t.Errorf("code = %d, want %d", w.Code, c.wantCode)
			}
		})
	}
}

func TestIsLoopbackPeer(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:80":    true,
		"[::1]:8080":      true,
		"127.0.0.53:1234": true,
		"100.64.0.1:443":  false,
		"192.168.1.1:22":  false,
		"8.8.8.8:53":      false,
		"not-an-ip":       false,
		"localhost:8080":  false, // hostname, not an IP — fail closed
		"":                false,
	}
	for addr, want := range cases {
		if got := isLoopbackPeer(addr); got != want {
			t.Errorf("isLoopbackPeer(%q) = %v, want %v", addr, got, want)
		}
	}
}

// "/" is a catch-all in net/http's ServeMux, so without an explicit path check
// every typo and scanner probe returned 200 plus the entire dashboard HTML —
// and unknown /api/* paths were answered by the PAGE auth gate (which accepts
// ?token=) instead of the header-only API gate, handing API clients HTML.
//
// The 404 must also stay behind auth: if an unauthorised caller saw 404 for a
// fake path and 401 for a real one, they could enumerate the route table.
func TestUnmatchedPathsAreNotTheDashboard(t *testing.T) {
	cases := []struct {
		name     string
		token    string // "" = open mode
		path     string
		header   string
		wantCode int
		wantJSON bool
	}{
		{"open: root serves dashboard", "", "/", "", http.StatusOK, false},
		{"open: unknown page 404s", "", "/nonexistent", "", http.StatusNotFound, false},
		{"open: unknown api 404s as JSON", "", "/api/bogus", "", http.StatusNotFound, true},
		{"open: deep unknown api 404s", "", "/api/intel/nope", "", http.StatusNotFound, true},

		// With a token and no credentials, EVERYTHING is 401 — real or not.
		{"token: unknown api unauthorised", "tok", "/api/bogus", "", http.StatusUnauthorized, false},
		{"token: unknown page unauthorised", "tok", "/nonexistent", "", http.StatusUnauthorized, false},
		{"token: real api unauthorised", "tok", "/api/dashboard", "", http.StatusUnauthorized, false},

		// Authorised callers see the real distinction.
		{"token: authorised unknown api 404s", "tok", "/api/bogus", "tok", http.StatusNotFound, true},
		{"token: authorised unknown page 404s", "tok", "/nonexistent", "tok", http.StatusNotFound, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newAuthTestServer(t, c.token)
			var h http.HandlerFunc
			if strings.HasPrefix(c.path, "/api/") {
				h = s.guard(s.handleAPINotFound)
			} else {
				h = s.handleIndex
			}
			r := httptest.NewRequest(http.MethodGet, c.path, nil)
			if c.header != "" {
				r.Header.Set("Authorization", "Bearer "+c.header)
			}
			w := httptest.NewRecorder()
			h(w, r)
			if w.Code != c.wantCode {
				t.Fatalf("code = %d, want %d (body %q)", w.Code, c.wantCode, w.Body.String())
			}
			body := w.Body.String()
			if c.wantJSON {
				if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
					t.Errorf("Content-Type = %q, want JSON", ct)
				}
				if strings.Contains(body, "<!doctype") || strings.Contains(body, "<html") {
					t.Errorf("API path returned HTML: %q", body)
				}
			}
			if c.wantCode == http.StatusNotFound && strings.Contains(body, "ShardLure telemetry") {
				t.Errorf("404 leaked the dashboard body")
			}
		})
	}
}
