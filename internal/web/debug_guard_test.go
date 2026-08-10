package web

import (
	"net/http"
	"net/http/httptest"
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
