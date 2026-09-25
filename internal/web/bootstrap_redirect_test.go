package web

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The ?token= bootstrap redirect must stay on this origin whatever request
// target the client sent. An absolute-form target keeps its scheme and host
// in r.URL, so redirecting to r.URL.String() sent the browser off-site.
func TestTokenBootstrapRedirectStaysOnOrigin(t *testing.T) {
	const tok = "s3cret-token"
	s := newAuthTestServer(t, tok)
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndexAuthOnly)
	ts := httptest.NewServer(mux)
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")
	for _, target := range []string{
		"http://evil.example/?token=" + tok,
		"//evil.example/?token=" + tok,
		"/\\evil.example/?token=" + tok,
		"/%2F%2Fevil.example/?token=" + tok,
		"/?token=" + tok + "&next=//evil.example",
	} {
		conn, err := net.Dial("tcp", host)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target, host)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		conn.Close()
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		loc := resp.Header.Get("Location")
		t.Logf("%-48q -> %d Location=%q", target, resp.StatusCode, loc)
		if loc == "" {
			continue
		}
		if !strings.HasPrefix(loc, "/") || strings.HasPrefix(loc, "//") || strings.HasPrefix(loc, "/\\") {
			t.Errorf("%s redirected off-origin: %q", target, loc)
		}
	}
}

func (s *Server) handleIndexAuthOnly(w http.ResponseWriter, r *http.Request) {
	if s.requirePageAuth(w, r) {
		w.WriteHeader(http.StatusOK)
	}
}
