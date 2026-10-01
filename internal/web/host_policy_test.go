package web

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// startHostTestServer runs s through RunContext (the host check wraps the
// live handler, not the mux) with a trivial /test/ok route.
func startHostTestServer(t *testing.T, s *Server) string {
	t.Helper()
	s.addr = "127.0.0.1:0"
	s.testRoutes = func(mux *http.ServeMux) {
		mux.HandleFunc("/test/ok", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	}
	bound := make(chan string, 1)
	s.onListening = func(a net.Addr) { bound <- a.String() }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.RunContext(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case addr := <-bound:
		return addr
	case err := <-done:
		t.Fatalf("listener failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("listener not announced")
	}
	return ""
}

func getWithHost(t *testing.T, addr, host string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/test/ok", nil)
	req.Host = host
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	resp, err := (&http.Client{Timeout: 5 * time.Second, Transport: transport}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// TestOpenModeRefusesUnknownHost pins fix-D M3 (DNS rebinding). In open mode
// "same-origin" is judged against the request's own Host, so a page at
// http://evil.example:8080 whose name rebinds to the dashboard's address is
// same-origin with itself and passes every browser-label check. A Host the
// deployment does not answer to is refused before any route runs.
func TestOpenModeRefusesUnknownHost(t *testing.T) {
	t.Setenv("SHARDLURE_DASH_TOKEN", "")
	prev := machineHostname
	machineHostname = func() (string, error) { return "Honeypot-Arm", nil }
	t.Cleanup(func() { machineHostname = prev })
	s := newAuthTestServer(t, "")
	s.publicOriginHost = "dash.example.org"
	addr := startHostTestServer(t, s)
	_, port, _ := net.SplitHostPort(addr)
	for _, tc := range []struct {
		host string
		want int
	}{
		{addr, http.StatusOK},                           // the listen address
		{"127.0.0.1", http.StatusOK},                    // loopback, any port
		{"localhost:" + port, http.StatusOK},            // localhost
		{"LOCALHOST.", http.StatusOK},                   // case and trailing dot
		{"[::1]:" + port, http.StatusOK},                // IPv6 loopback
		{"dash.example.org", http.StatusOK},             // dashboard.public_origin
		{"honeypot-arm:" + port, http.StatusOK},         // MagicDNS short name
		{"honeypot-arm.tail1234.ts.net", http.StatusOK}, // MagicDNS FQDN
		{"evil.example:" + port, http.StatusMisdirectedRequest},
		{"honeypot-arm.evil.example", http.StatusMisdirectedRequest},
		{"other.tail1234.ts.net", http.StatusMisdirectedRequest},
		{"honeypot-arm.a.b.ts.net", http.StatusMisdirectedRequest},
		{"sub.dash.example.org", http.StatusMisdirectedRequest},
		{"localhost.evil.example", http.StatusMisdirectedRequest},
		{"10.0.0.9:" + port, http.StatusMisdirectedRequest}, // an IP that is not ours
	} {
		if got := getWithHost(t, addr, tc.host); got != tc.want {
			t.Errorf("Host %q = %d, want %d", tc.host, got, tc.want)
		}
	}
}

// Token mode keeps its behaviour: a bearer header cannot be forged by a
// rebinding page, and a reverse proxy may present any name.
func TestTokenModeDoesNotCheckHost(t *testing.T) {
	s := newAuthTestServer(t, "tok")
	addr := startHostTestServer(t, s)
	if got := getWithHost(t, addr, "evil.example"); got != http.StatusOK {
		t.Fatalf("token mode Host check = %d", got)
	}
}
