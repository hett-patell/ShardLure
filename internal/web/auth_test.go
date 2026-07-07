package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
)

// newAuthTestServer builds a Server whose keystore holds the given dashboard
// token (empty = auth disabled). The token now lives in the keystore, not a
// struct field, so tests seed it there.
func newAuthTestServer(t *testing.T, token string) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatalf("settings.Load: %v", err)
	}
	if token != "" {
		if err := keys.Set(settings.KeyDashToken, token); err != nil {
			t.Fatalf("seed token: %v", err)
		}
	}
	return &Server{keys: keys}
}

// TestAuthGates is the regression guard for HIGH-2: a configured dashboard
// token must NOT make the dashboard unreachable. Page routes accept ?token=
// (a browser navigation can't set a header); API routes stay header-only so
// the token never lands in an XHR URL / access log.
func TestAuthGates(t *testing.T) {
	const tok = "s3cret-token"
	s := newAuthTestServer(t, tok)

	req := func(target, header, query string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if header != "" {
			r.Header.Set("Authorization", "Bearer "+header)
		}
		if query != "" {
			q := r.URL.Query()
			q.Set("token", query)
			r.URL.RawQuery = q.Encode()
		}
		return r
	}

	cases := []struct {
		name   string
		page   bool // true → requirePageAuth, false → requireDashboardAuth
		header string
		query  string
		wantOK bool
	}{
		{"page valid header", true, tok, "", true},
		{"page valid query", true, "", tok, true}, // the HIGH-2 fix
		{"page bad query", true, "", "wrong", false},
		{"page no creds", true, "", "", false},
		{"api valid header", false, tok, "", true},
		{"api query rejected", false, "", tok, false}, // header-only stays header-only
		{"api bad header", false, "wrong", "", false},
		{"api no creds", false, "", "", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			r := req("/", c.header, c.query)
			var ok bool
			if c.page {
				ok = s.requirePageAuth(rec, r)
			} else {
				ok = s.requireDashboardAuth(rec, r)
			}
			if ok != c.wantOK {
				t.Fatalf("auth = %v, want %v (code %d)", ok, c.wantOK, rec.Code)
			}
			if !c.wantOK && rec.Code != http.StatusUnauthorized {
				t.Fatalf("denied request should 401, got %d", rec.Code)
			}
		})
	}
}

// TestPublicBindClassification is the MED-5 regression guard: a token-less
// dashboard refuses to start only on a genuinely public bind, while loopback,
// private, CGNAT/Tailscale, wildcard (:8080 / 0.0.0.0) and hostnames stay a
// warning (the documented behind-a-firewall cases).
func TestPublicBindClassification(t *testing.T) {
	refuse := []string{
		"8.8.8.8:8080",                // public v4
		"203.0.113.10:8080",           // public v4 (TEST-NET-3, but global-unicast)
		"[2606:4700:4700::1111]:8080", // public v6
	}
	for _, addr := range refuse {
		ip := listenHostIP(addr)
		if ip == nil || !isPublicIP(ip) {
			t.Errorf("%s should be classified public (refuse start), got ip=%v", addr, ip)
		}
	}

	warnOnly := []string{
		":8080",            // wildcard — can't tell, warn
		"0.0.0.0:8080",     // wildcard
		"[::]:8080",        // v6 wildcard
		"127.0.0.1:8080",   // loopback
		"192.168.1.5:8080", // private
		"10.0.0.5:8080",    // private
		"100.64.0.5:8080",  // CGNAT / Tailscale
		"localhost:8080",   // hostname
	}
	for _, addr := range warnOnly {
		ip := listenHostIP(addr)
		if ip != nil && isPublicIP(ip) {
			t.Errorf("%s should NOT be classified public (warn only), got ip=%v", addr, ip)
		}
	}
}

// TestAuthDisabledAllowsAll: with no token configured, both gates are open.
func TestAuthDisabledAllowsAll(t *testing.T) {
	t.Setenv(settings.KeyDashToken, "") // ensure no env token leaks in
	s := newAuthTestServer(t, "")
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if !s.requirePageAuth(rec, r) || !s.requireDashboardAuth(rec, r) {
		t.Fatal("unset token must allow all requests")
	}
}
