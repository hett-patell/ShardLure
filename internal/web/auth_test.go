package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
		name     string
		page     bool // true → requirePageAuth, false → requireDashboardAuth
		header   string
		query    string
		cookie   string
		wantOK   bool
		wantCode int // expected HTTP code for denied cases; 0 = skip check
	}{
		{"page valid header", true, tok, "", "", true, 0},
		{"page valid cookie", true, "", "", tok, true, 0},
		{"page valid query redirects", true, "", tok, "", false, http.StatusFound},
		{"page bad query", true, "", "wrong", "", false, http.StatusUnauthorized},
		{"page bad cookie", true, "", "", "wrong", false, http.StatusUnauthorized},
		{"page no creds", true, "", "", "", false, http.StatusUnauthorized},
		{"api valid header", false, tok, "", "", true, 0},
		{"api query rejected", false, "", tok, "", false, http.StatusUnauthorized},
		{"api cookie rejected", false, "", "", tok, false, http.StatusUnauthorized},
		{"api bad header", false, "wrong", "", "", false, http.StatusUnauthorized},
		{"api no creds", false, "", "", "", false, http.StatusUnauthorized},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			r := req("/", c.header, c.query)
			if c.cookie != "" {
				r.AddCookie(&http.Cookie{Name: "shardlure_session", Value: c.cookie})
			}
			var ok bool
			if c.page {
				ok = s.requirePageAuth(rec, r)
			} else {
				ok = s.requireDashboardAuth(rec, r)
			}
			if ok != c.wantOK {
				t.Fatalf("auth = %v, want %v (code %d)", ok, c.wantOK, rec.Code)
			}
			if !c.wantOK && c.wantCode != 0 && rec.Code != c.wantCode {
				t.Fatalf("denied request should %d, got %d", c.wantCode, rec.Code)
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
	// Wildcards (listenHostIP == nil) are now fail-closed, not warn-only.
	wildcards := []string{":8080", "0.0.0.0:8080", "[::]:8080"}
	for _, addr := range wildcards {
		if ip := listenHostIP(addr); ip != nil {
			t.Errorf("%s should be classified as wildcard (nil), got ip=%v", addr, ip)
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

// TestSecurityHeaders verifies that the securityHeaders middleware sets
// X-Content-Type-Options, X-Frame-Options, and Referrer-Policy on every response.
func TestSecurityHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := securityHeaders(inner)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

// TestCookieBootstrapRedirect verifies that a valid ?token= on a page GET
// sets an HttpOnly shardlure_session cookie and 302-redirects to the clean
// URL without the token, so the bearer never stays in the URL.
func TestCookieBootstrapRedirect(t *testing.T) {
	const tok = "s3cret-token"
	s := newAuthTestServer(t, tok)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/intel?token="+tok+"&foo=bar", nil)
	ok := s.requirePageAuth(rec, r)

	// requirePageAuth returns false because it wrote a redirect (not an error page).
	if ok {
		t.Fatal("expected redirect (ok=false), got true")
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("redirect code = %d, want %d", rec.Code, http.StatusFound)
	}

	loc := rec.Header().Get("Location")
	if strings.Contains(loc, "token=") {
		t.Errorf("redirect location still contains token: %s", loc)
	}
	if !strings.Contains(loc, "foo=bar") {
		t.Errorf("redirect location dropped non-token query param: %s", loc)
	}

	ck := rec.Result().Cookies()
	var found bool
	for _, c := range ck {
		if c.Name == "shardlure_session" {
			found = true
			if c.Value != tok {
				t.Errorf("cookie value = %q, want %q", c.Value, tok)
			}
			if !c.HttpOnly {
				t.Error("cookie should be HttpOnly")
			}
			if c.SameSite != http.SameSiteStrictMode {
				t.Errorf("cookie SameSite = %v, want Strict", c.SameSite)
			}
		}
	}
	if !found {
		t.Error("shardlure_session cookie not set on redirect")
	}
}
