package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyOriginAndCookiePolicy(t *testing.T) {
	p, err := NewOriginPolicy("https://dash.example.test:443", []string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	s := newAuthTestServer(t, "inert-token")
	s.originPolicy = p
	req := httptest.NewRequest("POST", "http://dash.example.test/api/settings/save", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Origin", "https://dash.example.test")
	req.AddCookie(&http.Cookie{Name: "shardlure_session", Value: "inert-token"})
	if origin, secure, err := p.Expected(req); err != nil || origin != "https://dash.example.test" || !secure {
		t.Fatalf("expected=%q secure=%v err=%v", origin, secure, err)
	}
	if !s.requireDashboardAuth(httptest.NewRecorder(), req) {
		t.Fatal("trusted HTTPS origin denied")
	}
	req.RemoteAddr = "192.0.2.1:3"
	req.Header.Set("X-Forwarded-Proto", "https")
	if s.requireDashboardAuth(httptest.NewRecorder(), req) {
		t.Fatal("spoofed forwarding trusted")
	}
	req.RemoteAddr = "127.0.0.1:3"
	req.Host = "wrong.example.test"
	if s.requireDashboardAuth(httptest.NewRecorder(), req) {
		t.Fatal("proxy Host mismatch accepted")
	}
	req = httptest.NewRequest("GET", "http://dash.example.test/?token=inert-token", nil)
	req.RemoteAddr = "127.0.0.1:4"
	w := httptest.NewRecorder()
	s.requirePageAuth(w, req)
	if cookies := w.Result().Cookies(); len(cookies) != 1 || !cookies[0].Secure {
		t.Fatal("proxy bootstrap lost Secure cookie")
	}
	req = httptest.NewRequest("POST", "http://dash.example.test/api/settings/token/rotate", nil)
	req.RemoteAddr = "127.0.0.1:5"
	w = httptest.NewRecorder()
	s.handleTokenRotate(w, req)
	if cookies := w.Result().Cookies(); len(cookies) != 1 || !cookies[0].Secure {
		t.Fatal("proxy rotation lost Secure cookie")
	}
	open := newAuthTestServer(t, "")
	open.originPolicy = p
	req = httptest.NewRequest("GET", "/healthz", nil)
	req.RemoteAddr = "127.0.0.1:4"
	w = httptest.NewRecorder()
	open.guardOperationalRead(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })(w, req)
	if w.Code != 403 {
		t.Fatal("local proxy obtained anonymous operational access")
	}
}

func TestProxyRejectsAmbiguousConfiguration(t *testing.T) {
	for _, origin := range []string{"http://user:secret@x", "https://x/path", "https://x?", "https://x#", "ftp://x", "https://x:70000", "https://"} {
		if _, err := NewOriginPolicy(origin, []string{"127.0.0.1"}); err == nil {
			t.Errorf("invalid origin accepted: %q", origin)
		}
	}
	for _, proxy := range []string{"localhost", "0.0.0.0/0", "::/0", "::ffff:0.0.0.0/96", "invalid"} {
		if _, err := NewOriginPolicy("https://x", []string{proxy}); err == nil {
			t.Errorf("unsafe proxy accepted: %q", proxy)
		}
	}
	if _, err := NewOriginPolicy("https://x", nil); err == nil {
		t.Fatal("partial configuration accepted")
	}
	if _, err := NewOriginPolicy("", []string{"127.0.0.1"}); err == nil {
		t.Fatal("partial proxy configuration accepted")
	}
}

// Regression (whole-branch review): with no dashboard token, the open mode
// trusts "the caller is on this host", but a trusted reverse proxy connects
// from that same loopback address on behalf of Internet clients. Only the
// operational routes refused it; /debug/* (heap, cmdline, goroutines), the
// /api/* surface (including credential exports) and the pages did not.
func TestTrustedProxyNeverGetsTokenlessAccess(t *testing.T) {
	p, err := NewOriginPolicy("https://dash.example.test", []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	open := newAuthTestServer(t, "")
	open.originPolicy = p
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }
	for name, check := range map[string]func(*http.Request) int{
		"debug": func(r *http.Request) int {
			w := httptest.NewRecorder()
			open.guardDebug(ok)(w, r)
			return w.Code
		},
		"api": func(r *http.Request) int {
			w := httptest.NewRecorder()
			if !open.requireDashboardAuth(w, r) {
				return w.Code
			}
			return 200
		},
		"page": func(r *http.Request) int {
			w := httptest.NewRecorder()
			if !open.requirePageAuth(w, r) {
				return w.Code
			}
			return 200
		},
	} {
		r := httptest.NewRequest("GET", "http://dash.example.test/x", nil)
		r.RemoteAddr = "127.0.0.1:4242"
		if code := check(r); code == 200 {
			t.Errorf("%s: token-less request forwarded by the trusted proxy was served", name)
		}
		// A genuinely local, non-proxy peer keeps the documented open mode.
		r = httptest.NewRequest("GET", "http://127.0.0.1/x", nil)
		r.RemoteAddr = "[::1]:4242"
		if code := check(r); code != 200 {
			t.Errorf("%s: local non-proxy peer lost open-mode access (%d)", name, code)
		}
	}
}
