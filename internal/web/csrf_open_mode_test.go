package web

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/networkshard/shardlure/internal/settings"
)

// mutatingRoutes derives every route registered with bare guard (the
// mutating/quota-spending half of the API) from server.go itself, the same way
// route_method_test.go derives its rule: a hand-kept list could miss a route.
func mutatingRoutes(t *testing.T) []string {
	t.Helper()
	src := readSource(t, "server.go")
	var out []string
	for _, m := range regexp.MustCompile(`mux\.HandleFunc\("([^"]+)", s\.guard\(s\.`).FindAllStringSubmatch(src, -1) {
		out = append(out, m[1])
	}
	if len(out) < 10 {
		t.Fatalf("found only %d guard routes: %v", len(out), out)
	}
	return out
}

// TestOpenModeRefusesCrossSiteWrites pins the open-mode CSRF boundary. With no
// dashboard token every /api/* route is reachable without credentials, so a
// page on any other site could make the operator's browser POST to the
// dashboard (a settings save, an AbuseIPDB report, a campaign edit). Browsers
// label such requests with Origin and/or Sec-Fetch-Site; clients that send
// neither (curl, the CLI) are not browsers and cannot be driven cross-site, so
// they keep working.
func TestOpenModeRefusesCrossSiteWrites(t *testing.T) {
	t.Setenv(settings.KeyDashToken, "")
	s := newAuthTestServer(t, "")
	mux := s.routes()
	routes := mutatingRoutes(t)

	type hdr map[string]string
	refused := []struct {
		name string
		h    hdr
	}{
		{"foreign origin", hdr{"Origin": "https://attacker.example"}},
		{"null origin", hdr{"Origin": "null"}},
		{"cross-site fetch", hdr{"Sec-Fetch-Site": "cross-site"}},
		{"same-site fetch", hdr{"Sec-Fetch-Site": "same-site"}},
		{"cross-site with own origin", hdr{"Sec-Fetch-Site": "cross-site", "Origin": "http://example.com"}},
		{"own origin wrong port", hdr{"Origin": "http://example.com:8081"}},
	}
	allowed := []struct {
		name string
		h    hdr
	}{
		{"no browser headers (curl/CLI)", hdr{}},
		{"same-origin fetch", hdr{"Sec-Fetch-Site": "same-origin", "Origin": "http://example.com"}},
		{"own origin only", hdr{"Origin": "http://example.com"}},
		{"same-origin fetch only", hdr{"Sec-Fetch-Site": "same-origin"}},
		// Behind a TLS-terminating proxy (tailscale serve, Caddy) with no
		// public_origin, the browser's Origin is https:// while the server
		// sees plain HTTP; a Host-rewriting proxy changes the host too. The
		// browser's own same-origin verdict is authoritative in both.
		{"https behind proxy", hdr{"Sec-Fetch-Site": "same-origin", "Origin": "https://example.com"}},
		{"host rewritten by proxy", hdr{"Sec-Fetch-Site": "same-origin", "Origin": "https://dash.tailnet.ts.net"}},
	}
	send := func(method, route string, h hdr) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://example.com"+route, nil)
		for k, v := range h {
			r.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec
	}
	for _, route := range routes {
		for _, c := range refused {
			// GET too, for a browser that labels it (HTTPS origins). Over plain
			// HTTP browsers send no Sec-Fetch-* at all, so an <img> GET passes
			// this gate: the quota-spending GETs are closed separately by
			// requireQuotaHeader (TestOpenModeQuotaGETsNeedCustomHeader).
			for _, method := range []string{http.MethodPost, http.MethodGet} {
				rec := send(method, route, c.h)
				if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), crossSiteRefusal) {
					t.Errorf("%s %s (%s): status %d body %q, want 403 cross-site refusal",
						method, route, c.name, rec.Code, strings.TrimSpace(rec.Body.String()))
				}
			}
		}
		for _, c := range allowed {
			// PUT: every POST-only handler answers 405 before touching the
			// (absent) store, which proves the request got past the gate.
			rec := send(http.MethodPut, route, c.h)
			if strings.Contains(rec.Body.String(), crossSiteRefusal) {
				t.Errorf("PUT %s (%s): refused as cross-site, want it through the gate", route, c.name)
			}
		}
	}
	t.Logf("checked %d mutating routes: %v", len(routes), routes)
}

// Browsers send no Sec-Fetch-* headers to a plain-HTTP origin - the primary
// http://<tailnet-ip> deployment - so a cross-site <img src=".../payload/vt?sha=">
// passes the cross-site gate and spends VirusTotal quota; enrich fans out to
// seven providers. In open mode those GETs need a custom header, which a
// foreign page cannot send without a CORS preflight the server never grants.
func TestOpenModeQuotaGETsNeedCustomHeader(t *testing.T) {
	t.Setenv(settings.KeyDashToken, "")
	s := newAuthTestServer(t, "")
	mux := s.routes()
	for _, route := range []string{"/api/intel/payload/vt", "/api/intel/enrich"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com"+route, nil))
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), quotaHeader+": 1") {
			t.Errorf("GET %s without %s = %d %q, want 403 naming the header", route, quotaHeader, rec.Code, rec.Body.String())
		}
		r := httptest.NewRequest(http.MethodGet, "http://example.com"+route, nil)
		r.Header.Set(quotaHeader, "1")
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		if rec.Code != http.StatusBadRequest { // reached the handler: missing sha/ip
			t.Errorf("GET %s with the header = %d %q, want the handler's 400", route, rec.Code, rec.Body.String())
		}
	}
	// Token mode is unchanged: the bearer header already needs a preflight.
	st := newAuthTestServer(t, "tok")
	tmux := st.routes()
	for _, route := range []string{"/api/intel/payload/vt", "/api/intel/enrich"} {
		r := httptest.NewRequest(http.MethodGet, "http://example.com"+route, nil)
		r.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		tmux.ServeHTTP(rec, r)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("token mode GET %s = %d %q, want the handler's 400", route, rec.Code, rec.Body.String())
		}
	}
}

// The console must send the header in open mode too, so its fetch wrapper is
// installed unconditionally (it used to return early without a token).
func TestIntelFetchWrapperSendsQuotaHeader(t *testing.T) {
	i := strings.Index(intelHTML, "var _fetch = window.fetch.bind(window);")
	if i < 0 {
		t.Fatal("fetch wrapper not found")
	}
	head := intelHTML[max(0, i-200):i]
	if strings.Contains(head, "if (!DASH_TOKEN) return;") {
		t.Error("fetch wrapper still skipped in open mode")
	}
	if !strings.Contains(intelHTML[i:i+900], "h.set('X-ShardLure-Request', '1');") {
		t.Error("fetch wrapper does not set X-ShardLure-Request")
	}
}
