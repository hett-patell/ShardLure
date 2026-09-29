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
			// GET too: /api/intel/payload/vt spends VirusTotal quota on GET, and
			// an <img src> needs no CORS at all.
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
