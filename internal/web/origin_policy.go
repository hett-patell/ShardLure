package web

import (
	"github.com/networkshard/shardlure/internal/netmatch"
	"net/http"
)

type OriginPolicy = netmatch.OriginPolicy

func NewOriginPolicy(origin string, trusted []string) (OriginPolicy, error) {
	return netmatch.NewOriginPolicy(origin, trusted)
}
func (s *Server) sameOriginRequest(r *http.Request) bool {
	expected, _, err := s.originPolicy.Expected(r)
	if err != nil {
		return false
	}
	supplied, err := netmatch.CanonicalOrigin(r.Header.Get("Origin"))
	return err == nil && supplied == expected
}

const crossSiteRefusal = "cross-site request refused"

// refuseCrossSiteBrowser closes the open-mode CSRF hole on the mutating routes.
//
// With no dashboard token the API needs no credentials at all, so any web page
// the operator visits could make their browser POST to the dashboard (save a
// setting, report an IP to AbuseIPDB, rewrite a campaign) or GET the
// quota-spending VirusTotal lookup with an <img>. Token mode does not have this
// gap: a bearer header cannot be forged cross-site, and requireDashboardAuth
// already holds cookie sessions to same-origin.
//
// Browsers label every such request: Sec-Fetch-Site (all current engines) and,
// on non-GET requests, Origin. A request carrying neither is not a browser -
// curl, the CLI, scripts - and cannot be driven by a foreign page, so it stays
// allowed. A browser request is allowed only when it proves it came from the
// dashboard itself:
//   - Sec-Fetch-Site "same-origin" is the browser's own verdict and a page
//     cannot set it, so it is accepted on its own. Also matching Origin against
//     the Host the server sees added nothing and broke every write behind a
//     TLS-terminating or Host-rewriting proxy (tailscale serve, Caddy) with no
//     dashboard.public_origin: the browser says https://name, the server sees
//     http://127.0.0.1:8080.
//   - With no Sec-Fetch-Site (an engine too old to send it), an Origin equal to
//     the dashboard's origin.
//
// Any other Sec-Fetch-Site value - including "same-site", a sibling host on
// the same registrable domain, and "none" - is refused, as is a mismatched or
// "null" Origin.
func (s *Server) refuseCrossSiteBrowser(w http.ResponseWriter, r *http.Request) bool {
	site := r.Header.Get("Sec-Fetch-Site")
	origin := r.Header.Get("Origin")
	switch {
	case site == "" && origin == "":
		return false
	case site == "same-origin":
		return false
	case site == "" && s.sameOriginRequest(r):
		return false
	}
	http.Error(w, crossSiteRefusal, http.StatusForbidden)
	return true
}
