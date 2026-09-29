package web

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"github.com/networkshard/shardlure/internal/netmatch"
)

// machineHostname is os.Hostname; tests substitute it.
var machineHostname = os.Hostname

// hostPolicy is the set of names an open-mode (token-less) dashboard answers
// to. It closes DNS rebinding (audit-web M3).
//
// Without a token every open-mode check that a request "came from the
// dashboard itself" (Sec-Fetch-Site same-origin, Origin equal to the expected
// origin, the X-ShardLure-Request header) is judged relative to the request's
// own Host. A page at http://evil.example:8080 whose name the attacker then
// re-points at the dashboard's address is same-origin with itself, so its
// requests carry every one of those labels and read the whole API. The one
// thing it cannot change is the Host header its browser sends: evil.example.
// So open mode serves only Hosts that name this dashboard:
//   - the listen IP, exactly (open mode refuses wildcard and hostname binds,
//     so it is always an explicit IP; `--tailscale` makes it the tailnet IP,
//     which is how production is reached: http://100.124.3.67:8080);
//   - loopback IPs and "localhost" (an SSH tunnel or a local browser);
//   - dashboard.public_origin's hostname, exactly;
//   - Tailscale MagicDNS names for this machine: the short hostname, and
//     "<hostname>.<tailnet>.ts.net" with exactly one tailnet label. MagicDNS
//     names come from the machine name, which defaults to the OS hostname; a
//     node renamed in the admin console needs dashboard.public_origin (or a
//     token). ts.net is Tailscale's domain and its machine names resolve
//     only through a tailnet's own MagicDNS (or, for Funnel, to Tailscale's
//     relays), so an attacker's public DNS cannot answer for them. This is
//     the one pattern rather than an exact name: the tailnet label is not
//     knowable offline.
//
// The port is ignored: a rebinding page must already use the dashboard's port
// to reach it, and the hostname is what it cannot fake. A request with no
// Host (HTTP/1.0) is not a browser and passes. Token mode is not checked: a
// bearer header cannot be forged by a rebinding page, and a proxy in front of
// a tokened dashboard may present any name.
type hostPolicy struct {
	listen  netip.Addr // invalid when the listen address is not an IP
	public  string     // lowercase hostname or ""
	machine string     // lowercase short hostname or ""
}

func newHostPolicy(listenAddr, publicHost, machine string) hostPolicy {
	p := hostPolicy{public: normaliseHostName(publicHost)}
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		host = listenAddr
	}
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && ip.Zone() == "" {
		p.listen = ip.Unmap()
	}
	machine = normaliseHostName(machine)
	if i := strings.IndexByte(machine, '.'); i >= 0 {
		machine = machine[:i]
	}
	if validDNSLabel(machine) {
		p.machine = machine
	}
	return p
}

// normaliseHostName lowercases a hostname and drops one trailing root dot.
func normaliseHostName(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

func validDNSLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for _, c := range l {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// allows reports whether a request's Host header names this dashboard.
func (p hostPolicy) allows(hostHeader string) bool {
	if hostHeader == "" {
		return true
	}
	host := hostHeader
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return false
		}
		ip = ip.Unmap()
		return ip.IsLoopback() || (p.listen.IsValid() && ip == p.listen)
	}
	host = normaliseHostName(host)
	switch {
	case host == "localhost":
		return true
	case p.public != "" && host == p.public:
		return true
	case p.machine == "":
		return false
	case host == p.machine:
		return true
	}
	// <machine>.<tailnet>.ts.net, one tailnet label.
	rest, ok := strings.CutPrefix(host, p.machine+".")
	if !ok {
		return false
	}
	tailnet, ok := strings.CutSuffix(rest, ".ts.net")
	return ok && validDNSLabel(tailnet)
}

// publicOriginHostname returns dashboard.public_origin's hostname, or "" when
// it is unset or invalid (NewOriginPolicy reports an invalid one).
func publicOriginHostname(origin string) string {
	if origin == "" {
		return ""
	}
	canon, err := netmatch.CanonicalOrigin(origin)
	if err != nil {
		return ""
	}
	u, err := url.Parse(canon)
	if err != nil {
		return ""
	}
	return normaliseHostName(u.Hostname())
}

// misdirectedHost is the body of a refused open-mode request.
const misdirectedHost = "unrecognised Host for a dashboard without a token: reach it by its listen address, " +
	"localhost, its Tailscale name or dashboard.public_origin (or set SHARDLURE_DASH_TOKEN)"

// requireKnownHost wraps the live handler (RunContext). The token is read per
// request, so setting one in the Settings panel lifts the check at once.
func (s *Server) requireKnownHost(p hostPolicy, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.dashboardToken() == "" && !p.allows(r.Host) {
			http.Error(w, misdirectedHost, http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// newServerHostPolicy builds the policy for s from its listen address, the
// configured public origin and the machine's hostname.
func (s *Server) newServerHostPolicy() hostPolicy {
	name, err := machineHostname()
	if err != nil {
		name = ""
	}
	return newHostPolicy(s.addr, s.publicOriginHost, name)
}
