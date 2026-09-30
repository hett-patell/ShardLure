package web

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/networkshard/shardlure/internal/netmatch"
)

// machineHostname is os.Hostname; tests substitute it.
var machineHostname = os.Hostname

// tailscaleSelfDNSName is this node's MagicDNS name as the local tailscale
// CLI reports it (`tailscale status --json`, Self.DNSName), or "" when the
// CLI is absent, the daemon is down or the call exceeds its budget. It runs
// once per process (the host policy is built at startup); tests substitute
// it.
var tailscaleSelfDNSName = sync.OnceValue(readTailscaleSelfDNSName)

// tailscaleStatusTimeout bounds the startup call: the dashboard must never
// wait on a wedged tailscaled. On timeout the hostname rules still apply.
const tailscaleStatusTimeout = 2 * time.Second

func readTailscaleSelfDNSName() string {
	path, err := exec.LookPath("tailscale")
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), tailscaleStatusTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "status", "--json").Output()
	if err != nil {
		return ""
	}
	return parseTailscaleSelfDNSName(out)
}

func parseTailscaleSelfDNSName(out []byte) string {
	var st struct {
		Self *struct {
			DNSName string `json:"DNSName"`
		} `json:"Self"`
	}
	if json.Unmarshal(out, &st) != nil || st.Self == nil {
		return ""
	}
	return strings.TrimSpace(st.Self.DNSName)
}

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
//   - Tailscale MagicDNS names for this machine:
//   - the exact name the local tailscale CLI reports (Self.DNSName, read
//     once at startup), and its first label. This covers a node renamed
//     in the admin console, whenever the CLI is installed and answering;
//   - as a fallback, from the OS hostname: a short name, and
//     "<label>.<tailnet>.ts.net" with exactly one tailnet label. Tailscale
//     derives the label from the hostname but sanitises it (characters
//     outside [a-z0-9-] become '-', so my_box is my-box) and de-duplicates
//     a clash with a numeric suffix (a second "arm" is arm-1), so the label
//     is the sanitised first label or the sanitised whole name, optionally
//     followed by -<1..4 digits> (final audit M4). Production's hostname
//     is arm and its name arm.kingfisher-typhon.ts.net, which both rules
//     accept.
//     ts.net is Tailscale's domain and its machine names resolve only
//     through a tailnet's own MagicDNS (or, for Funnel, to Tailscale's
//     relays), so an attacker's public DNS cannot answer for them. This is
//     a pattern rather than an exact name because the tailnet label is not
//     knowable offline without the CLI. A node renamed with no CLI
//     available still needs dashboard.public_origin (or a token).
//
// The port is ignored: a rebinding page must already use the dashboard's port
// to reach it, and the hostname is what it cannot fake. A request with no
// Host (HTTP/1.0) is not a browser and passes. Token mode is not checked: a
// bearer header cannot be forged by a rebinding page, and a proxy in front of
// a tokened dashboard may present any name.
type hostPolicy struct {
	listen   netip.Addr // invalid when the listen address is not an IP
	public   string     // lowercase hostname or ""
	machines []string   // MagicDNS labels this node may carry (see labelMatches)
	magic    string     // lowercase MagicDNS FQDN from the tailscale CLI, or ""
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
	first := machine
	if i := strings.IndexByte(machine, '.'); i >= 0 {
		first = machine[:i]
	}
	for _, l := range []string{first, sanitiseTailscaleLabel(first), sanitiseTailscaleLabel(machine)} {
		p.addMachine(l)
	}
	return p
}

// withMagicDNS adds the node's MagicDNS FQDN as the tailscale CLI reported
// it. Anything that is not a dotted name of valid labels is ignored.
func (p hostPolicy) withMagicDNS(name string) hostPolicy {
	name = normaliseHostName(name)
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return p
	}
	for _, l := range labels {
		if !validDNSLabel(l) {
			return p
		}
	}
	p.magic = name
	p.machines = append([]string(nil), p.machines...)
	p.addMachine(labels[0])
	return p
}

func (p *hostPolicy) addMachine(l string) {
	if !validDNSLabel(l) {
		return
	}
	for _, m := range p.machines {
		if m == l {
			return
		}
	}
	p.machines = append(p.machines, l)
}

// sanitiseTailscaleLabel approximates how Tailscale turns a hostname into a
// MagicDNS label: lowercase, every character outside [a-z0-9-] becomes '-',
// leading and trailing '-' are trimmed, and the result is cut to 63 bytes.
func sanitiseTailscaleLabel(h string) string {
	b := []byte(strings.ToLower(h))
	for i, c := range b {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			b[i] = '-'
		}
	}
	l := strings.Trim(string(b), "-")
	if len(l) > 63 {
		l = strings.TrimRight(l[:63], "-")
	}
	return l
}

// labelMatches reports whether l is one of this node's labels, optionally
// with Tailscale's de-duplication suffix -<1..4 digits>.
func (p hostPolicy) labelMatches(l string) bool {
	for _, m := range p.machines {
		if l == m {
			return true
		}
		if n, ok := strings.CutPrefix(l, m+"-"); ok && len(n) >= 1 && len(n) <= 4 && strings.Trim(n, "0123456789") == "" {
			return true
		}
	}
	return false
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
	case p.magic != "" && host == p.magic:
		return true
	}
	// A short name, or <label>.<tailnet>.ts.net with one tailnet label.
	label, rest, dotted := strings.Cut(host, ".")
	if !p.labelMatches(label) {
		return false
	}
	if !dotted {
		return true
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
	return newHostPolicy(s.addr, s.publicOriginHost, name).withMagicDNS(tailscaleSelfDNSName())
}
