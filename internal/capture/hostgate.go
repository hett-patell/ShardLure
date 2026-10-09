package capture

import (
	"net/netip"
	"net/url"
	"strings"
	"sync"
)

// HostGate allows at most one in-flight fetch per payload host, so the
// re-fetch worker and the capture worker never hammer one attacker server
// in parallel (and never look like a scanner to it). The key is
// hostGateKey's canonical host: scheme, port and userinfo are ignored.
type HostGate struct {
	mu   sync.Mutex
	held map[string]struct{}
}

// NewHostGate returns an empty gate.
func NewHostGate() *HostGate {
	return &HostGate{held: make(map[string]struct{})}
}

// TryAcquire claims rawURL's host without blocking. On success the returned
// release frees it; release is idempotent, so a stale second call can never
// free a later holder. An unparsable URL, or one with no host, is refused.
func (g *HostGate) TryAcquire(rawURL string) (release func(), ok bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, false
	}
	host := hostGateKey(u.Hostname())
	if host == "" {
		return nil, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, busy := g.held[host]; busy {
		return nil, false
	}
	g.held[host] = struct{}{}
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			delete(g.held, host)
			g.mu.Unlock()
		})
	}, true
}

// hostGateKey canonicalises a URL hostname so every spelling of one server
// shares a key: lowercase (Unicode-aware), one trailing root dot removed,
// and IP literals in netip's canonical form with IPv4-mapped IPv6 unmapped
// (so [::ffff:1.2.3.4] and 1.2.3.4, or [2001:db8:0:0::1] and
// [2001:db8::1], collide). IPv6 is kept without brackets.
//
// Unicode names are NOT converted to punycode: golang.org/x/net/idna is not
// a module dependency and is not added for this, so bücher.de and
// xn--bcher-kva.de remain distinct keys. The cost is politeness only.
func hostGateKey(h string) string {
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if h == "" {
		return ""
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().String()
	}
	return h
}
