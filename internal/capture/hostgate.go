package capture

import (
	"net/url"
	"strings"
	"sync"
)

// HostGate allows at most one in-flight fetch per payload host, so the
// re-fetch worker and the capture worker never hammer one attacker server
// in parallel (and never look like a scanner to it). The key is the
// lowercase hostname: scheme and port are ignored, an IPv6 literal is kept
// without brackets.
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
	host := strings.ToLower(u.Hostname())
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
