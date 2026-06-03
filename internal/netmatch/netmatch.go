// Package netmatch provides a small IP/CIDR membership matcher shared by the
// actor clustering and capture (SSRF guard) subsystems. It exists as a leaf
// package so both can depend on it without an import cycle.
package netmatch

import (
	"net"
	"sort"
	"strings"
)

// Set matches an IP against a list of admin/trusted entries. Each entry may be
// a bare IP ("100.64.0.1") or a CIDR range ("192.168.1.0/24", "fd00::/8").
// Bare IPs match exactly; CIDR entries match any address inside the range.
//
// The previous implementation compared only with net.ParseIP(entry), so a
// CIDR entry parsed to nil and silently matched nothing — an admin range in
// the config would be treated as attacker traffic and would not be exempt
// from the SSRF guard. Set closes that gap.
type Set struct {
	exact map[string]struct{}
	cidrs []*net.IPNet
	empty bool
}

// New parses entries into a Set. Unparseable entries are skipped (callers that
// want to warn can use Invalid to find them first).
func New(entries []string) *Set {
	s := &Set{exact: map[string]struct{}{}}
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			if _, ipnet, err := net.ParseCIDR(e); err == nil {
				s.cidrs = append(s.cidrs, ipnet)
				continue
			}
			// Fall through: not a valid CIDR, try as a bare IP below.
		}
		if ip := net.ParseIP(e); ip != nil {
			// Normalize to the canonical string so textual lookups match
			// regardless of input form (e.g. IPv6 shorthand).
			s.exact[ip.String()] = struct{}{}
			// Also key the raw form so callers doing string lookups with
			// the unparsed source IP still hit on exact matches.
			s.exact[e] = struct{}{}
		}
	}
	s.empty = len(s.exact) == 0 && len(s.cidrs) == 0
	return s
}

// Invalid returns the entries that could not be parsed as either an IP or a
// CIDR range, so the caller can surface a startup warning.
func Invalid(entries []string) []string {
	var bad []string
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			if _, _, err := net.ParseCIDR(e); err == nil {
				continue
			}
		}
		if net.ParseIP(e) == nil {
			bad = append(bad, e)
		}
	}
	return bad
}

// Key returns a stable canonical fingerprint of the set's contents,
// independent of construction order or pointer identity. Two Sets built from
// the same entries compare equal by Key. Used to detect the "different admin
// set passed across goroutines" misuse in the live collector.
func (s *Set) Key() string {
	if s == nil {
		return ""
	}
	parts := make([]string, 0, len(s.exact)+len(s.cidrs))
	for k := range s.exact {
		parts = append(parts, k)
	}
	for _, n := range s.cidrs {
		parts = append(parts, n.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x00")
}

// Has reports whether ip (a string source address) is in the set.
func (s *Set) Has(ip string) bool {
	if s == nil || s.empty {
		return false
	}
	if _, ok := s.exact[ip]; ok {
		return true
	}
	if len(s.cidrs) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return s.HasIP(parsed)
}

// HasIP reports whether a parsed net.IP is in the set. Useful for callers that
// already hold a net.IP (e.g. the SSRF guard inspecting resolved addresses).
func (s *Set) HasIP(ip net.IP) bool {
	if s == nil || s.empty || ip == nil {
		return false
	}
	if _, ok := s.exact[ip.String()]; ok {
		return true
	}
	for _, n := range s.cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
