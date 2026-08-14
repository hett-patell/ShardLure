package intelutil

import (
	"net"
	"strings"

	"github.com/networkshard/shardlure/internal/netmatch"
)

// Host classification shared by every outbound-intel gate (urlhaus, threatfox).
//
// These predicates decide whether a host recovered from attacker input is safe
// to publish to a public abuse.ch dataset. They live here, in one place,
// because a divergent second copy of an SSRF/pollution gate is exactly how a
// private address slips into a public feed: the urlhaus gate and the threatfox
// gate MUST answer "is this a public payload host" identically. Do not inline a
// variant in a caller.

// ShortenerHosts are pure redirection services that host no payload themselves.
// A public dataset must not carry them (the redirect target, not the shortener,
// is the real IOC). Not exhaustive by design — it catches the common ones an
// attacker one-liner actually uses.
var ShortenerHosts = map[string]bool{
	"bit.ly": true, "tinyurl.com": true, "goo.gl": true, "t.co": true,
	"ow.ly": true, "is.gd": true, "buff.ly": true, "cutt.ly": true,
	"rb.gy": true, "shorturl.at": true, "rebrand.ly": true, "t.ly": true,
	"tiny.cc": true, "s.id": true, "shorte.st": true, "adf.ly": true,
}

// IsShortener reports whether host (with an optional leading "www.") is a known
// URL shortener/redirector.
func IsShortener(host string) bool {
	return ShortenerHosts[strings.ToLower(strings.TrimPrefix(host, "www."))]
}

// IsNumericHost reports whether every dot-separated label is numeric (decimal
// or 0x-hex). Such a host is always an IP literal in some encoding — no real
// DNS name looks like this — and resolvers accept forms Go's net.ParseIP does
// not ("127.1" -> 127.0.0.1, "2130706433" -> 127.0.0.1). Treating them as
// unclassifiable is what stops a loopback/RFC1918 address reaching a public
// blocklist through an alternate spelling.
func IsNumericHost(host string) bool {
	if host == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return false
		}
		s := label
		if strings.HasPrefix(s, "0x") {
			s = s[2:]
			if s == "" {
				return false
			}
		}
		for _, r := range s {
			isDec := r >= '0' && r <= '9'
			isHex := strings.HasPrefix(label, "0x") && ((r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F'))
			if !isDec && !isHex {
				return false
			}
		}
	}
	return true
}

// IsSubmittableHostname rejects names that can't be a public payload host:
// bare hostnames with no dot (intranet names), localhost, and .local/.internal
// style private suffixes.
func IsSubmittableHostname(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "" || h == "localhost" {
		return false
	}
	if !strings.Contains(h, ".") {
		return false
	}
	for _, suffix := range []string{".local", ".internal", ".localdomain", ".lan", ".home", ".corp", ".test", ".invalid", ".example", ".onion"} {
		if strings.HasSuffix(h, suffix) {
			return false
		}
	}
	return true
}

// PublicHostKind classifies a normalised host (lowercased, trailing dot
// stripped) for submission to a public dataset. It returns one of:
//
//	"ip"       - a public IP literal (net.ParseIP ok AND netmatch.IsPublicIP)
//	"domain"   - a submittable public hostname
//	""         - NOT submittable, with a human-readable reason
//
// The reason is only meaningful when kind == "". This is the single decision
// both urlhaus and threatfox use so the two can never disagree about whether a
// host is public. Callers must normalise the host first (TrimSuffix ".",
// ToLower) — HostNormalise does exactly that.
func PublicHostKind(host string) (kind, reason string) {
	switch {
	case net.ParseIP(host) != nil:
		// netmatch.IsPublicIP is the ONE conservative definition of "public"
		// shared with the capture fetcher and the AbuseIPDB gate. It covers
		// RFC6890 special-use blocks a naive check misses (AS112, NAT64, 6to4,
		// IETF protocol assignments, benchmarking, documentation).
		if !netmatch.IsPublicIP(net.ParseIP(host)) {
			return "", "private or special-purpose IP address"
		}
		return "ip", ""
	case IsNumericHost(host):
		// An all-numeric host is an IP in some alternate encoding that Go's
		// strict parser rejects but libc/browsers happily resolve. We do NOT
		// resolve attacker input (DNS side channel + TOCTOU), so an address we
		// cannot classify is a no.
		return "", "ambiguous numeric host (possible IP shorthand)"
	case !IsSubmittableHostname(host):
		return "", "non-public hostname"
	}
	if len(host) > 253 {
		return "", "hostname exceeds the 253-byte DNS limit"
	}
	if IsShortener(host) {
		return "", "URL shortener / redirector, not a payload host"
	}
	return "domain", ""
}

// HostNormalise lowercases a host and strips the FQDN root dot ("127.0.0.1."
// -> "127.0.0.1"), the form that otherwise slips a loopback address past a
// net.ParseIP check into the hostname rule.
func HostNormalise(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}
