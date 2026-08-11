package urlhaus

import (
	"strings"
	"testing"
	"time"
)

// Adversarial / malformed inputs must be rejected cleanly, never panic, and
// never be accepted. Attacker-controlled URLs reach this gate directly.
func TestVetHostileInputsNeverPanicOrPass(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	hostile := []string{
		"", " ", "\x00", "http://", "https://", "http:///path",
		"http://[", "http://]", "://evil.tld/x", "http://evil.tld:99999/x",
		"http://user:pass@evil.tld/x", "http://evil.tld\n/x", "http://evil.tld\t/x",
		"http://127.0.0.1./x", "http://LOCALHOST/x", "http://0x7f000001/x",
		"http://2130706433/x", "http://[::ffff:127.0.0.1]/x",
		"javascript:alert(1)", "data:text/html,x", "file:///etc/passwd",
	}
	for _, u := range hostile {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic on %q: %v", u, r)
				}
			}()
			c := goodCandidate()
			c.URL = u
			ok, reason := Vet(c, now)
			if ok {
				t.Errorf("hostile URL accepted: %q", u)
			}
			if reason == "" {
				t.Errorf("no rejection reason for %q", u)
			}
		}()
	}
}

// IPv4-mapped IPv6 and decimal/hex encodings of loopback are classic filter
// bypasses. netmatch must catch the parseable ones; unparseable ones fall to
// the hostname rule.
func TestVetRejectsLoopbackEncodings(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	for _, u := range []string{
		"http://[::ffff:127.0.0.1]/x", // IPv4-mapped loopback
		"http://[::ffff:10.0.0.1]/x",  // IPv4-mapped RFC1918
		"http://127.1/x",              // short-form loopback (unparseable as IP -> hostname rule)
	} {
		c := goodCandidate()
		c.URL = u
		if ok, _ := Vet(c, now); ok {
			t.Errorf("loopback encoding accepted: %q", u)
		}
	}
}

// Uppercase schemes and long paths are LEGITIMATE: url.Parse lowercases the
// scheme, and a long path is just a path. Pinned so a future "harden the
// parser" change doesn't start silently dropping real malware URLs.
func TestVetAcceptsLegitimateOddButValidURLs(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	for _, u := range []string{
		"HTTP://EVIL.TLD/X",
		"hTtP://evil.tld/x",
		"http://evil.tld/" + strings.Repeat("a", 2000),
		"http://evil.tld:8080/bins/x86",
		"http://evil.tld/x?id=123&v=2",
	} {
		c := goodCandidate()
		c.URL = u
		if ok, reason := Vet(c, now); !ok {
			t.Errorf("legitimate URL rejected: %q (%s)", u, reason)
		}
	}
}

// Credentials in a submitted URL would be published to a public blocklist.
func TestVetRejectsCredentialsAndBadPorts(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	cases := map[string]string{
		"http://user:pass@evil.tld/x": "credentials",
		"http://user@evil.tld/x":      "credentials",
		// Classic host-obscuring trick: the real host is evil.tld.
		"http://www.google.com@evil.tld/x": "credentials",
		"http://evil.tld:99999/x":          "invalid port",
		"http://evil.tld:0/x":              "invalid port",
	}
	for u, want := range cases {
		c := goodCandidate()
		c.URL = u
		ok, reason := Vet(c, now)
		if ok {
			t.Errorf("accepted %q", u)
			continue
		}
		if !strings.Contains(reason, want) {
			t.Errorf("%q rejected for %q, want %q", u, reason, want)
		}
	}
}
