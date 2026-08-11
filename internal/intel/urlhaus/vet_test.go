package urlhaus

import (
	"strings"
	"testing"
	"time"
)

var vetNow = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

// goodCandidate is a URL we fetched a real ELF from an hour ago — the
// canonical accept case. Tests mutate one field at a time from here.
func goodCandidate() Candidate {
	return Candidate{
		URL:       "http://185.7.214.3/bins/x86",
		SHA256:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		SizeBytes: 45000,
		Origin:    "quarantine_fetch",
		Status:    "fetched",
		FetchedAt: vetNow.Add(-1 * time.Hour),
		FileKind:  "ELF",
	}
}

func TestVetAcceptsVerifiedActiveMalwareURL(t *testing.T) {
	ok, reason := Vet(goodCandidate(), vetNow)
	if !ok {
		t.Fatalf("expected accept, got reject: %s", reason)
	}
	if reason != "" {
		t.Errorf("accept should carry no reason, got %q", reason)
	}
}

func TestVetHardRejects(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Candidate)
		wantSub string
	}{
		// The internal dedup pseudo-keys must never reach a public dataset.
		{"cowrie download pseudo-key", func(c *Candidate) {
			c.URL = "cowrie-download:2146a9c89601763189a3369e23ed9df9"
		}, "not an http(s) URL"},
		{"cowrie event pseudo-key", func(c *Candidate) {
			c.URL = "cowrie-event:666366"
		}, "not an http(s) URL"},
		{"tty pseudo-key", func(c *Candidate) {
			c.URL = "cowrie-tty:20260810-abc.log"
		}, "not an http(s) URL"},
		{"ftp scheme", func(c *Candidate) { c.URL = "ftp://x.tld/a" }, "not an http(s) URL"},
		{"empty url", func(c *Candidate) { c.URL = "" }, "not an http(s) URL"},

		// Provenance / proof-of-serving.
		{"wrong origin", func(c *Candidate) { c.Origin = "cowrie_download" }, "not a URL we fetched"},
		{"failed fetch", func(c *Candidate) { c.Status = "failed" }, "fetch did not succeed"},
		{"pending fetch", func(c *Candidate) { c.Status = "pending" }, "fetch did not succeed"},
		{"no payload hash", func(c *Candidate) { c.SHA256 = "" }, "no payload hash"},
		{"tiny payload", func(c *Candidate) { c.SizeBytes = 12 }, "too small"},

		// Benign / unclassifiable.
		{"ssh key", func(c *Candidate) { c.FileKind = "SSH key" }, "benign content"},
		{"unknown kind", func(c *Candidate) { c.FileKind = "unknown" }, "payload shape unrecognised"},
		{"blank kind", func(c *Candidate) { c.FileKind = "" }, "payload shape unrecognised"},

		// RFC1597 / RFC6890 — explicitly required by the submission policy.
		{"rfc1918 10/8", func(c *Candidate) { c.URL = "http://10.0.0.5/x" }, "private or special-purpose"},
		{"rfc1918 192.168", func(c *Candidate) { c.URL = "http://192.168.1.10/x" }, "private or special-purpose"},
		{"rfc1918 172.16", func(c *Candidate) { c.URL = "http://172.16.4.4/x" }, "private or special-purpose"},
		{"loopback", func(c *Candidate) { c.URL = "http://127.0.0.1/x" }, "private or special-purpose"},
		{"cgnat/tailscale", func(c *Candidate) { c.URL = "http://100.124.3.67/x" }, "private or special-purpose"},
		{"link-local", func(c *Candidate) { c.URL = "http://169.254.169.254/latest" }, "private or special-purpose"},
		{"test-net-1", func(c *Candidate) { c.URL = "http://192.0.2.8/x" }, "private or special-purpose"},
		{"test-net-3", func(c *Candidate) { c.URL = "http://203.0.113.9/x" }, "private or special-purpose"},
		{"ipv6 loopback", func(c *Candidate) { c.URL = "http://[::1]/x" }, "private or special-purpose"},
		// RFC6890 special-use blocks a naive private-IP check misses. These are
		// the ranges the previous hand-rolled isPublicIP would have leaked to a
		// public dataset; netmatch.IsPublicIP is the shared, complete definition.
		{"unspecified 0.0.0.0/8", func(c *Candidate) { c.URL = "http://0.1.2.3/x" }, "private or special-purpose"},
		{"ietf protocol assignments", func(c *Candidate) { c.URL = "http://192.0.0.8/x" }, "private or special-purpose"},
		{"as112-v4", func(c *Candidate) { c.URL = "http://192.31.196.1/x" }, "private or special-purpose"},
		{"deprecated 6to4 relay anycast", func(c *Candidate) { c.URL = "http://192.88.99.1/x" }, "private or special-purpose"},
		{"as112 direct delegation", func(c *Candidate) { c.URL = "http://192.175.48.1/x" }, "private or special-purpose"},
		{"benchmarking 198.18/15", func(c *Candidate) { c.URL = "http://198.19.0.1/x" }, "private or special-purpose"},
		{"ipv6 nat64 well-known", func(c *Candidate) { c.URL = "http://[64:ff9b::1]/x" }, "private or special-purpose"},
		{"ipv6 6to4", func(c *Candidate) { c.URL = "http://[2002::1]/x" }, "private or special-purpose"},
		{"ipv6 link-local", func(c *Candidate) { c.URL = "http://[fe80::1]/x" }, "private or special-purpose"},
		{"ipv6 discard-only", func(c *Candidate) { c.URL = "http://[100::1]/x" }, "private or special-purpose"},
		{"ipv6 unique local", func(c *Candidate) { c.URL = "http://[fd00::1]/x" }, "private or special-purpose"},
		{"ipv6 doc range", func(c *Candidate) { c.URL = "http://[2001:db8::1]/x" }, "private or special-purpose"},

		// Non-public names.
		{"localhost", func(c *Candidate) { c.URL = "http://localhost/x" }, "non-public hostname"},
		{"dotless host", func(c *Candidate) { c.URL = "http://intranet/x" }, "non-public hostname"},
		{"mdns .local", func(c *Candidate) { c.URL = "http://box.local/x" }, "non-public hostname"},
		{"onion", func(c *Candidate) { c.URL = "http://abc.onion/x" }, "non-public hostname"},

		// Redirectors host no payload.
		{"bit.ly", func(c *Candidate) { c.URL = "http://bit.ly/abc" }, "shortener"},
		{"www.tinyurl", func(c *Candidate) { c.URL = "http://www.tinyurl.com/abc" }, "shortener"},

		// Liveness.
		{"stale", func(c *Candidate) { c.FetchedAt = vetNow.Add(-10 * 24 * time.Hour) }, "may be offline"},
		{"unknown fetch time", func(c *Candidate) { c.FetchedAt = time.Time{} }, "unknown fetch time"},
		{"future fetch time", func(c *Candidate) { c.FetchedAt = vetNow.Add(48 * time.Hour) }, "future"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := goodCandidate()
			tc.mutate(&c)
			ok, reason := Vet(c, vetNow)
			if ok {
				t.Fatalf("expected reject, got accept")
			}
			if !strings.Contains(reason, tc.wantSub) {
				t.Errorf("reason = %q, want substring %q", reason, tc.wantSub)
			}
		})
	}
}

// A hard reject must win even when every other signal looks good — the same
// ordering guarantee the bazaar gate makes.
func TestVetHardRejectBeatsGoodSignals(t *testing.T) {
	c := goodCandidate()
	c.FileKind = "ELF" // strong malware signal
	c.SizeBytes = 500000
	c.URL = "http://127.0.0.1/bins/x86" // but private
	if ok, _ := Vet(c, vetNow); ok {
		t.Error("private IP must reject regardless of payload strength")
	}
}

func TestVetActiveDaysOnlyTightens(t *testing.T) {
	c := goodCandidate()
	c.FetchedAt = vetNow.Add(-2 * 24 * time.Hour) // 2 days old

	// Default window (3d) accepts it.
	if ok, reason := Vet(c, vetNow); !ok {
		t.Fatalf("2-day-old URL should pass the default window: %s", reason)
	}
	// Tightening to 1 day rejects it.
	if ok, _ := Vet(c, vetNow, VetOptions{ActiveDays: 1}); ok {
		t.Error("ActiveDays=1 should reject a 2-day-old URL")
	}
	// A caller may not LOOSEN past the default.
	if ok, _ := Vet(c, vetNow, VetOptions{ActiveDays: 90}); !ok {
		t.Error("oversized ActiveDays should fall back to the default, not reject")
	}
	c.FetchedAt = vetNow.Add(-30 * 24 * time.Hour)
	if ok, _ := Vet(c, vetNow, VetOptions{ActiveDays: 90}); ok {
		t.Error("ActiveDays=90 must not loosen the 3-day default")
	}
}

func TestVetAcceptsHTTPSAndScriptPayloads(t *testing.T) {
	c := goodCandidate()
	c.URL = "https://del.sou.pp.ua/install.sh"
	c.FileKind = "shell script"
	if ok, reason := Vet(c, vetNow); !ok {
		t.Errorf("https shell-script dropper should be accepted: %s", reason)
	}
}

func TestSanitiseTags(t *testing.T) {
	got := sanitiseTags([]string{"shardlure", "honey pot", "bad;tag", "sha-1.2", "", "shardlure"})
	want := []string{"badtag", "honey pot", "sha-1.2", "shardlure"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tag[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
