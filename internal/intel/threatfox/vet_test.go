package threatfox

import (
	"testing"
	"time"
)

// vetNow is the fixed clock for vet tests: fixtures set FetchedAt relative to
// it, so the active-days window never ages out as wall-clock time passes (the
// time-bomb the urlhaus tests hit).
var vetNow = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

// goodCandidate is a candidate that clears every gate: a mirai ELF fetched
// first-hand an hour ago from a PUBLIC IP host. Public IP on purpose —
// netmatch rejects private AND the RFC5737 documentation ranges, so an
// "example" IP would be wrongly rejected and mask what a test measures.
func goodCandidate() Candidate {
	return Candidate{
		URL:       "http://45.155.205.230/bins/mirai.x86",
		SHA256:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		SizeBytes: 52000,
		Origin:    "quarantine_fetch",
		Status:    "fetched",
		FetchedAt: vetNow.Add(-1 * time.Hour),
		FileKind:  "ELF",
		Family:    "mirai",
	}
}

func TestVetAcceptsConfirmedFetchWithFamily(t *testing.T) {
	ok, malware, iocs, reason := Vet(goodCandidate(), vetNow)
	if !ok {
		t.Fatalf("good candidate rejected: %s", reason)
	}
	if malware != "elf.mirai" {
		t.Errorf("malware label = %q, want elf.mirai", malware)
	}
	// Expect three IOCs: the URL (payload_delivery), the ip:port
	// (payload_delivery), and the sha256 (payload).
	byType := map[string]IOC{}
	for _, i := range iocs {
		byType[i.Type] = i
	}
	if u, ok := byType[IOCTypeURL]; !ok || u.ThreatType != ThreatPayloadDelivery {
		t.Errorf("missing/wrong URL IOC: %+v", byType[IOCTypeURL])
	}
	if p, ok := byType[IOCTypeIPPort]; !ok || p.Value != "45.155.205.230:80" || p.ThreatType != ThreatPayloadDelivery {
		t.Errorf("missing/wrong ip:port IOC: %+v (want 45.155.205.230:80)", byType[IOCTypeIPPort])
	}
	if h, ok := byType[IOCTypeSHA256]; !ok || h.ThreatType != ThreatPayload {
		t.Errorf("missing/wrong sha256 IOC: %+v", byType[IOCTypeSHA256])
	}
}

func TestVetDomainHostYieldsDomainIOC(t *testing.T) {
	c := goodCandidate()
	c.URL = "https://malware.example-evil.tld/x/redtail.arm"
	c.Family = "redtail"
	ok, malware, iocs, reason := Vet(c, vetNow)
	if !ok {
		t.Fatalf("rejected: %s", reason)
	}
	if malware != "elf.redtail" {
		t.Errorf("malware = %q, want elf.redtail", malware)
	}
	found := false
	for _, i := range iocs {
		if i.Type == IOCTypeDomain {
			found = true
			if i.Value != "malware.example-evil.tld" {
				t.Errorf("domain IOC = %q", i.Value)
			}
		}
		if i.Type == IOCTypeIPPort {
			t.Errorf("domain host must not yield an ip:port IOC: %+v", i)
		}
	}
	if !found {
		t.Error("domain host produced no domain IOC")
	}
}

// TestVetHardRejects walks every reject path. Each case mutates goodCandidate so
// exactly one gate fails; the reject reason must be non-empty and no IOCs
// returned. The family/host/freshness rejects are the ones that protect the
// shared abuse.ch account, so each is pinned explicitly.
func TestVetHardRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Candidate)
	}{
		{"unparseable pseudo-key", func(c *Candidate) { c.URL = "cowrie-event:12345" }},
		{"not http", func(c *Candidate) { c.URL = "ftp://45.155.205.230/x" }},
		{"credentials in url", func(c *Candidate) { c.URL = "http://user:pw@45.155.205.230/x" }},
		{"invalid port", func(c *Candidate) { c.URL = "http://45.155.205.230:99999/x" }},
		{"wrong origin", func(c *Candidate) { c.Origin = "cowrie_download" }},
		{"not fetched", func(c *Candidate) { c.Status = "failed" }},
		{"no hash", func(c *Candidate) { c.SHA256 = "" }},
		{"malformed hash (short)", func(c *Candidate) { c.SHA256 = "deadbeef" }},
		{"malformed hash (non-hex)", func(c *Candidate) { c.SHA256 = "z3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }},
		{"too small", func(c *Candidate) { c.SizeBytes = 32 }},
		{"benign ssh key", func(c *Candidate) { c.FileKind = "SSH key" }},
		{"unknown kind", func(c *Candidate) { c.FileKind = "unknown" }},
		// The ThreatFox-specific reject: a confirmed malware file whose family
		// has no Malpedia label. Komari is confirmed malware but unmappable.
		{"unmappable family", func(c *Candidate) { c.Family = "komari" }},
		{"empty family", func(c *Candidate) { c.Family = "" }},
		{"private ip host", func(c *Candidate) { c.URL = "http://192.168.1.10/x" }},
		{"loopback host", func(c *Candidate) { c.URL = "http://127.0.0.1/x" }},
		{"numeric shorthand host", func(c *Candidate) { c.URL = "http://127.1/x" }},
		{"non-public hostname", func(c *Candidate) { c.URL = "http://server.local/x" }},
		{"shortener host", func(c *Candidate) { c.URL = "http://bit.ly/x" }},
		{"stale fetch", func(c *Candidate) { c.FetchedAt = vetNow.Add(-30 * 24 * time.Hour) }},
		{"zero fetch time", func(c *Candidate) { c.FetchedAt = time.Time{} }},
		{"future fetch (skew)", func(c *Candidate) { c.FetchedAt = vetNow.Add(48 * time.Hour) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := goodCandidate()
			tc.mutate(&c)
			ok, malware, iocs, reason := Vet(c, vetNow)
			if ok {
				t.Fatalf("expected reject, but accepted (malware=%q iocs=%d)", malware, len(iocs))
			}
			if reason == "" {
				t.Error("reject must carry a human-readable reason")
			}
			if len(iocs) != 0 || malware != "" {
				t.Errorf("reject must return no IOCs and no label; got %d iocs, malware=%q", len(iocs), malware)
			}
		})
	}
}

// TestVetIPv6 pins the two IPv6 dangers found in adversarial review: (1) every
// private/reserved IPv6 form is rejected (netmatch.IsPublicIP handles v6), and
// (2) a PUBLIC IPv6 host yields a correctly BRACKETED ip:port IOC — the naive
// host+":"+port renders the malformed "2606::1111:80" that ThreatFox would
// reject as junk (an account-risk).
func TestVetIPv6(t *testing.T) {
	// Private / reserved v6 must all reject.
	for _, u := range []string{
		"http://[::1]/x",              // loopback
		"http://[fe80::1]/x",          // link-local
		"http://[2001:db8::1]/x",      // documentation (reserved)
		"http://[64:ff9b::808:808]/x", // NAT64
		"http://[fc00::1]/x",          // unique-local
	} {
		c := goodCandidate()
		c.URL = u
		if ok, _, _, _ := Vet(c, vetNow); ok {
			t.Errorf("private/reserved IPv6 %q was ACCEPTED — must reject", u)
		}
	}
	// Public v6 accepts, with a bracketed ip:port.
	c := goodCandidate()
	c.URL = "http://[2606:4700:4700::1111]/bins/mirai.x86"
	ok, _, iocs, reason := Vet(c, vetNow)
	if !ok {
		t.Fatalf("public IPv6 rejected: %s", reason)
	}
	var ipPortIOC string
	for _, i := range iocs {
		if i.Type == IOCTypeIPPort {
			ipPortIOC = i.Value
		}
	}
	if ipPortIOC != "[2606:4700:4700::1111]:80" {
		t.Errorf("IPv6 ip:port IOC = %q, want [2606:4700:4700::1111]:80 (bracketed) — an "+
			"unbracketed value is malformed junk", ipPortIOC)
	}
}

// TestVetActiveDaysOnlyTightens pins that VetOptions.ActiveDays can shrink the
// window but never widen it past the 3-day default.
func TestVetActiveDaysOnlyTightens(t *testing.T) {
	c := goodCandidate()
	c.FetchedAt = vetNow.Add(-2 * 24 * time.Hour) // 2 days old

	// Default (3d): accepted.
	if ok, _, _, reason := Vet(c, vetNow); !ok {
		t.Fatalf("2-day-old fetch rejected under default 3d window: %s", reason)
	}
	// Tighten to 1 day: now rejected.
	if ok, _, _, _ := Vet(c, vetNow, VetOptions{ActiveDays: 1}); ok {
		t.Error("ActiveDays=1 should reject a 2-day-old fetch")
	}
	// Attempt to LOOSEN to 30 days: ignored, still uses the 3-day default, so a
	// 2-day fetch stays accepted but a 10-day one would not.
	c.FetchedAt = vetNow.Add(-10 * 24 * time.Hour)
	if ok, _, _, _ := Vet(c, vetNow, VetOptions{ActiveDays: 30}); ok {
		t.Error("ActiveDays=30 must be ignored (may only tighten); 10-day fetch should reject")
	}
}
