package abuseipdb

import (
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/netmatch"
)

// vetNow is a fixed clock. Vet's staleness gate is time-dependent, so the tests
// pin "now" rather than calling time.Now(): otherwise a case sitting exactly on
// the boundary would pass or fail depending on when the suite ran.
var vetNow = time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)

func TestVet(t *testing.T) {
	admin := netmatch.New([]string{"8.8.4.4", "10.0.0.0/8"})

	// A textbook confirmed brute-forcer: public IP, brute playbook, high probe,
	// well above the event/user floor, and still attacking an hour ago.
	good := ReportCandidate{
		SrcIP: "8.8.8.8", Playbook: "fast_dictionary_spray",
		ProbeScore: 80, EventCount: 500, UniqueUsers: 40,
		LastSeen: vetNow.Add(-time.Hour),
	}

	cases := []struct {
		name   string
		cand   ReportCandidate
		want   bool
		reason string // substring expected in the reject reason (when want=false)
	}{
		{"confirmed brute-forcer accepted", good, true, ""},
		{"admin IP rejected", func() ReportCandidate { c := good; c.SrcIP = "8.8.4.4"; return c }(), false, "admin"},
		{"private IP rejected", func() ReportCandidate { c := good; c.SrcIP = "10.1.2.3"; return c }(), false, "private/reserved"},
		{"loopback rejected", func() ReportCandidate { c := good; c.SrcIP = "127.0.0.1"; return c }(), false, "private/reserved"},
		{"CGNAT rejected", func() ReportCandidate { c := good; c.SrcIP = "100.100.1.2"; return c }(), false, "private/reserved"},
		{"TEST-NET rejected", func() ReportCandidate { c := good; c.SrcIP = "203.0.113.7"; return c }(), false, "private/reserved"},
		{"benchmarking rejected", func() ReportCandidate { c := good; c.SrcIP = "198.18.0.1"; return c }(), false, "private/reserved"},
		{"IPv6 documentation rejected", func() ReportCandidate { c := good; c.SrcIP = "2001:db8::1"; return c }(), false, "private/reserved"},
		{"malformed IP rejected", func() ReportCandidate { c := good; c.SrcIP = "not-an-ip"; return c }(), false, "malformed"},
		{"non-brute playbook rejected", func() ReportCandidate { c := good; c.Playbook = "crypto_target"; return c }(), false, "not a brute-force"},
		{"low probe rejected", func() ReportCandidate { c := good; c.ProbeScore = 30; return c }(), false, "probe score"},
		{"low volume rejected", func() ReportCandidate { c := good; c.EventCount = 5; c.UniqueUsers = 1; return c }(), false, "floor"},
		{"service_account_enum accepted", func() ReportCandidate { c := good; c.Playbook = "service_account_enum"; return c }(), true, ""},
		{"public IPv6 accepted", func() ReportCandidate { c := good; c.SrcIP = "2606:4700:4700::1111"; return c }(), true, ""},

		// Staleness. A report asserts present-tense abuse, so an attacker that
		// stopped weeks ago must not be offered — the suggestions widget was
		// recommending 31-50 day old IPs because nothing here could see the date.
		{"dormant IP rejected", func() ReportCandidate {
			c := good
			c.LastSeen = vetNow.Add(-31 * 24 * time.Hour)
			return c
		}(), false, "dormant"},
		{"missing last-seen rejected", func() ReportCandidate { c := good; c.LastSeen = time.Time{}; return c }(), false, "no last-seen"},
		{"just inside the age bound accepted", func() ReportCandidate {
			c := good
			c.LastSeen = vetNow.Add(-defaultMaxAgeDays * 24 * time.Hour).Add(time.Minute)
			return c
		}(), true, ""},
		{"just outside the age bound rejected", func() ReportCandidate {
			c := good
			c.LastSeen = vetNow.Add(-defaultMaxAgeDays * 24 * time.Hour).Add(-time.Minute)
			return c
		}(), false, "dormant"},
		// Clock skew must not block a live attacker: a future timestamp yields a
		// negative age, which is not stale.
		{"future last-seen accepted", func() ReportCandidate { c := good; c.LastSeen = vetNow.Add(time.Hour); return c }(), true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := Vet(tc.cand, admin, 60, vetNow)
			if ok != tc.want {
				t.Fatalf("Vet ok=%v want=%v (reason=%q)", ok, tc.want, reason)
			}
			if !tc.want && tc.reason != "" && !contains(reason, tc.reason) {
				t.Fatalf("reject reason %q does not contain %q", reason, tc.reason)
			}
		})
	}
}

// TestVetAdminNilSafe verifies a nil admin set doesn't panic and still applies
// the private/reserved reject.
func TestVetAdminNilSafe(t *testing.T) {
	c := ReportCandidate{SrcIP: "192.168.1.1", Playbook: "dictionary_spray", ProbeScore: 90, EventCount: 100,
		UniqueUsers: 10, LastSeen: vetNow}
	if ok, _ := Vet(c, nil, 60, vetNow); ok {
		t.Fatal("private IP must be rejected even with nil admin set")
	}
}

// TestVetMaxAgeDaysOnlyTightens pins the VetOptions contract shared with
// bazaar/urlhaus: an operator may make the gate stricter, never looser. A knob
// that could be widened to 90 would re-open exactly the bug this gate closed,
// and an out-of-range or unset value must fall back to the hard default rather
// than to "no limit".
func TestVetMaxAgeDaysOnlyTightens(t *testing.T) {
	cand := func(ageDays int) ReportCandidate {
		return ReportCandidate{
			SrcIP: "8.8.8.8", Playbook: "fast_dictionary_spray", ProbeScore: 80,
			EventCount: 500, UniqueUsers: 40,
			LastSeen: vetNow.Add(-time.Duration(ageDays) * 24 * time.Hour),
		}
	}
	// 5 days old: accepted by default, rejected once the operator tightens to 3.
	if ok, reason := Vet(cand(5), nil, 60, vetNow); !ok {
		t.Fatalf("5d-old candidate rejected under the default %dd bound: %s", defaultMaxAgeDays, reason)
	}
	if ok, _ := Vet(cand(5), nil, 60, vetNow, VetOptions{MaxAgeDays: 3}); ok {
		t.Error("MaxAgeDays=3 did not tighten the gate: a 5-day-old candidate still passed")
	}
	// Every attempt to loosen must land back on the default, so a 10-day-old
	// candidate stays rejected regardless of what was asked for.
	for _, opt := range []VetOptions{
		{MaxAgeDays: 0},   // unset
		{MaxAgeDays: 30},  // wider than the default
		{MaxAgeDays: 365}, // absurdly wider
		{MaxAgeDays: -1},  // nonsense
	} {
		if ok, _ := Vet(cand(10), nil, 60, vetNow, opt); ok {
			t.Errorf("VetOptions{MaxAgeDays: %d} loosened the gate: a 10-day-old candidate passed",
				opt.MaxAgeDays)
		}
	}
}

// TestVetStalenessBeatsAcceptSignals is the hard-rejects-always-win half of the
// vetting-gate pattern. The dormant IPs actually offered by the widget were not
// marginal — they carried probe 100 and six-figure event counts, which is
// precisely why the staleness check has to run BEFORE the accept signals rather
// than being weighed against them. The figures below are the real top actor's.
func TestVetStalenessBeatsAcceptSignals(t *testing.T) {
	maximal := ReportCandidate{
		SrcIP: "8.8.8.8", Playbook: "fast_dictionary_spray", ProbeScore: 100,
		EventCount: 302872, UniqueUsers: 1895, AttemptsPerHour: 373,
		LastSeen: vetNow.Add(-50 * 24 * time.Hour),
	}
	ok, reason := Vet(maximal, nil, 60, vetNow)
	if ok {
		t.Fatal("a maximally-scoring but 50-day-dormant candidate was accepted; " +
			"accept signals must never outvote a hard reject")
	}
	if !contains(reason, "dormant") {
		t.Errorf("reject reason %q should name staleness, not some later gate", reason)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
