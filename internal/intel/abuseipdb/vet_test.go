package abuseipdb

import (
	"testing"

	"github.com/networkshard/shardlure/internal/netmatch"
)

func TestVet(t *testing.T) {
	admin := netmatch.New([]string{"100.64.0.5", "10.0.0.0/8"})

	// A textbook confirmed brute-forcer: public IP, brute playbook, high probe,
	// well above the event/user floor.
	good := ReportCandidate{
		SrcIP: "203.0.113.7", Playbook: "fast_dictionary_spray",
		ProbeScore: 80, EventCount: 500, UniqueUsers: 40,
	}

	cases := []struct {
		name   string
		cand   ReportCandidate
		want   bool
		reason string // substring expected in the reject reason (when want=false)
	}{
		{"confirmed brute-forcer accepted", good, true, ""},
		{"admin IP rejected", func() ReportCandidate { c := good; c.SrcIP = "100.64.0.5"; return c }(), false, "admin"},
		{"private IP rejected", func() ReportCandidate { c := good; c.SrcIP = "10.1.2.3"; return c }(), false, "private/reserved"},
		{"loopback rejected", func() ReportCandidate { c := good; c.SrcIP = "127.0.0.1"; return c }(), false, "private/reserved"},
		{"malformed IP rejected", func() ReportCandidate { c := good; c.SrcIP = "not-an-ip"; return c }(), false, "malformed"},
		{"non-brute playbook rejected", func() ReportCandidate { c := good; c.Playbook = "crypto_target"; return c }(), false, "not a brute-force"},
		{"low probe rejected", func() ReportCandidate { c := good; c.ProbeScore = 30; return c }(), false, "probe score"},
		{"low volume rejected", func() ReportCandidate { c := good; c.EventCount = 5; c.UniqueUsers = 1; return c }(), false, "floor"},
		{"service_account_enum accepted", func() ReportCandidate { c := good; c.Playbook = "service_account_enum"; return c }(), true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := Vet(tc.cand, admin, 60)
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
	c := ReportCandidate{SrcIP: "192.168.1.1", Playbook: "dictionary_spray", ProbeScore: 90, EventCount: 100, UniqueUsers: 10}
	if ok, _ := Vet(c, nil, 60); ok {
		t.Fatal("private IP must be rejected even with nil admin set")
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
