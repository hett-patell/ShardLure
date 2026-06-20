package netmatch

import (
	"net"
	"testing"
)

func TestSetHas(t *testing.T) {
	s := New([]string{
		"203.0.113.7",    // bare IPv4
		"192.168.0.0/16", // IPv4 CIDR
		"100.64.0.0/10",  // Tailscale CGNAT range
		"2001:db8::/32",  // IPv6 CIDR
		"  10.0.0.1  ",   // whitespace tolerated
		"",               // skipped
		"not-an-ip",      // skipped (Invalid would surface it)
	})

	cases := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.7", true},    // exact IPv4
		{"203.0.113.8", false},   // adjacent, not listed
		{"192.168.1.50", true},   // inside /16
		{"192.169.0.1", false},   // outside /16
		{"100.100.50.1", true},   // inside CGNAT /10 — the regression case
		{"101.0.0.1", false},     // outside /10
		{"2001:db8::dead", true}, // inside IPv6 /32
		{"2001:dead::1", false},  // outside IPv6 /32
		{"10.0.0.1", true},       // trimmed exact
		{"", false},              // empty
		{"garbage", false},       // unparseable
	}
	for _, c := range cases {
		if got := s.Has(c.ip); got != c.want {
			t.Errorf("Has(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

// TestCIDRRegression is the specific bug the change fixes: a CIDR admin entry
// used to parse to nil under net.ParseIP and match nothing.
func TestCIDRRegression(t *testing.T) {
	s := New([]string{"192.168.1.0/24"})
	if !s.Has("192.168.1.42") {
		t.Fatal("CIDR admin entry must match addresses inside the range")
	}
	if s.Has("192.168.2.42") {
		t.Fatal("CIDR admin entry must not match addresses outside the range")
	}
}

func TestHasIP(t *testing.T) {
	s := New([]string{"10.0.0.0/8"})
	if !s.HasIP(net.ParseIP("10.5.6.7")) {
		t.Error("HasIP should match inside /8")
	}
	if s.HasIP(net.ParseIP("11.0.0.1")) {
		t.Error("HasIP should not match outside /8")
	}
	if s.HasIP(nil) {
		t.Error("HasIP(nil) must be false")
	}
}

func TestNilAndEmpty(t *testing.T) {
	var s *Set
	if s.Has("1.2.3.4") {
		t.Error("nil set must match nothing")
	}
	if New(nil).Has("1.2.3.4") {
		t.Error("empty set must match nothing")
	}
}

func TestInvalid(t *testing.T) {
	bad := Invalid([]string{"1.2.3.4", "10.0.0.0/8", "nope", "", "  ", "5.6.7.8/33"})
	want := map[string]bool{"nope": true, "5.6.7.8/33": true}
	if len(bad) != len(want) {
		t.Fatalf("Invalid returned %v, want keys %v", bad, want)
	}
	for _, b := range bad {
		if !want[b] {
			t.Errorf("unexpected invalid entry %q", b)
		}
	}
}

func TestKeyOrderIndependent(t *testing.T) {
	a := New([]string{"10.0.0.1", "10.0.0.2", "192.168.0.0/16"})
	b := New([]string{"192.168.0.0/16", "10.0.0.2", "10.0.0.1"})
	if a.Key() != b.Key() {
		t.Errorf("Key must be order-independent:\n a=%q\n b=%q", a.Key(), b.Key())
	}
	c := New([]string{"10.0.0.1"})
	if a.Key() == c.Key() {
		t.Error("different sets must have different keys")
	}
	var nilSet *Set
	if nilSet.Key() != "" {
		t.Error("nil set Key must be empty string")
	}
}
