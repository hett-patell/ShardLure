package intelutil

import "testing"

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"", 5, ""},
		{"abc", 5, "abc"},
		{"abcdef", 6, "abcdef"},
		{"abcdef", 3, "abc…"},
		{"abcdef", 0, "…"},
	}
	for _, c := range cases {
		if got := Truncate(c.in, c.n); got != c.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

// One upstream rule, one implementation: this used to exist twice (a rune
// switch in bazaar, a regex in urlhaus) and the copies had already drifted on
// ordering. Both destinations now share this, so the contract is pinned here.
func TestSanitiseAbuseChTags(t *testing.T) {
	got := SanitiseAbuseChTags([]string{
		"elf", "elf", "linux/x86", "x86_64!", "  ", "shardlure",
		"honey pot", "semi;colon", "dot.dash-ok", "",
	})
	want := []string{"dot.dash-ok", "elf", "honey pot", "linuxx86", "semicolon", "shardlure", "x8664"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tag[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// Output must be deterministic regardless of input order — that is the
	// property that makes submission payloads diffable.
	a := SanitiseAbuseChTags([]string{"zeta", "alpha", "mid"})
	b := SanitiseAbuseChTags([]string{"mid", "zeta", "alpha"})
	if len(a) != len(b) {
		t.Fatalf("length mismatch: %v vs %v", a, b)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("not order-independent: %v vs %v", a, b)
		}
	}

	// Nothing outside [A-Za-z0-9.- ] may survive.
	for _, tag := range SanitiseAbuseChTags([]string{"a/b\\c:d*e?f\"g<h>i|j\nk\tl"}) {
		for _, r := range tag {
			ok := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
				(r >= '0' && r <= '9') || r == '.' || r == '-' || r == ' '
			if !ok {
				t.Errorf("disallowed rune %q survived in %q", r, tag)
			}
		}
	}
	if got := SanitiseAbuseChTags(nil); len(got) != 0 {
		t.Errorf("nil input = %v, want empty", got)
	}
}
