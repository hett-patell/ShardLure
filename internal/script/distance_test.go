package script

import "testing"

func TestDistanceBasics(t *testing.T) {
	a := []string{"cd", "/tmp", ";", "wget", "<url>"}
	if d := Distance(a, a); d != 0 {
		t.Fatalf("identical = %v", d)
	}
	if d := Distance(a, []string{"cd", "/tmp", ";", "curl", "<url>"}); d != 0.2 {
		t.Fatalf("substitution = %v, want 0.2", d)
	}
	if d := Distance(a, []string{"/tmp", "cd", ";", "wget", "<url>"}); d != 0.2 {
		t.Fatalf("transposition = %v, want 0.2", d)
	}
	if d := Distance(nil, nil); d != 0 {
		t.Fatalf("empty = %v", d)
	}
}

// Families are anchored on their representative, not grown through members:
// with A ~ B and B ~ C but A !~ C, C must not join A's family through B.
func TestAssignFamilyDoesNotChain(t *testing.T) {
	a := make([]string, 20)
	for i := range a {
		a[i] = "t"
	}
	edit := func(src []string, from, to int, tag string) []string {
		out := append([]string(nil), src...)
		for i := from; i < to; i++ {
			out[i] = tag
		}
		return out
	}
	b := edit(a, 0, 2, "x") // 2 of 20 tokens from A
	c := edit(b, 2, 4, "y") // 2 of 20 from B, 4 of 20 from A
	if d := Distance(a, b); d > FamilyThreshold {
		t.Fatalf("setup: A~B = %v", d)
	}
	if d := Distance(b, c); d > FamilyThreshold {
		t.Fatalf("setup: B~C = %v", d)
	}
	if d := Distance(a, c); d <= FamilyThreshold {
		t.Fatalf("setup: A!~C = %v", d)
	}
	reps := []Rep{{Fingerprint: "A", Tokens: a}}
	if fp, _, ok := AssignFamily(b, reps); !ok || fp != "A" {
		t.Fatalf("B not assigned to A: %v %v", fp, ok)
	}
	// Contrast: were B a representative too, C would join through it, so
	// the fixture really chains and the next assertion is not vacuous.
	if fp, _, ok := AssignFamily(c, []Rep{{Fingerprint: "A", Tokens: a}, {Fingerprint: "B", Tokens: b}}); !ok || fp != "B" {
		t.Fatalf("setup: C beside rep B = %v %v, want B", fp, ok)
	}
	// B joined A's family as a member; only A represents it.
	if fp, d, ok := AssignFamily(c, reps); ok {
		t.Fatalf("C chained into A's family through B: %v at %v", fp, d)
	}
}

// The 0.8 length-ratio pre-filter must skip the O(n*m) distance entirely,
// not merely lose on the threshold afterwards (it always would: distance is
// at least 1-ratio). Distance calls are counted through the seam.
func TestAssignFamilyAppliesLengthBand(t *testing.T) {
	calls := 0
	orig := familyDistance
	familyDistance = func(a, b []string) float64 { calls++; return orig(a, b) }
	defer func() { familyDistance = orig }()

	toks := func(n int) []string { return make([]string, n) }
	reps := []Rep{
		{Fingerprint: "a79", Tokens: toks(79)},   // 79/100 < 0.8: skipped
		{Fingerprint: "b80", Tokens: toks(80)},   // 80/100 = 0.8: compared
		{Fingerprint: "c100", Tokens: toks(100)}, // compared
		{Fingerprint: "d125", Tokens: toks(125)}, // 100/125 = 0.8: compared
		{Fingerprint: "e126", Tokens: toks(126)}, // 100/126 < 0.8: skipped
		{Fingerprint: "f0", Tokens: nil},         // empty: skipped
	}
	if fp, _, ok := AssignFamily(toks(100), reps); !ok || fp != "c100" {
		t.Fatalf("AssignFamily = %v %v, want c100", fp, ok)
	}
	if calls != 3 {
		t.Fatalf("Distance computed %d times, want 3 (the in-band reps only)", calls)
	}
	for _, tc := range []struct {
		a, b int
		in   bool
	}{{8, 10, true}, {10, 8, true}, {79, 100, false}, {0, 0, false}, {0, 5, false}} {
		if got := InLengthBand(tc.a, tc.b); got != tc.in {
			t.Errorf("InLengthBand(%d,%d) = %v", tc.a, tc.b, got)
		}
	}
}

func TestAssignFamilyTieGoesToSmallestFingerprint(t *testing.T) {
	x := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	reps := []Rep{{Fingerprint: "aa", Tokens: x}, {Fingerprint: "bb", Tokens: x}}
	if fp, _, _ := AssignFamily(x, reps); fp != "aa" {
		t.Fatalf("tie went to %q", fp)
	}
}
