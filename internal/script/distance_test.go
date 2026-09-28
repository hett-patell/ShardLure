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

func TestAssignFamilyDoesNotChain(t *testing.T) {
	base := make([]string, 20)
	for i := range base {
		base[i] = "t"
	}
	mk := func(n int, tag string) []string {
		out := append([]string(nil), base...)
		for i := 0; i < n; i++ {
			out[i] = tag
		}
		return out
	}
	reps := []Rep{{Fingerprint: "A", Tokens: base}}
	if fp, _, ok := AssignFamily(mk(2, "x"), reps); !ok || fp != "A" {
		t.Fatalf("0.10 variant not assigned: %v %v", fp, ok)
	}
	if _, _, ok := AssignFamily(mk(4, "y"), reps); ok {
		t.Fatal("0.20 from the representative joined the family")
	}
	if _, _, ok := AssignFamily(make([]string, 5), []Rep{{Fingerprint: "B", Tokens: make([]string, 100)}}); ok {
		t.Fatal("length ratio 0.05 must be rejected")
	}
}

func TestAssignFamilyTieGoesToSmallestFingerprint(t *testing.T) {
	x := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	reps := []Rep{{Fingerprint: "aa", Tokens: x}, {Fingerprint: "bb", Tokens: x}}
	if fp, _, _ := AssignFamily(x, reps); fp != "aa" {
		t.Fatalf("tie went to %q", fp)
	}
}
