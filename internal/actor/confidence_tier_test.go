package actor

import "testing"

func TestConfidenceTier(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{ConfidenceJournalBase, "LOW"},          // 55
		{ConfidenceJournalHighAPH, "MEDIUM"},    // 70
		{ConfidenceCowrieBase, "HIGH"},           // 72
		{ConfidenceCowriePayload, "CONFIRMED"},   // 84
		{0, "LOW"},
		{100, "CONFIRMED"},
	}
	for _, c := range cases {
		if got := ConfidenceTier(c.in); got != c.want {
			t.Fatalf("ConfidenceTier(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
