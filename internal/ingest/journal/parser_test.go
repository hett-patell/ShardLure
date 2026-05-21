package journal

import (
	"os"
	"testing"
)

func TestParseSample(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/sample.journal")
	if err != nil {
		t.Skip(err)
	}
	lines := string(b)
	var n int
	for _, line := range splitLines(lines) {
		if _, ok := ParseLine(line); ok {
			n++
		}
	}
	if n != 7 {
		t.Fatalf("expected 7 events, got %d", n)
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
