package journal

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func testdataPath(name string) string {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..", "..")
	return filepath.Join(root, "testdata", name)
}

func TestParseSample(t *testing.T) {
	path := testdataPath("sample.journal")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	var n int
	for _, line := range splitLines(string(b)) {
		if _, ok := ParseLine(line); ok {
			n++
		}
	}
	if n != 7 {
		t.Fatalf("expected 7 events from %s, got %d", path, n)
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
