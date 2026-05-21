package journal

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
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

func TestParseIPv6Source(t *testing.T) {
	line := "2026-05-21T07:09:07+00:00 arm sshd[3152395]: Invalid user root from 2001:db8::42 port 34400"
	e, ok := ParseLine(line)
	if !ok {
		t.Fatalf("expected IPv6 journal line to parse")
	}
	if e.SrcIP != "2001:db8::42" {
		t.Fatalf("expected IPv6 source, got %q", e.SrcIP)
	}
	if e.SrcPort != 34400 {
		t.Fatalf("expected source port 34400, got %d", e.SrcPort)
	}
}

func TestJournalReplaceKeepsCowrieData(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	cowrieEvent := &models.Event{
		TS:     time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC),
		Source: models.SourceCowrie,
		Kind:   models.KindFailedPass,
		SrcIP:  "198.51.100.10",
		Raw:    "cowrie-line",
	}
	if err := st.InsertEvent(cowrieEvent); err != nil {
		t.Fatalf("insert cowrie event: %v", err)
	}

	path := filepath.Join(t.TempDir(), "journal.log")
	body := "2026-05-21T07:09:07+00:00 arm sshd[3152395]: Invalid user root from 203.0.113.10 port 34400\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write journal: %v", err)
	}
	if _, err := IngestFile(st, path, nil, true); err != nil {
		t.Fatalf("journal replace ingest: %v", err)
	}
	events, err := st.EventsBySource(models.SourceCowrie)
	if err != nil {
		t.Fatalf("load cowrie events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected cowrie event to survive journal replace, got %d", len(events))
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
