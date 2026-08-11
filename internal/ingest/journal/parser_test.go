package journal

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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

func TestParseFailedPublicKeyForInvalidUser(t *testing.T) {
	line := "2026-05-21T07:09:07+00:00 arm sshd[3152395]: Failed publickey for invalid user foo from 203.0.113.42 port 34400 ssh2"
	e, ok := ParseLine(line)
	if !ok {
		t.Fatal("expected failed public-key line for an invalid user to parse")
	}
	if e.Username != "foo" {
		t.Fatalf("username = %q, want %q", e.Username, "foo")
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

// Regression: found by FuzzParseLine. journald hands us the line verbatim and
// an attacker picks the username/client string inside it, so arbitrary bytes
// reached Event.Raw and Event.Username. Nothing crashed, but the bytes were
// stored in SQLite as invalid UTF-8 while the dashboard served U+FFFD
// (encoding/json substitutes on marshal) — storage and presentation disagreed.
// The cowrie path never had this because json.Unmarshal already substitutes,
// so the two ingest sources gave different guarantees for the same columns.
func TestParseLineSanitisesInvalidUTF8AndNUL(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{
			"invalid utf-8 in hostname (the fuzzer's find)",
			"0000-01-10T0:00:00+0000 \x88 sshd[0]: Failed password for 0from 0.0.0.0",
		},
		{
			"invalid utf-8 in username",
			"2026-08-10T12:00:00+0000 arm sshd[1]: Failed password for ro\xffot from 1.2.3.4 port 22 ssh2",
		},
		{
			"NUL in username",
			"2026-08-10T12:00:00+0000 arm sshd[1]: Failed password for ro\x00ot from 1.2.3.4 port 22 ssh2",
		},
		{
			"lone surrogate bytes in client string",
			"2026-08-10T12:00:00+0000 arm sshd[1]: Invalid user \xed\xa0\x80 from 1.2.3.4 port 22",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, ok := ParseLine(c.line)
			if !ok {
				return // not matching a known pattern is a fine outcome
			}
			for name, v := range map[string]string{
				"Raw": ev.Raw, "Username": ev.Username, "SrcIP": ev.SrcIP,
				"SSHClient": ev.SSHClient,
			} {
				if !utf8.ValidString(v) {
					t.Errorf("%s is not valid UTF-8: %q", name, v)
				}
				if strings.ContainsRune(v, 0) {
					t.Errorf("%s contains a NUL byte: %q", name, v)
				}
			}
		})
	}
}

// Sanitisation must not disturb ordinary lines, including legitimate non-ASCII.
func TestSanitiseTextPreservesValidInput(t *testing.T) {
	for _, s := range []string{
		"", "plain ascii", "root", "1.2.3.4",
		"üñïçø∂é user", "日本語", "emoji 🔥 ok",
	} {
		if got := sanitiseText(s); got != s {
			t.Errorf("sanitiseText(%q) = %q, want unchanged", s, got)
		}
	}
	if got := sanitiseText("a\x00b"); got != "ab" {
		t.Errorf("NUL should be dropped, got %q", got)
	}
	if got := sanitiseText("a\xffb"); got != "a\uFFFDb" {
		t.Errorf("invalid byte should become U+FFFD, got %q", got)
	}
}
