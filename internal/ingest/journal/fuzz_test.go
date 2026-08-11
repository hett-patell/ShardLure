package journal

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzParseLine hammers the sshd journal line parser. This input is
// attacker-influenced: usernames, source IPs and client strings all appear in
// the log line verbatim, and an attacker chooses them. A panic here would take
// down the journal tail goroutine (and with it all journal ingest) for the
// daemon's remaining lifetime.
//
// Run longer with:
//
//	go test ./internal/ingest/journal/ -run=Fuzz -fuzz=FuzzParseLine -fuzztime=60s
func FuzzParseLine(f *testing.F) {
	seeds := []string{
		"2026-08-10T12:00:00+0000 arm sshd[123]: Failed password for root from 1.2.3.4 port 55000 ssh2",
		"2026-08-10T12:00:00+0000 arm sshd[123]: Invalid user admin from 5.6.7.8 port 22",
		"2026-08-10T12:00:00+0000 arm sshd[1]: Accepted publickey for ubuntu from 9.9.9.9 port 1 ssh2: RSA SHA256:abc",
		"2026-08-10T12:00:00+0000 arm sshd[9]: Connection closed by authenticating user root 1.2.3.4 port 5 [preauth]",
		"2026-08-10T12:00:00+0000 arm sshd[9]: Received disconnect from 1.2.3.4 port 5:11: Bye Bye [preauth]",
		"",
		" ",
		"garbage",
		// Attacker-controlled username containing the very tokens the parser
		// keys on — a classic way to confuse a field-splitting parser.
		"2026-08-10T12:00:00+0000 arm sshd[1]: Failed password for from port 22 from 1.2.3.4 port 22 ssh2",
		"2026-08-10T12:00:00+0000 arm sshd[1]: Failed password for invalid user  from 1.2.3.4 port 22 ssh2",
		"2026-08-10T12:00:00+0000 arm sshd[1]: Failed password for root from not-an-ip port abc ssh2",
		"2026-08-10T12:00:00+0000 arm sshd[1]: Failed password for root from 1.2.3.4 port 99999999999999999999 ssh2",
		"2026-08-10T12:00:00+0000 arm sshd[1]: Failed password for \x00\x01\x02 from 1.2.3.4 port 22 ssh2",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		ev, ok := ParseLine(line)
		if !ok {
			if ev != nil {
				t.Fatalf("ok=false must return a nil event, got %+v", ev)
			}
			return
		}
		if ev == nil {
			t.Fatal("ok=true must return a non-nil event")
		}
		// Fields that reach SQLite and then the dashboard must be valid UTF-8;
		// invalid bytes would corrupt JSON responses and the TUI.
		for name, v := range map[string]string{
			"Username": ev.Username, "SrcIP": ev.SrcIP,
			"Kind": string(ev.Kind), "Raw": ev.Raw, "SSHClient": ev.SSHClient,
		} {
			if !utf8.ValidString(v) {
				t.Errorf("%s is not valid UTF-8: %q (line %q)", name, v, line)
			}
		}
		// A parsed event must never carry an embedded NUL: SQLite treats it as
		// a string terminator in some tooling and check-utf8 rejects it.
		if strings.ContainsRune(ev.Username, 0) || strings.ContainsRune(ev.SrcIP, 0) {
			t.Errorf("NUL byte in parsed field from %q", line)
		}
		if ev.Kind == "" {
			t.Errorf("parsed event has empty Kind: %q", line)
		}
	})
}
