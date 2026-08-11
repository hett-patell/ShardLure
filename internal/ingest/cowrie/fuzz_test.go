package cowrie

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzParseReader fuzzes the Cowrie jsonlog reader.
//
// Cowrie writes this file while an attacker is connected, so the content is
// attacker-influenced (usernames, passwords, commands, client strings) and the
// tail can be a half-written line. parseReader also runs the bounded line
// reader that exists so one oversized attacker line is skipped-but-consumed
// rather than wedging ingest forever — worth pinning against regressions.
//
// Longer run:
//
//	go test ./internal/ingest/cowrie/ -run=XXX -fuzz=FuzzParseReader -fuzztime=60s
func FuzzParseReader(f *testing.F) {
	seeds := []string{
		`{"eventid":"cowrie.login.failed","timestamp":"2026-08-10T12:00:00.000000Z","src_ip":"1.2.3.4","username":"root","password":"x","session":"abc"}`,
		`{"eventid":"cowrie.command.input","timestamp":"2026-08-10T12:00:00.000000Z","src_ip":"1.2.3.4","input":"uname -a","session":"abc"}`,
		`{"eventid":"cowrie.client.kex","timestamp":"2026-08-10T12:00:00.000000Z","src_ip":"1.2.3.4","hassh":"aa11","session":"abc"}`,
		`{"eventid":"cowrie.session.file_download","timestamp":"2026-08-10T12:00:00.000000Z","src_ip":"1.2.3.4","url":"http://x/y","shasum":"ab","session":"abc"}`,
		`{"eventid":"cowrie.direct-tcpip.request","timestamp":"2026-08-10T12:00:00.000000Z","src_ip":"1.2.3.4","dst_ip":"1.1.1.1","dst_port":443,"session":"abc"}`,
		"",
		"\n\n\n",
		"not json",
		"{",
		`{"eventid":`,
		// Valid JSON, wrong shapes for every field the ingester reads.
		`{"eventid":123,"timestamp":[],"src_ip":{},"session":null}`,
		`{"eventid":"cowrie.login.failed","timestamp":"","src_ip":"","username":"","session":""}`,
		`{"eventid":"cowrie.login.failed","timestamp":"not-a-time","src_ip":"zzz","username":"u","session":"s"}`,
		// Deep nesting and a duplicated key: both are legal JSON.
		`{"eventid":"cowrie.command.input","input":"a","input":"b","timestamp":"2026-08-10T12:00:00Z","src_ip":"1.2.3.4","session":"s"}`,
		// Two events on separate lines plus a truncated third.
		`{"eventid":"cowrie.login.failed","timestamp":"2026-08-10T12:00:00Z","src_ip":"1.2.3.4","username":"a","session":"s"}` + "\n" +
			`{"eventid":"cowrie.login.failed","timestamp":"2026-08-10T12:00:01Z","src_ip":"1.2.3.4","username":"b","session":"s"}` + "\n" +
			`{"eventid":"cowrie.log`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		events, skipped, consumed, _, err := parseReader(strings.NewReader(data), true)
		if err != nil {
			return
		}
		if consumed < 0 || consumed > int64(len(data)) {
			t.Fatalf("consumed %d bytes of a %d-byte input", consumed, len(data))
		}
		if skipped < 0 {
			t.Fatalf("negative skipped count %d", skipped)
		}
		// The offset bookkeeping is load-bearing: incremental ingest seeks to
		// it, so a value past EOF would silently skip attacker activity.
		if len(events) > len(data)+1 {
			t.Fatalf("produced %d events from %d bytes", len(events), len(data))
		}
		for _, ev := range events {
			// Everything here lands in SQLite and then in dashboard JSON.
			for name, v := range map[string]string{
				"Username": ev.Username, "Password": ev.Password,
				"Command": ev.Command, "SrcIP": ev.SrcIP,
				"SessionID": ev.SessionID, "Kind": string(ev.Kind),
			} {
				if !utf8.ValidString(v) {
					t.Errorf("%s invalid UTF-8: %q", name, v)
				}
				if strings.ContainsRune(v, 0) {
					t.Errorf("%s contains NUL: %q", name, v)
				}
			}
			if ev.Kind == "" {
				t.Error("event with empty Kind")
			}
		}
	})
}
