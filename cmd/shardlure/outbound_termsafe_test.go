package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/intel/abuseipdb"
	"github.com/networkshard/shardlure/internal/intel/bazaar"
	"github.com/networkshard/shardlure/internal/intel/threatfox"
	"github.com/networkshard/shardlure/internal/intel/urlhaus"
	"github.com/networkshard/shardlure/internal/store"
)

// hostile carries an ESC sequence (retitle the terminal), an 8-bit CSI, a
// bidi override and a newline that would forge a table row.
const hostile = "http://x/\x1b]0;pwned\x07\u009b31m‮\nFAKE ROW"

func assertTermSafe(t *testing.T, name, out string) {
	t.Helper()
	for _, bad := range []string{"\x1b", "\x07", "\u009b", "‮", "\nFAKE ROW"} {
		if strings.Contains(out, bad) {
			t.Errorf("%s printed %q raw:\n%q", name, bad, out)
		}
	}
	if !strings.Contains(out, `\x1b`) {
		t.Errorf("%s: hostile text missing or not escaped visibly:\n%q", name, out)
	}
}

// Every share/report progress and status line prints data an attacker chose
// (payload URLs, classifier output derived from their bytes) or a remote
// service returned (status strings, error bodies). CLAUDE.md: attacker-derived
// CLI output goes through termSafe.
func TestShareAndReportOutputIsTermSafe(t *testing.T) {
	now := time.Now()
	remoteErr := errors.New("remote said: " + hostile)
	cases := map[string]func(*bytes.Buffer){
		"urlhaus progress": func(b *bytes.Buffer) {
			fprintURLhausProgress(b, urlhaus.Candidate{URL: hostile}, false, "reason "+hostile)
		},
		"urlhaus submit": func(b *bytes.Buffer) { fprintURLhausProgress(b, urlhaus.Candidate{URL: hostile}, true, hostile) },
		"urlhaus status": func(b *bytes.Buffer) {
			fprintURLhausStatus(b, []store.URLhausSubmission{{SubmittedAt: now, Status: hostile, URL: hostile}})
		},
		"threatfox progress": func(b *bytes.Buffer) {
			fprintThreatFoxProgress(b, threatfox.Candidate{URL: hostile}, true, 2, hostile)
		},
		"threatfox status": func(b *bytes.Buffer) {
			fprintThreatFoxStatus(b, []store.ThreatFoxSubmission{{SubmittedAt: now, IOCType: hostile, Malware: hostile, IOC: hostile}})
		},
		"bazaar progress error": func(b *bytes.Buffer) {
			fprintBazaarProgress(b, bazaar.Candidate{SHA256: hostile}, bazaar.Classification{FileKind: hostile, Family: hostile, Tags: []string{hostile}}, nil, remoteErr)
		},
		"bazaar progress result": func(b *bytes.Buffer) {
			fprintBazaarProgress(b, bazaar.Candidate{SHA256: "ab"}, bazaar.Classification{}, &bazaar.Result{Status: hostile, SampleURL: hostile}, nil)
		},
		"bazaar status": func(b *bytes.Buffer) {
			fprintBazaarStatus(b, []store.BazaarUpload{{SHA256: hostile, UploadedAt: now, ResponseStatus: hostile, MBURL: hostile}})
		},
		"abuseipdb progress": func(b *bytes.Buffer) {
			fprintAbuseReportProgress(b, abuseipdb.ReportCandidate{SrcIP: hostile, Playbook: hostile}, nil, remoteErr)
		},
		"abuseipdb status": func(b *bytes.Buffer) {
			fprintAbuseReportStatus(b, []store.AbuseReport{{IP: hostile, ReportedAt: now, Status: hostile}})
		},
	}
	for name, run := range cases {
		var b bytes.Buffer
		run(&b)
		assertTermSafe(t, name, b.String())
	}
}

// actors --limit follows the campaign commands: 0 or a negative value used to
// reach ListActors as "no limit" and dump every actor, and a stray positional
// argument was ignored.
func TestParseActorsArgs(t *testing.T) {
	for _, c := range []struct {
		args []string
		want int
	}{{nil, 25}, {[]string{"--limit=1"}, 1}, {[]string{"--limit", "1000"}, 1000}} {
		if n, err := parseActorsArgs(c.args); err != nil || n != c.want {
			t.Errorf("%v = %d, %v; want %d", c.args, n, err, c.want)
		}
	}
	for _, args := range [][]string{{"--limit=0"}, {"--limit=-5"}, {"--limit=1001"}, {"extra"}, {"--limti=5"}} {
		if _, err := parseActorsArgs(args); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}
