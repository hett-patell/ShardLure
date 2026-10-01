package main

import (
	"bytes"
	"strings"
	"testing"
)

// Every command the dispatcher accepts must appear in the usage text. Two
// shipped commands did not: `reclassify` (whole subcommand missing) and
// `share threatfox` (listed beside bazaar/urlhaus in `share`'s own usage, but
// not at the top level), leaving both undiscoverable from the binary's help
// despite being fully wired to CLI and dashboard.
func TestUsageDocumentsEveryDispatchedCommand(t *testing.T) {
	var buf bytes.Buffer
	usageTo(&buf)
	got := buf.String()

	for _, cmd := range []string{
		"ingest",
		"actors",
		"actor show",
		"reclassify",
		"dashboard",
		"web",
		"live",
		"run",
		"status",
		"ioc",
		"share bazaar",
		"share urlhaus",
		"share threatfox",
		"report abuseipdb",
		"campaigns",
		"campaign show",
		"scripts",
		"scripts --rebuild",
	} {
		if !strings.Contains(got, "shardlure "+cmd) {
			t.Errorf("usage() does not document %q\n---\n%s", cmd, got)
		}
	}
}

// The usage text matches what the commands accept: actor show takes an
// actor ID as well as an IP, and actors documents its 0 = all (audit M6).
func TestUsageDocumentsActorArgs(t *testing.T) {
	var buf bytes.Buffer
	usageTo(&buf)
	got := buf.String()
	for _, want := range []string{"shardlure actor show <id|ip>", "0 = all"} {
		if !strings.Contains(got, want) {
			t.Errorf("usage lacks %q", want)
		}
	}
}
