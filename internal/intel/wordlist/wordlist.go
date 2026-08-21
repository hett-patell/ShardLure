// Package wordlist generates credential dictionaries from observed
// honeypot traffic. The output is intentionally raw — the goal is a
// drop-in file you can feed to hydra/medusa/hashcat without further
// processing. Frequency ordering matters: the user/pass at the top
// of the list is the most-probed credential we've seen.
package wordlist

import (
	"strings"
)

// Entry is one row in a wordlist. The Username/Password fields are
// set per call site - for usernames.txt only Username is populated,
// for passwords.txt only Password, for combos both.
type Entry struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Count    int    `json:"count"`
}

// NOTE: the event-slice collectors (CollectUsernames/CollectPasswords/
// CollectCombos) were removed. The web handler counts credentials in SQL
// (store.TopUsernamesSince/TopPasswordsSince/TopCombosSince) — folding the
// window's events in memory undercounted busy deployments by ~60% (a capped
// in-memory fetch was presented as the window total), and a regression test
// (internal/web/threat_test.go) now bans reintroducing the event-slice form.
// This package keeps only the Entry type and the output writers.

// WriteLines writes one value per line, no header, no counts.
// Designed for tools that expect a plain dictionary.
func WriteLines(b *strings.Builder, entries []Entry, pickValue func(Entry) string) {
	for _, e := range entries {
		v := pickValue(e)
		if v == "" {
			continue
		}
		b.WriteString(v)
		b.WriteByte('\n')
	}
}

// WriteCombos writes user:password lines.
func WriteCombos(b *strings.Builder, entries []Entry) {
	for _, e := range entries {
		if e.Username == "" || e.Password == "" {
			continue
		}
		b.WriteString(e.Username)
		b.WriteByte(':')
		b.WriteString(e.Password)
		b.WriteByte('\n')
	}
}
