// Package wordlist generates credential dictionaries from observed
// honeypot traffic. The output is intentionally raw — the goal is a
// drop-in file you can feed to hydra/medusa/hashcat without further
// processing. Frequency ordering matters: the user/pass at the top
// of the list is the most-probed credential we've seen.
package wordlist

import (
	"sort"
	"strings"

	"github.com/networkshard/shardlure/pkg/models"
)

// Entry is one row in a wordlist. The Username/Password fields are
// set per call site - for usernames.txt only Username is populated,
// for passwords.txt only Password, for combos both.
type Entry struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Count    int    `json:"count"`
}

// CollectUsernames returns every distinct username observed in any
// authentication attempt, ranked by frequency (descending).
func CollectUsernames(events []*models.Event) []Entry {
	counts := map[string]int{}
	for _, e := range events {
		if e == nil {
			continue
		}
		u := strings.TrimSpace(e.Username)
		if u == "" {
			continue
		}
		if !isCredentialEvent(e.Kind) {
			continue
		}
		counts[u]++
	}
	return rank(counts, func(k string, c int) Entry { return Entry{Username: k, Count: c} })
}

// CollectPasswords returns every distinct password observed (only
// failed-password events carry a usable Password value in cowrie).
func CollectPasswords(events []*models.Event) []Entry {
	counts := map[string]int{}
	for _, e := range events {
		if e == nil {
			continue
		}
		p := e.Password
		if p == "" {
			continue
		}
		if !isCredentialEvent(e.Kind) {
			continue
		}
		counts[p]++
	}
	return rank(counts, func(k string, c int) Entry { return Entry{Password: k, Count: c} })
}

// CollectCombos returns user:password pairs ranked by frequency.
// Empty halves are skipped (a pair with no password is just a
// username probe, already in the usernames list).
func CollectCombos(events []*models.Event) []Entry {
	type k struct{ u, p string }
	counts := map[k]int{}
	for _, e := range events {
		if e == nil {
			continue
		}
		if !isCredentialEvent(e.Kind) {
			continue
		}
		u := strings.TrimSpace(e.Username)
		if u == "" || e.Password == "" {
			continue
		}
		counts[k{u, e.Password}]++
	}
	out := make([]Entry, 0, len(counts))
	for kk, c := range counts {
		out = append(out, Entry{Username: kk.u, Password: kk.p, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].Username != out[j].Username {
			return out[i].Username < out[j].Username
		}
		return out[i].Password < out[j].Password
	})
	return out
}

// isCredentialEvent gates which event kinds carry a usable username
// / password pair. Failed and accepted logins both surface them.
func isCredentialEvent(k models.EventKind) bool {
	switch k {
	case models.KindFailedPass, models.KindFailedKey, models.KindInvalidUser, models.KindAccepted:
		return true
	}
	return false
}

func rank(counts map[string]int, mk func(string, int) Entry) []Entry {
	out := make([]Entry, 0, len(counts))
	for k, c := range counts {
		out = append(out, mk(k, c))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		// Stable tie-break on the populated field
		a := out[i].Username + out[i].Password
		b := out[j].Username + out[j].Password
		return a < b
	})
	return out
}

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
