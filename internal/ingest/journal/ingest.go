package journal

import (
	"bufio"
	"io"
	"os"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

type Result struct {
	Events       int
	Actors       int
	SkippedAdmin int
	SkippedLines int
	Duplicates   int
}

func IngestFile(st *store.Store, path string, adminIPs []string, replace bool) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	events, skippedLines, err := parseReaderCounting(f)
	if err != nil {
		return nil, err
	}

	res, err := persistJournalEvents(st, events, adminIPs, replace)
	if res != nil {
		res.SkippedLines = skippedLines
	}
	return res, err
}

// parseReaderCounting parses journal lines and returns (events, malformedLineCount, err).
// A "malformed" line is non-empty and does not match any sshd regex we care about.
func parseReaderCounting(r io.Reader) ([]*models.Event, int, error) {
	var events []*models.Event
	var skipped int
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if e, ok := ParseLine(line); ok {
			events = append(events, e)
			continue
		}
		// Only count lines that look like sshd traffic but failed to parse;
		// random unrelated journal lines aren't "skipped" telemetry.
		if looksLikeSSHD(line) {
			skipped++
		}
	}
	return events, skipped, sc.Err()
}

func looksLikeSSHD(line string) bool {
	for _, marker := range []string{"sshd[", "Invalid user", "Failed password", "Failed publickey", "Accepted "} {
		if containsASCII(line, marker) {
			return true
		}
	}
	return false
}

func containsASCII(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(s, sub string) int {
	n := len(sub)
	if n == 0 {
		return 0
	}
	for i := 0; i+n <= len(s); i++ {
		if s[i:i+n] == sub {
			return i
		}
	}
	return -1
}

func persistJournalEvents(st *store.Store, events []*models.Event, adminIPs []string, replace bool) (*Result, error) {
	admin := actor.AdminSet(adminIPs)
	skippedAdmin := 0
	var stored []*models.Event
	var attack []*models.Event
	for _, e := range events {
		if e.Kind == models.KindAccepted && admin[e.SrcIP] {
			skippedAdmin++
			continue
		}
		if e.Kind == models.KindAccepted {
			// Non-allowlisted success is stored as telemetry but does not form an attacker actor.
			stored = append(stored, e)
			continue
		}
		attack = append(attack, e)
		stored = append(stored, e)
	}

	var actors []*models.Actor
	var duplicates int
	if replace {
		actors = actor.BuildFromJournal(attack, admin)
		if err := st.ReplaceSourceEventsAndActors(models.SourceJournal, stored, actors); err != nil {
			return nil, err
		}
	} else {
		// Dedup against what's already persisted before appending.
		var fresh []*models.Event
		for _, e := range stored {
			exists, err := st.EventExists(e)
			if err != nil {
				return nil, err
			}
			if exists {
				duplicates++
				continue
			}
			fresh = append(fresh, e)
		}
		all, err := st.EventsBySource(models.SourceJournal)
		if err != nil {
			return nil, err
		}
		all = append(all, fresh...)
		actors = actor.BuildFromJournal(filterAttackJournalEvents(all), admin)
		if err := st.AppendEventsAndReplaceActors(models.SourceJournal, fresh, all, actors); err != nil {
			return nil, err
		}
	}

	return &Result{
		Events:       len(stored) - duplicates,
		Actors:       len(actors),
		SkippedAdmin: skippedAdmin,
		Duplicates:   duplicates,
	}, nil
}

func filterAttackJournalEvents(events []*models.Event) []*models.Event {
	var out []*models.Event
	for _, e := range events {
		if e.Kind != models.KindAccepted {
			out = append(out, e)
		}
	}
	return out
}
