package journal

import (
	"bufio"
	"io"
	"os"
	"strings"

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
		if strings.Contains(line, marker) {
			return true
		}
	}
	return false
}

func persistJournalEvents(st *store.Store, events []*models.Event, adminIPs []string, replace bool) (*Result, error) {
	admin := actor.AdminSet(adminIPs)
	skippedAdmin := 0
	stored := make([]*models.Event, 0, len(events))
	attack := make([]*models.Event, 0, len(events))
	for _, e := range events {
		if e.Kind == models.KindAccepted && admin.Has(e.SrcIP) {
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
	actor.AssignJournalActorIDs(attack, admin)

	var aggActors []*models.AggregatedActor
	actorCount := 0
	var duplicates int
	if replace {
		aggActors = actor.BuildFromJournalAggregated(attack, admin)
		actorCount = len(aggActors)
		if err := st.ReplaceSourceEventsAndActorsAgg(models.SourceJournal, stored, aggActors); err != nil {
			return nil, err
		}
	} else {
		// Batched dedup: build the set of identities already in the DB for
		// this source in one query, then filter in memory. Previously this
		// was an N+1 (one EventExists per candidate event).
		freshStored, dupes, err := batchDedupJournal(st, stored)
		if err != nil {
			return nil, err
		}
		duplicates = dupes
		// Nothing new — skip the full actor rebuild (which streams the
		// entire persisted journal history and rewrites every journal
		// actor row). This is the common case on daemon restart, where
		// the 30-day journalctl seed re-offers already-ingested lines.
		if len(freshStored) == 0 {
			return &Result{
				Events:       0,
				Actors:       0,
				SkippedAdmin: skippedAdmin,
				Duplicates:   duplicates,
			}, nil
		}
		// Lifetime state may outlive retained events. Fold only fresh rows into
		// durable counters, under the same post-dedup transaction as live ingest.
		// Each writer batch is bounded; retry safely deduplicates committed pages.
		touched := map[string]struct{}{}
		for start := 0; start < len(freshStored); start += 500 {
			page := freshStored[start:min(start+500, len(freshStored))]
			n, err := st.AppendJournalEventsAtomic(page)
			if err != nil {
				return nil, err
			}
			duplicates += len(page) - n
			for _, e := range page {
				if e.ActorID != "" && e.ID != 0 {
					touched[e.ActorID] = struct{}{}
				}
			}
		}
		actorCount = len(touched)
	}

	return &Result{
		Events:       len(stored) - duplicates,
		Actors:       actorCount,
		SkippedAdmin: skippedAdmin,
		Duplicates:   duplicates,
	}, nil
}

// batchDedupJournal returns the subset of candidates that does NOT match an
// existing row in the events table, along with the duplicate count. Batches
// by ts (the most selective column for journal ingest because journalctl
// times are second-precision and unique per line) via the shared
// store.IterateEventIdentitiesByTS — which owns the planner workaround that
// previously lived in two diverging copies (this one had regressed into a
// full-source scan; the cowrie copy hadn't).
//
// Journal events carry no session id, so SessionID is "" on both sides of
// the identity comparison and never mismatches.
func batchDedupJournal(st *store.Store, candidates []*models.Event) ([]*models.Event, int, error) {
	if len(candidates) == 0 {
		return nil, 0, nil
	}
	tsSet := make(map[string]struct{}, len(candidates))
	for _, e := range candidates {
		tsSet[store.CanonicalEventTime(e.TS)] = struct{}{}
	}
	tsList := make([]string, 0, len(tsSet))
	for t := range tsSet {
		tsList = append(tsList, t)
	}
	existing := make(map[store.EventIdentity]struct{}, len(tsList))
	if err := st.IterateEventIdentitiesByTS(models.SourceJournal, tsList, func(id store.EventIdentity) {
		existing[id] = struct{}{}
	}); err != nil {
		return nil, 0, err
	}
	fresh := make([]*models.Event, 0, len(candidates))
	dupes := 0
	for _, e := range candidates {
		id := identityForEvent(e)
		if _, ok := existing[id]; ok {
			dupes++
			continue
		}
		// Defensive: also dedupe within the candidate batch itself.
		existing[id] = struct{}{}
		fresh = append(fresh, e)
	}
	return fresh, dupes, nil
}

func identityForEvent(e *models.Event) store.EventIdentity {
	return store.EventIdentity{
		TS:       store.CanonicalEventTime(e.TS),
		Kind:     e.Kind,
		SrcIP:    e.SrcIP,
		SrcPort:  e.SrcPort,
		Raw:      e.Raw,
		Username: e.Username,
	}
}
