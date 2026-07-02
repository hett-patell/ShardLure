package journal

import (
	"bufio"
	"io"
	"os"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/netmatch"
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
	var duplicates int
	if replace {
		aggActors = actor.BuildFromJournalAggregated(attack, admin)
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
		// Rebuild actors by streaming persisted journal events + the
		// fresh attack subset; never materializes the full event set.
		aggActors, err = buildJournalActorsFromDB(st, freshAttackOnly(freshStored), admin)
		if err != nil {
			return nil, err
		}
		if err := st.AppendEventsAndReplaceActorsAgg(models.SourceJournal, freshStored, aggActors); err != nil {
			return nil, err
		}
	}

	return &Result{
		Events:       len(stored) - duplicates,
		Actors:       len(aggActors),
		SkippedAdmin: skippedAdmin,
		Duplicates:   duplicates,
	}, nil
}

// buildJournalActorsFromDB streams persisted *attack* journal events past
// the collector and folds in the fresh attack batch.
func buildJournalActorsFromDB(st *store.Store, fresh []*models.Event, admin *netmatch.Set) ([]*models.AggregatedActor, error) {
	jc := actor.NewJournalCollector(admin)
	if err := st.IterateEventsBySource(models.SourceJournal, func(e *models.Event) error {
		// Accepted/admin lines are stored but never form an actor.
		if e.Kind == models.KindAccepted {
			return nil
		}
		jc.Add(e)
		return nil
	}); err != nil {
		return nil, err
	}
	for _, e := range fresh {
		jc.Add(e)
	}
	return jc.Finalize(), nil
}

// batchDedupJournal returns the subset of candidates that does NOT match an
// existing row in the events table, along with the duplicate count. The
// previous implementation issued one EventExists round-trip per candidate
// (N+1 query). This batches by ts (the most selective column for journal
// ingest because journalctl times are second-precision and unique per line)
// and disambiguates the rest in Go.
func batchDedupJournal(st *store.Store, candidates []*models.Event) ([]*models.Event, int, error) {
	if len(candidates) == 0 {
		return nil, 0, nil
	}
	// Collect unique ts values from the candidate set.
	tsSet := make(map[string]struct{}, len(candidates))
	for _, e := range candidates {
		tsSet[e.TS.UTC().Format(time.RFC3339Nano)] = struct{}{}
	}
	// SQLite limits IN-list size; chunk to be safe.
	const chunk = 400
	tsList := make([]string, 0, len(tsSet))
	for t := range tsSet {
		tsList = append(tsList, t)
	}
	existing := make(map[journalIdentity]struct{}, len(tsList))
	for i := 0; i < len(tsList); i += chunk {
		end := i + chunk
		if end > len(tsList) {
			end = len(tsList)
		}
		batch := tsList[i:end]
		if err := loadExistingJournalIdentities(st, batch, existing); err != nil {
			return nil, 0, err
		}
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

type journalIdentity struct {
	TS       string
	Kind     models.EventKind
	IP       string
	Username string
	Command  string
}

func identityForEvent(e *models.Event) journalIdentity {
	return journalIdentity{
		TS:       e.TS.UTC().Format(time.RFC3339Nano),
		Kind:     e.Kind,
		IP:       e.SrcIP,
		Username: e.Username,
		Command:  e.Command,
	}
}

func loadExistingJournalIdentities(st *store.Store, tsBatch []string, into map[journalIdentity]struct{}) error {
	if len(tsBatch) == 0 {
		return nil
	}
	placeholders := make([]string, len(tsBatch))
	args := make([]any, 0, len(tsBatch))
	for i, t := range tsBatch {
		placeholders[i] = "?"
		args = append(args, t)
	}
	// Filter on ts only, NOT source — same planner pathology the cowrie
	// dedup already works around (see batchDedupCowrie): a `source=?`
	// constraint makes SQLite pick a source-prefixed index and scan every
	// journal row in the table per chunk, while `ts IN (...)` alone is
	// point lookups on idx_events_ts (verified via EXPLAIN QUERY PLAN).
	// The source filter is re-applied in Go.
	query := "SELECT source, ts, kind, src_ip, username, command FROM events WHERE ts IN (" +
		strings.Join(placeholders, ",") + ")"
	return st.QueryRows(query, args, func(scan func(...any) error) error {
		var src string
		var id journalIdentity
		if err := scan(&src, &id.TS, &id.Kind, &id.IP, &id.Username, &id.Command); err != nil {
			return err
		}
		if src != string(models.SourceJournal) {
			return nil
		}
		into[id] = struct{}{}
		return nil
	})
}

func freshAttackOnly(events []*models.Event) []*models.Event {
	out := make([]*models.Event, 0, len(events))
	for _, e := range events {
		if e.Kind == models.KindAccepted {
			continue
		}
		out = append(out, e)
	}
	return out
}
