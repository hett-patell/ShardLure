package store

import (
	"fmt"
	"strings"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// EventIdentity is the tuple the append-mode ingest dedups match on. It is
// the superset used by both sources: journal events carry no session, so
// SessionID is "" there and simply never mismatches.
type EventIdentity struct {
	TS        string // CanonicalEventTime, exactly as persisted
	Kind      models.EventKind
	SrcIP     string
	SrcPort   int
	Raw       string
	SessionID string
	Username  string
	Command   string
}

// IterateEventIdentitiesByTS streams the identity tuple of every persisted
// event of the given source whose ts is in tsList, invoking fn per row.
// tsList is chunked to stay under SQLite's bound-parameter limit.
//
// The SQL deliberately filters on ts only, NOT source: any `source=...`
// constraint (parameter or literal) makes the planner pick a source-prefixed
// index and scan EVERY row of that source per chunk, while `ts IN (...)`
// alone is point lookups on idx_events_ts (both verified via EXPLAIN QUERY
// PLAN). The source filter is re-applied here in Go, so semantics are
// unchanged. This pathology bit the journal ingest once already after the
// cowrie side was fixed independently — which is why the workaround now
// lives in exactly one place.
func (s *Store) IterateEventIdentitiesByTS(source models.Source, tsList []string, fn func(EventIdentity)) error {
	// v20 writes fixed-width UTC; pre-v20 rows use RFC3339Nano with trailing
	// zeroes removed. Match both until backfill is finished, including during
	// the initial journal replay which precedes the background migration.
	keys := make([]string, 0, 2*len(tsList))
	seen := make(map[string]bool, 2*len(tsList))
	for _, raw := range tsList {
		ts, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return fmt.Errorf("event dedup: invalid timestamp")
		}
		canonical := CanonicalEventTime(ts)
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		// Keep pairs intact even if both strings are identical. An even-sized
		// chunk then probes both formats in one SQLite snapshot; backfill cannot
		// move a row from a later chunk into a previously examined one.
		keys = append(keys, canonical, ts.UTC().Format(time.RFC3339Nano))
	}
	tsList = keys
	const chunk = 400
	want := string(source)
	for i := 0; i < len(tsList); i += chunk {
		end := i + chunk
		if end > len(tsList) {
			end = len(tsList)
		}
		batch := tsList[i:end]
		placeholders := make([]string, len(batch))
		args := make([]any, 0, len(batch))
		for j, t := range batch {
			placeholders[j] = "?"
			args = append(args, t)
		}
		// COALESCE the nullable columns: rows predating the legacy-column
		// backfill hold NULL there (ADD COLUMN default), which would fail a
		// plain string scan — and a fresh parse of the same log line yields
		// "" for those fields, so NULL must compare as "".
		query := "SELECT source, ts, kind, COALESCE(src_ip,''), COALESCE(session_id,''), COALESCE(username,''), COALESCE(command,''), COALESCE(src_port,0), COALESCE(raw,'') FROM events WHERE ts IN (" +
			strings.Join(placeholders, ",") + ")"
		if err := s.QueryRows(query, args, func(scan func(...any) error) error {
			var src string
			var id EventIdentity
			if err := scan(&src, &id.TS, &id.Kind, &id.SrcIP, &id.SessionID, &id.Username, &id.Command, &id.SrcPort, &id.Raw); err != nil {
				return err
			}
			if src != want {
				return nil
			}
			ts, err := time.Parse(time.RFC3339Nano, id.TS)
			if err != nil {
				return fmt.Errorf("event dedup: invalid stored timestamp")
			}
			id.TS = CanonicalEventTime(ts)
			if source == models.SourceJournal {
				id.SessionID, id.Command = "", ""
			} else {
				id.SrcPort, id.Raw = 0, ""
			}
			fn(id)
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
