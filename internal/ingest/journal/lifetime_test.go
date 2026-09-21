package journal

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func TestJournalAppendPreservesLifetimeBeyondRetention(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "lifetime.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	const id = "journal:198.51.100.10"
	// Lifetime counters and durable username evidence intentionally exceed the
	// retained events. Appending a fresh line must not rebuild them as one event.
	a := &models.Actor{ID: id, Source: models.SourceJournal, PrimaryIP: "198.51.100.10", EventCount: 100, UniqueUsers: 1, FirstSeen: base, LastSeen: base, Campaigns: "operator-campaign", Notes: "operator note"}
	if err := s.AppendEventsAndUpsertActorsAgg(nil, []*models.AggregatedActor{{Actor: a, Users: map[string]int{"historic": 100}, IPs: map[string]models.IPStat{a.PrimaryIP: {Count: 100, First: base, Last: base}}}}); err != nil {
		t.Fatal(err)
	}
	e := &models.Event{TS: base.Add(24 * time.Hour), Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: a.PrimaryIP, Username: "fresh", Raw: "inert fresh journal event"}
	for i := 0; i < 2; i++ {
		r, err := persistJournalEvents(s, []*models.Event{e}, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 && r.Events != 1 || i == 1 && r.Duplicates != 1 {
			t.Fatalf("pass %d result=%+v", i, r)
		}
		got, err := s.GetActor(id)
		if err != nil {
			t.Fatal(err)
		}
		if got.EventCount != 101 || got.UniqueUsers != 2 || !got.FirstSeen.Equal(base) {
			t.Errorf("lifetime counters replaced: %+v", got)
		}
		if got.Campaigns != "operator-campaign" || got.Notes != "operator note" {
			t.Errorf("annotations replaced: %+v", got)
		}
		state, err := s.LoadJournalIPStats(id, a.PrimaryIP)
		if err != nil {
			t.Fatal(err)
		}
		if state.Count != 101 || state.UserCounts["historic"] != 100 || state.UserCounts["fresh"] != 1 {
			t.Errorf("durable lifetime corpus replaced: %+v", state)
		}
	}
}
