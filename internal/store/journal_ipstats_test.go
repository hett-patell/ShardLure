package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestLoadJournalIPStatsIsActorQualified(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "journal-ipstats.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	ip := "198.51.100.24"
	journalID := "journal:" + ip
	journalFirst := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	journalLast := journalFirst.Add(5 * time.Minute)
	cowrieFirst := journalLast.Add(time.Hour)
	cowrieLast := cowrieFirst.Add(10 * time.Minute)

	actors := []*models.AggregatedActor{
		{
			Actor: &models.Actor{
				ID: journalID, Source: models.SourceJournal, PrimaryIP: ip,
				FirstSeen: journalFirst, LastSeen: journalLast, EventCount: 7, UniqueUsers: 2,
			},
			IPs:   map[string]models.IPStat{ip: {Count: 7, First: journalFirst, Last: journalLast}},
			Users: map[string]int{"root": 4, "admin": 3},
		},
		{
			Actor: &models.Actor{
				ID: "cowrie:shared-ip", Source: models.SourceCowrie, PrimaryIP: ip,
				FirstSeen: cowrieFirst, LastSeen: cowrieLast, EventCount: 40, UniqueUsers: 1,
			},
			IPs:   map[string]models.IPStat{ip: {Count: 40, First: cowrieFirst, Last: cowrieLast}},
			Users: map[string]int{"cowrie-user": 40},
		},
	}
	if err := st.AppendEventsAndUpsertActorsAgg(nil, actors); err != nil {
		t.Fatalf("seed actors: %v", err)
	}

	got, err := st.LoadJournalIPStats(journalID, ip)
	if err != nil {
		t.Fatalf("LoadJournalIPStats: %v", err)
	}
	if got.Count != 7 {
		t.Errorf("Count = %d, want journal count 7", got.Count)
	}
	if !got.First.Equal(journalFirst) {
		t.Errorf("First = %s, want journal first %s", got.First, journalFirst)
	}
	if !got.Last.Equal(journalLast) {
		t.Errorf("Last = %s, want journal last %s", got.Last, journalLast)
	}
	if len(got.UserCounts) != 2 || got.UserCounts["root"] != 4 || got.UserCounts["admin"] != 3 {
		t.Errorf("UserCounts = %#v, want journal users map[admin:3 root:4]", got.UserCounts)
	}
}
