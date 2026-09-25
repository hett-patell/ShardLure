package actor

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func TestJournalOverflowPersistsExactUsernameCounts(t *testing.T) {
	resetLiveCollectorForTest()
	defer resetLiveCollectorForTest()
	previous := liveMaxUsersPerIP
	liveMaxUsersPerIP = 2
	defer func() { liveMaxUsersPerIP = previous }()
	s, err := store.Open(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	admin := AdminSet(nil)
	now := time.Now()
	for i, user := range []string{"root", "admin", "u1", "u2", "u1", "u3"} {
		if i == 4 {
			resetLiveCollectorForTest()
		}
		e := &models.Event{TS: now.Add(time.Duration(i) * time.Second), Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: "8.8.8.8", Username: user, Raw: fmt.Sprint(i)}
		if _, err := SyncJournalEvent(s, e, admin); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := s.LoadJournalIPStats(JournalActorID("8.8.8.8"), "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	for user, want := range map[string]int{"root": 1, "admin": 1, "u1": 2, "u2": 1, "u3": 1} {
		if got := stats.UserCounts[user]; got != want {
			t.Errorf("%s count=%d want=%d", user, got, want)
		}
	}
	rows, err := s.ListActors(10)
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].UniqueUsers != 5 {
		t.Errorf("unique users=%d want=5", rows[0].UniqueUsers)
	}
}
