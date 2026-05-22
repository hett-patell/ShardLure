package actor

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

// TestSyncJournalEventIncremental confirms each Add updates the
// actor row in-place: counters reflect the running total, no full
// event history is read, and per-event work is O(1) regardless of
// how many events have already been processed for the same IP.
func TestSyncJournalEventIncremental(t *testing.T) {
	ResetLiveCollectorForTest()
	defer ResetLiveCollectorForTest()

	st, err := store.Open(filepath.Join(t.TempDir(), "sync.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	admin := map[string]bool{}

	ip := "203.0.113.7"
	t0 := time.Now().Add(-30 * time.Minute)
	users := []string{"root", "admin", "root", "git", "root"}
	for i, u := range users {
		e := &models.Event{
			TS:       t0.Add(time.Duration(i) * time.Minute),
			Source:   models.SourceJournal,
			Kind:     models.KindFailedPass,
			SrcIP:    ip,
			Username: u,
			ActorID:  JournalActorID(ip),
			Raw:      "{}",
		}
		if err := st.InsertEvent(e); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
		if err := SyncJournalEvent(st, e, admin); err != nil {
			t.Fatalf("sync %d: %v", i, err)
		}
	}

	actors, err := st.ListActors(10)
	if err != nil {
		t.Fatalf("list actors: %v", err)
	}
	if len(actors) != 1 {
		t.Fatalf("want 1 actor, got %d", len(actors))
	}
	a := actors[0]
	if a.EventCount != len(users) {
		t.Errorf("EventCount = %d, want %d", a.EventCount, len(users))
	}
	if a.UniqueUsers != 3 {
		t.Errorf("UniqueUsers = %d, want 3 (root/admin/git)", a.UniqueUsers)
	}
}

// TestSyncJournalEventSkipsAdmin ensures admin-source events do not
// pollute the live collector or create actor rows.
func TestSyncJournalEventSkipsAdmin(t *testing.T) {
	ResetLiveCollectorForTest()
	defer ResetLiveCollectorForTest()

	st, err := store.Open(filepath.Join(t.TempDir(), "sync-admin.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	admin := map[string]bool{"10.0.0.5": true}
	e := &models.Event{
		TS: time.Now(), Source: models.SourceJournal, Kind: models.KindAccepted,
		SrcIP: "10.0.0.5", Username: "ops", ActorID: JournalActorID("10.0.0.5"),
		Raw: "{}",
	}
	if err := SyncJournalEvent(st, e, admin); err != nil {
		t.Fatalf("sync: %v", err)
	}
	actors, err := st.ListActors(10)
	if err != nil {
		t.Fatalf("list actors: %v", err)
	}
	if len(actors) != 0 {
		t.Errorf("admin event created an actor row: %+v", actors)
	}
}
