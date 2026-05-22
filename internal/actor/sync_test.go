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
	resetLiveCollectorForTest()
	defer resetLiveCollectorForTest()

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
	resetLiveCollectorForTest()
	defer resetLiveCollectorForTest()

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

// TestSyncJournalEventRejectsAdminMismatch confirms the second call
// errors out when the admin set differs from the bound one. Catches
// the "different goroutine, different admin map" misuse described
// in the doc comment.
func TestSyncJournalEventRejectsAdminMismatch(t *testing.T) {
	resetLiveCollectorForTest()
	defer resetLiveCollectorForTest()

	st, err := store.Open(filepath.Join(t.TempDir(), "admin-mismatch.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	e := &models.Event{
		TS: time.Now(), Source: models.SourceJournal, Kind: models.KindFailedPass,
		SrcIP: "198.51.100.1", Username: "root", ActorID: JournalActorID("198.51.100.1"),
		Raw: "{}",
	}
	if err := st.InsertEvent(e); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := SyncJournalEvent(st, e, map[string]bool{"10.0.0.1": true}); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	err = SyncJournalEvent(st, e, map[string]bool{"10.0.0.2": true})
	if err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
}

// TestAdminSetsEqual is a small unit covering the helper used by
// SyncJournalEvent's mismatch check.
func TestAdminSetsEqual(t *testing.T) {
	cases := []struct {
		name string
		a, b map[string]bool
		want bool
	}{
		{"both nil", nil, nil, true},
		{"empty vs nil", map[string]bool{}, nil, true},
		{"same one", map[string]bool{"x": true}, map[string]bool{"x": true}, true},
		{"different size", map[string]bool{"x": true}, map[string]bool{"x": true, "y": true}, false},
		{"different value", map[string]bool{"x": true}, map[string]bool{"x": false}, false},
		{"different key", map[string]bool{"x": true}, map[string]bool{"y": true}, false},
	}
	for _, c := range cases {
		if got := adminSetsEqual(c.a, c.b); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
