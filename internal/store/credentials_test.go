package store

import (
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// TestCredentialCountsAreExactNotSampled is the point of this file. The wordlist
// used to fold a CAPPED window of events in memory, so on a busy deployment it
// silently described a sample: measured at 200k of 533,647 events, counts ran
// ~60% low and 47% of distinct usernames were missing entirely. Counting in SQL
// removes the cap from the equation, so these must be exact.
func TestCredentialCountsAreExactNotSampled(t *testing.T) {
	st := newTestStore(t, "creds.db")
	now := time.Now().UTC()

	// 250 attempts for root, 40 for admin, plus a long tail. If anything samples,
	// the tail is what disappears first.
	var evs []*models.Event
	add := func(u, p string, n int, age time.Duration) {
		for i := 0; i < n; i++ {
			evs = append(evs, &models.Event{
				TS: now.Add(-age - time.Duration(i)*time.Second), Source: models.SourceCowrie,
				Kind: models.KindFailedPass, SrcIP: "1.2.3.4", Username: u, Password: p,
				ActorID: "a1",
			})
		}
	}
	add("root", "123456", 250, time.Hour)
	add("admin", "admin", 40, 2*time.Hour)
	for i := 0; i < 60; i++ {
		add("tail"+string(rune('a'+i%26))+string(rune('a'+i/26)), "pw", 1, 3*time.Hour)
	}
	// Non-credential events with a username must NOT be counted.
	for i := 0; i < 500; i++ {
		evs = append(evs, &models.Event{
			TS: now.Add(-time.Hour), Source: models.SourceCowrie, Kind: "command",
			SrcIP: "1.2.3.4", Username: "root", ActorID: "a1",
		})
	}
	// Outside the window.
	add("ancient", "x", 99, 40*24*time.Hour)

	for _, e := range evs {
		if err := st.InsertEvent(e); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	users, err := st.TopUsernamesSince(now.Add(-24*time.Hour), 0)
	if err != nil {
		t.Fatalf("TopUsernamesSince: %v", err)
	}
	if len(users) == 0 {
		t.Fatal("no usernames returned")
	}
	if users[0].Username != "root" || users[0].Count != 250 {
		t.Errorf("top = %s/%d, want root/250 (command events with a username must not "+
			"be counted as credential attempts)", users[0].Username, users[0].Count)
	}
	// 62 distinct: root, admin, and 60 tail values. The tail is the coverage the
	// sampled implementation lost.
	if len(users) != 62 {
		t.Errorf("distinct usernames = %d, want 62 - the long tail is exactly what a "+
			"capped in-memory fold drops", len(users))
	}
	for _, u := range users {
		if u.Username == "ancient" {
			t.Error("counted a username from outside the window")
		}
	}

	n, err := st.DistinctCredentialCount("username", now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("DistinctCredentialCount: %v", err)
	}
	if n != len(users) {
		t.Errorf("DistinctCredentialCount = %d but the ranked list has %d", n, len(users))
	}
}

// TestCredentialCountsRankAndLimit pins ordering and that a limit truncates the
// TAIL rather than reordering.
func TestCredentialCountsRankAndLimit(t *testing.T) {
	st := newTestStore(t, "creds2.db")
	now := time.Now().UTC()
	for u, n := range map[string]int{"root": 30, "admin": 20, "user": 10} {
		for i := 0; i < n; i++ {
			if err := st.InsertEvent(&models.Event{
				TS: now.Add(-time.Duration(i) * time.Minute), Source: models.SourceCowrie,
				Kind: models.KindInvalidUser, SrcIP: "9.9.9.9", Username: u, Password: "p",
				ActorID: "a2",
			}); err != nil {
				t.Fatalf("insert: %v", err)
			}
		}
	}
	all, err := st.TopUsernamesSince(now.Add(-24*time.Hour), 0)
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	want := []string{"root", "admin", "user"}
	for i, w := range want {
		if all[i].Username != w {
			t.Errorf("rank %d = %s, want %s", i, all[i].Username, w)
		}
	}
	two, err := st.TopUsernamesSince(now.Add(-24*time.Hour), 2)
	if err != nil {
		t.Fatalf("limited: %v", err)
	}
	if len(two) != 2 || two[0].Username != "root" || two[1].Username != "admin" {
		t.Errorf("limit=2 gave %v, want the two highest in order", two)
	}
}

// TestCombosPairUsernameAndPassword covers the combo list, which must key on the
// PAIR: the same password under two usernames is two entries.
func TestCombosPairUsernameAndPassword(t *testing.T) {
	st := newTestStore(t, "creds3.db")
	now := time.Now().UTC()
	mk := func(u, p string, n int) {
		for i := 0; i < n; i++ {
			if err := st.InsertEvent(&models.Event{
				TS: now.Add(-time.Duration(i) * time.Minute), Source: models.SourceCowrie,
				Kind: models.KindFailedPass, SrcIP: "8.8.8.8", Username: u, Password: p,
				ActorID: "a3",
			}); err != nil {
				t.Fatalf("insert: %v", err)
			}
		}
	}
	mk("root", "toor", 5)
	mk("admin", "toor", 3)
	combos, err := st.TopCombosSince(now.Add(-24*time.Hour), 0)
	if err != nil {
		t.Fatalf("combos: %v", err)
	}
	if len(combos) != 2 {
		t.Fatalf("got %d combos, want 2 (one shared password under two users)", len(combos))
	}
	if combos[0].Username != "root" || combos[0].Password != "toor" || combos[0].Count != 5 {
		t.Errorf("top combo = %+v, want root:toor x5", combos[0])
	}
}
