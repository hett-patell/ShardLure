package actor

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

// TestLiveCollectorEvictsByLRU drives more distinct IPs through the
// bounded collector than its cap and asserts only the most-recent
// maxIPs entries remain resident. The DB row count is unbounded; the
// in-memory map is not.
func TestLiveCollectorEvictsByLRU(t *testing.T) {
	resetLiveCollectorForTest()
	defer resetLiveCollectorForTest()

	// Shrink the cap for the duration of this test so we don't have
	// to drive 4k+ IPs through it.
	oldMax := liveMaxIPs
	liveMaxIPs = 8
	defer func() { liveMaxIPs = oldMax }()

	st, err := store.Open(filepath.Join(t.TempDir(), "evict.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	admin := AdminSet(nil)

	// 32 distinct IPs > cap of 8.
	for i := 0; i < 32; i++ {
		ip := "203.0.113." + strconv.Itoa(i+1)
		e := &models.Event{
			TS:       time.Now().Add(time.Duration(i) * time.Second),
			Source:   models.SourceJournal,
			Kind:     models.KindFailedPass,
			SrcIP:    ip,
			Username: "root",
			ActorID:  JournalActorID(ip),
			Raw:      "{}",
		}
		if _, err := SyncJournalEvent(st, e, admin); err != nil {
			t.Fatalf("sync %d: %v", i, err)
		}
	}

	if got := len(liveCollector.byIP); got != 8 {
		t.Errorf("byIP size = %d, want 8 (capped by liveMaxIPs)", got)
	}
	if got := liveCollector.lru.Len(); got != 8 {
		t.Errorf("lru len = %d, want 8", got)
	}
	// DB rows should reflect all 32 IPs — the eviction only drops
	// in-memory state, never the persisted row.
	actors, err := st.ListActors(64)
	if err != nil {
		t.Fatalf("list actors: %v", err)
	}
	if len(actors) != 32 {
		t.Errorf("DB has %d actors, want 32 (eviction must not drop DB rows)", len(actors))
	}
}

func TestLiveCollectorInvalidateRemovesExactEntry(t *testing.T) {
	c := newLiveJournalCollector(AdminSet(nil))
	base := time.Date(2026, 7, 22, 9, 0, 0, 0, time.UTC)
	event := func(ip string, ts time.Time) *models.Event {
		return &models.Event{
			TS: ts, Source: models.SourceJournal, Kind: models.KindFailedPass,
			SrcIP: ip, Username: "root", ActorID: JournalActorID(ip), Raw: "{}",
		}
	}

	const keepIP = "203.0.113.10"
	const invalidateIP = "203.0.113.11"
	c.hydrate(invalidateIP, store.JournalIPStats{})
	c.addAndFinalize(event(invalidateIP, base))
	c.hydrate(keepIP, store.JournalIPStats{})
	c.addAndFinalize(event(keepIP, base.Add(time.Second)))
	c.addAndFinalize(event(invalidateIP, base.Add(2*time.Second)))

	if tail := c.lru.Back(); tail == nil || tail.Value != keepIP {
		t.Fatalf("LRU tail = %v, want untouched IP %q", tail, keepIP)
	}
	c.invalidate(invalidateIP)

	if c.has(invalidateIP) {
		t.Fatalf("invalidated IP %q remains in collector", invalidateIP)
	}
	if !c.has(keepIP) {
		t.Fatalf("invalidate removed LRU tail %q instead of target", keepIP)
	}
	if got := c.lru.Len(); got != 1 {
		t.Fatalf("LRU length = %d, want 1", got)
	}
	if front := c.lru.Front(); front == nil || front.Value != keepIP {
		t.Fatalf("remaining LRU entry = %v, want %q", front, keepIP)
	}
}

// TestLiveCollectorHydratesEvictedIP confirms that when an evicted
// IP returns, its persisted counters are loaded so the next atomic append
// writes the running total rather than a smaller post-evict count.
func TestLiveCollectorHydratesEvictedIP(t *testing.T) {
	resetLiveCollectorForTest()
	defer resetLiveCollectorForTest()

	oldMax := liveMaxIPs
	liveMaxIPs = 2
	defer func() { liveMaxIPs = oldMax }()

	st, err := store.Open(filepath.Join(t.TempDir(), "hydrate.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	admin := AdminSet(nil)

	// Burn 5 events into target IP, then push 4 different IPs to
	// guarantee eviction (cap is 2).
	target := "198.51.100.10"
	for i := 0; i < 5; i++ {
		e := &models.Event{
			TS:       time.Now().Add(time.Duration(i) * time.Second),
			Source:   models.SourceJournal,
			Kind:     models.KindFailedPass,
			SrcIP:    target,
			Username: "root",
			ActorID:  JournalActorID(target),
			Raw:      "{}",
		}
		if _, err := SyncJournalEvent(st, e, admin); err != nil {
			t.Fatalf("sync target #%d: %v", i, err)
		}
	}
	for i := 0; i < 4; i++ {
		ip := "203.0.113." + strconv.Itoa(i+1)
		e := &models.Event{
			TS:       time.Now().Add(time.Duration(10+i) * time.Second),
			Source:   models.SourceJournal,
			Kind:     models.KindFailedPass,
			SrcIP:    ip,
			Username: "admin",
			ActorID:  JournalActorID(ip),
			Raw:      "{}",
		}
		if _, err := SyncJournalEvent(st, e, admin); err != nil {
			t.Fatalf("sync filler #%d: %v", i, err)
		}
	}

	// Confirm target was evicted.
	if liveCollector.has(target) {
		t.Fatal("target was not evicted; cap=2 should have pushed it out")
	}

	// Send one more event for target. After this call the persisted
	// count must be 6 (5 prior + 1 new), proving hydration loaded
	// the prior count instead of restarting at 1.
	e := &models.Event{
		TS:       time.Now().Add(time.Hour),
		Source:   models.SourceJournal,
		Kind:     models.KindFailedPass,
		SrcIP:    target,
		Username: "root",
		ActorID:  JournalActorID(target),
		Raw:      "{}",
	}
	if _, err := SyncJournalEvent(st, e, admin); err != nil {
		t.Fatalf("sync post-evict: %v", err)
	}

	a, err := st.GetActorByPrimaryIP(target)
	if err != nil {
		t.Fatalf("GetActorByPrimaryIP: %v", err)
	}
	if a.EventCount != 6 {
		t.Errorf("post-evict EventCount = %d, want 6 (hydration must preserve running total)", a.EventCount)
	}
}

func TestLiveCollectorHydratesJournalRowWhenCowrieIsNewer(t *testing.T) {
	resetLiveCollectorForTest()
	defer resetLiveCollectorForTest()

	st, err := store.Open(filepath.Join(t.TempDir(), "source-qualified-hydration.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	ip := "198.51.100.44"
	journalID := JournalActorID(ip)
	journalFirst := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	journalLast := journalFirst.Add(5 * time.Minute)
	cowrieFirst := journalLast.Add(time.Hour)
	cowrieLast := cowrieFirst.Add(10 * time.Minute)

	seed := []*models.AggregatedActor{
		{
			Actor: &models.Actor{
				ID: journalID, Source: models.SourceJournal, PrimaryIP: ip,
				FirstSeen: journalFirst, LastSeen: journalLast, EventCount: 5, UniqueUsers: 1,
			},
			IPs:   map[string]models.IPStat{ip: {Count: 5, First: journalFirst, Last: journalLast}},
			Users: map[string]int{"root": 5},
		},
		{
			Actor: &models.Actor{
				ID: "cowrie:newer-shared-ip", Source: models.SourceCowrie, PrimaryIP: ip,
				FirstSeen: cowrieFirst, LastSeen: cowrieLast, EventCount: 40, UniqueUsers: 1,
			},
			IPs:   map[string]models.IPStat{ip: {Count: 40, First: cowrieFirst, Last: cowrieLast}},
			Users: map[string]int{"cowrie-user": 40},
		},
	}
	if err := st.AppendEventsAndUpsertActorsAgg(nil, seed); err != nil {
		t.Fatalf("seed actors: %v", err)
	}

	e := &models.Event{
		TS:       cowrieLast.Add(time.Hour),
		Source:   models.SourceJournal,
		Kind:     models.KindFailedPass,
		SrcIP:    ip,
		Username: "root",
		ActorID:  journalID,
		Raw:      "{}",
	}
	if _, err := SyncJournalEvent(st, e, AdminSet(nil)); err != nil {
		t.Fatalf("sync journal event: %v", err)
	}

	got, err := st.GetActor(journalID)
	if err != nil {
		t.Fatalf("GetActor(%q): %v", journalID, err)
	}
	if got.EventCount != 6 {
		t.Errorf("EventCount = %d, want journal count 5 + new event = 6", got.EventCount)
	}
	if !got.FirstSeen.Equal(journalFirst) {
		t.Errorf("FirstSeen = %s, want journal first %s", got.FirstSeen, journalFirst)
	}
	if got.UniqueUsers != 1 {
		t.Errorf("UniqueUsers = %d, want journal user set only", got.UniqueUsers)
	}

	users, err := st.ActorUsers(journalID)
	if err != nil {
		t.Fatalf("ActorUsers(%q): %v", journalID, err)
	}
	if len(users) != 1 || users[0].Username != "root" || users[0].Count != 6 {
		t.Errorf("journal actor users = %#v, want root count 6", users)
	}
}

// TestLiveCollectorPerIPUserCap caps the per-IP username sub-map to
// keep a single noisy scanner from probing a million distinct names
// from one IP and using all of process memory.
func TestLiveCollectorPerIPUserCap(t *testing.T) {
	resetLiveCollectorForTest()
	defer resetLiveCollectorForTest()

	oldMax := liveMaxUsersPerIP
	liveMaxUsersPerIP = 4
	defer func() { liveMaxUsersPerIP = oldMax }()

	st, err := store.Open(filepath.Join(t.TempDir(), "user-cap.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	admin := AdminSet(nil)

	ip := "192.0.2.99"
	// 20 distinct usernames > cap of 4.
	for i := 0; i < 20; i++ {
		u := "user" + strconv.Itoa(i)
		e := &models.Event{
			TS:       time.Now().Add(time.Duration(i) * time.Second),
			Source:   models.SourceJournal,
			Kind:     models.KindFailedPass,
			SrcIP:    ip,
			Username: u,
			ActorID:  JournalActorID(ip),
			Raw:      "{}",
		}
		if _, err := SyncJournalEvent(st, e, admin); err != nil {
			t.Fatalf("sync: %v", err)
		}
	}

	ent := liveCollector.byIP[ip]
	if ent == nil {
		t.Fatal("entry missing")
	}
	// Distinct real keys must be <= cap.
	realKeys := 0
	for k := range ent.stats.Users {
		if k != liveUserOverflowKey {
			realKeys++
		}
	}
	if realKeys > liveMaxUsersPerIP {
		t.Errorf("real-key count %d exceeds cap %d", realKeys, liveMaxUsersPerIP)
	}
	if _, ok := ent.stats.Users[liveUserOverflowKey]; !ok {
		t.Error("overflow bucket missing; expected entries past the cap to roll into _overflow_")
	}
	// Total events still 20 — counters must not be lost just because
	// the map is full.
	if ent.stats.Count != 20 {
		t.Errorf("Count = %d, want 20", ent.stats.Count)
	}
}

// TestCapUsersMap exercises the hydration overflow logic in isolation.
func TestCapUsersMap(t *testing.T) {
	in := map[string]int{"a": 10, "b": 8, "c": 5, "d": 3, "e": 1, "f": 1}
	out := capUsersMap(in, 3)
	for _, want := range []string{"a", "b", "c"} {
		if out[want] != in[want] {
			t.Errorf("top key %q dropped or mis-counted: got %d want %d", want, out[want], in[want])
		}
	}
	if out[liveUserOverflowKey] != 3+1+1 {
		t.Errorf("overflow = %d, want 5 (d=3 + e=1 + f=1)", out[liveUserOverflowKey])
	}
	if len(out) != 4 { // 3 real + overflow
		t.Errorf("len = %d, want 4", len(out))
	}
}
