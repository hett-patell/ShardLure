package actor

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

// TestSyncJournalEventIncremental confirms each sync updates the
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
	admin := AdminSet(nil)

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
		if _, err := SyncJournalEvent(st, e, admin); err != nil {
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

func TestSyncJournalEventNilIsNoop(t *testing.T) {
	resetLiveCollectorForTest()
	defer resetLiveCollectorForTest()

	inserted, err := SyncJournalEvent(nil, nil, AdminSet(nil))
	if err != nil {
		t.Fatalf("nil sync: %v", err)
	}
	if inserted {
		t.Fatal("nil sync reported inserted")
	}
	if liveCollector != nil {
		t.Error("nil sync initialized the live collector")
	}
}

func TestSyncJournalEventEmptyIPPersistsWithoutActor(t *testing.T) {
	resetLiveCollectorForTest()
	defer resetLiveCollectorForTest()

	st, err := store.Open(filepath.Join(t.TempDir(), "sync-empty-ip.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	e := &models.Event{
		TS:       time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC),
		Source:   models.SourceJournal,
		Kind:     models.KindFailedPass,
		Username: "root",
		ActorID:  "must-be-cleared",
		Raw:      "journal event without a source IP",
	}

	inserted, err := SyncJournalEvent(st, e, AdminSet(nil))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !inserted {
		t.Fatal("empty-IP event reported duplicate")
	}
	if e.ActorID != "" {
		t.Fatalf("empty-IP event ActorID = %q, want blank", e.ActorID)
	}
	events, err := st.RecentEvents(10)
	if err != nil {
		t.Fatalf("recent events: %v", err)
	}
	if len(events) != 1 || events[0].ActorID != "" {
		t.Fatalf("stored empty-IP events = %#v, want one event with blank ActorID", events)
	}
	actors, err := st.ActorCount()
	if err != nil {
		t.Fatalf("actor count: %v", err)
	}
	if actors != 0 {
		t.Fatalf("actor count = %d, want 0", actors)
	}
	if liveCollector != nil {
		t.Error("empty-IP event initialized the live collector")
	}
}

func TestSyncJournalEventDuplicateDoesNotAdvanceCollector(t *testing.T) {
	resetLiveCollectorForTest()
	defer resetLiveCollectorForTest()

	st, err := store.Open(filepath.Join(t.TempDir(), "sync-duplicate.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	const ip = "203.0.113.44"
	e := &models.Event{
		TS:       time.Date(2026, 7, 22, 8, 9, 10, 123456789, time.UTC),
		Source:   models.SourceJournal,
		Kind:     models.KindFailedPass,
		SrcIP:    ip,
		SrcPort:  49200,
		Username: "root",
		Raw:      "Jul 22 08:09:10 host sshd[123]: Failed password for root from 203.0.113.44 port 49200 ssh2",
	}
	replay := *e
	distinct := *e
	distinct.Raw += " [distinct]"

	inserted, err := SyncJournalEvent(st, e, AdminSet(nil))
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if !inserted {
		t.Fatal("first sync reported duplicate")
	}
	if e.ID == 0 {
		t.Fatal("first sync did not publish the generated event ID")
	}

	replayID := replay.ID
	inserted, err = SyncJournalEvent(st, &replay, AdminSet(nil))
	if err != nil {
		t.Fatalf("replay sync: %v", err)
	}
	if inserted {
		t.Fatal("exact replay was inserted")
	}
	if replay.ID != replayID {
		t.Fatalf("replay ID = %d, want unchanged %d", replay.ID, replayID)
	}

	inserted, err = SyncJournalEvent(st, &distinct, AdminSet(nil))
	if err != nil {
		t.Fatalf("distinct sync: %v", err)
	}
	if !inserted {
		t.Fatal("distinct event reported duplicate")
	}

	events, err := st.EventCount()
	if err != nil {
		t.Fatalf("event count: %v", err)
	}
	if events != 2 {
		t.Fatalf("event count = %d, want 2", events)
	}

	actorID := JournalActorID(ip)
	a, err := st.GetActor(actorID)
	if err != nil {
		t.Fatalf("get actor: %v", err)
	}
	if a.EventCount != 2 {
		t.Errorf("actor event count = %d, want 2", a.EventCount)
	}
	stats, err := st.LoadJournalIPStats(actorID, ip)
	if err != nil {
		t.Fatalf("load journal IP stats: %v", err)
	}
	if stats.Count != 2 {
		t.Errorf("actor IP count = %d, want 2", stats.Count)
	}
	if got := stats.UserCounts["root"]; got != 2 {
		t.Errorf("actor user count = %d, want 2", got)
	}
}

func TestSyncJournalEventErrorDoesNotAdvanceCollector(t *testing.T) {
	resetLiveCollectorForTest()
	defer resetLiveCollectorForTest()

	dbPath := filepath.Join(t.TempDir(), "sync-error.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if st != nil {
			_ = st.Close()
		}
	})
	admin := AdminSet(nil)

	const ip = "198.51.100.73"
	first := &models.Event{
		TS:       time.Date(2026, 7, 22, 9, 10, 11, 0, time.UTC),
		Source:   models.SourceJournal,
		Kind:     models.KindFailedPass,
		SrcIP:    ip,
		SrcPort:  51321,
		Username: "root",
		Raw:      "first distinct journal event",
	}
	second := *first
	second.TS = first.TS.Add(time.Second)
	second.Raw = "second distinct journal event"
	third := *first
	third.TS = first.TS.Add(2 * time.Second)
	third.Raw = "third distinct journal event"
	inserted, err := SyncJournalEvent(st, first, admin)
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if !inserted {
		t.Fatal("first sync reported duplicate")
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	secondID := second.ID
	inserted, err = SyncJournalEvent(st, &second, admin)
	if err == nil {
		t.Fatal("sync against closed store returned nil error")
	}
	if inserted {
		t.Fatal("sync against closed store reported inserted")
	}
	if second.ID != secondID {
		t.Fatalf("failed event ID = %d, want unchanged %d", second.ID, secondID)
	}

	st, err = store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	inserted, err = SyncJournalEvent(st, &third, admin)
	if err != nil {
		t.Fatalf("third sync: %v", err)
	}
	if !inserted {
		t.Fatal("third sync reported duplicate")
	}

	events, err := st.EventCount()
	if err != nil {
		t.Fatalf("event count: %v", err)
	}
	if events != 2 {
		t.Fatalf("event count = %d, want 2", events)
	}
	actorID := JournalActorID(ip)
	a, err := st.GetActor(actorID)
	if err != nil {
		t.Fatalf("get actor: %v", err)
	}
	if a.EventCount != 2 {
		t.Errorf("actor event count = %d, want 2", a.EventCount)
	}
	stats, err := st.LoadJournalIPStats(actorID, ip)
	if err != nil {
		t.Fatalf("load journal IP stats: %v", err)
	}
	if stats.Count != 2 {
		t.Errorf("actor IP count = %d, want 2", stats.Count)
	}
	if got := stats.UserCounts["root"]; got != 2 {
		t.Errorf("actor user count = %d, want 2", got)
	}
}

func TestSyncJournalEventConcurrentRejectedWriteDoesNotLeak(t *testing.T) {
	resetLiveCollectorForTest()
	defer resetLiveCollectorForTest()

	st, err := store.Open(filepath.Join(t.TempDir(), "sync-concurrent-rejection.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	admin := AdminSet(nil)

	const ip = "192.0.2.81"
	seed := &models.Event{
		TS:       time.Date(2026, 7, 22, 10, 11, 12, 0, time.UTC),
		Source:   models.SourceJournal,
		Kind:     models.KindFailedPass,
		SrcIP:    ip,
		SrcPort:  55221,
		Username: "root",
		Raw:      "seed journal event",
	}
	duplicate := *seed
	distinct := *seed
	distinct.TS = seed.TS.Add(time.Second)
	distinct.Raw = "distinct journal event"
	inserted, err := SyncJournalEvent(st, seed, admin)
	if err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	if !inserted {
		t.Fatal("seed sync reported duplicate")
	}

	liveCollectorMu.Lock()
	c := liveCollector
	liveCollectorMu.Unlock()
	if c == nil {
		t.Fatal("seed sync did not initialize collector")
	}

	writesHeld := make(chan struct{})
	releaseWrites := make(chan struct{})
	blockDone := make(chan error, 1)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseWrites) }) }
	t.Cleanup(release)
	go func() {
		blockDone <- st.WithTx(func(_ *sql.Tx) error {
			close(writesHeld)
			<-releaseWrites
			return nil
		})
	}()
	select {
	case <-writesHeld:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out acquiring store write blocker")
	}

	type syncResult struct {
		inserted bool
		err      error
	}
	duplicateDone := make(chan syncResult, 1)
	go func() {
		got, syncErr := SyncJournalEvent(st, &duplicate, admin)
		duplicateDone <- syncResult{inserted: got, err: syncErr}
	}()
	if !waitForLiveJournalCount(c, ip, 2, 2*time.Second) {
		t.Fatal("duplicate did not mutate collector before blocked append")
	}

	distinctStarted := make(chan struct{})
	distinctDone := make(chan syncResult, 1)
	go func() {
		close(distinctStarted)
		got, syncErr := SyncJournalEvent(st, &distinct, admin)
		distinctDone <- syncResult{inserted: got, err: syncErr}
	}()
	<-distinctStarted
	// Without operation-level serialization the distinct call reaches count 3
	// while both appends are blocked. With serialization it waits behind the
	// duplicate, so this bounded condition expires and the write can be released.
	_ = waitForLiveJournalCount(c, ip, 3, 500*time.Millisecond)
	release()

	select {
	case err := <-blockDone:
		if err != nil {
			t.Fatalf("write blocker transaction: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out releasing store write blocker")
	}
	var duplicateResult syncResult
	select {
	case duplicateResult = <-duplicateDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for duplicate sync")
	}
	if duplicateResult.err != nil {
		t.Fatalf("duplicate sync: %v", duplicateResult.err)
	}
	if duplicateResult.inserted {
		t.Fatal("duplicate sync reported inserted")
	}
	var distinctResult syncResult
	select {
	case distinctResult = <-distinctDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for distinct sync")
	}
	if distinctResult.err != nil {
		t.Fatalf("distinct sync: %v", distinctResult.err)
	}
	if !distinctResult.inserted {
		t.Fatal("distinct sync reported duplicate")
	}

	events, err := st.EventCount()
	if err != nil {
		t.Fatalf("event count: %v", err)
	}
	if events != 2 {
		t.Fatalf("event count = %d, want 2", events)
	}
	actorID := JournalActorID(ip)
	a, err := st.GetActor(actorID)
	if err != nil {
		t.Fatalf("get actor: %v", err)
	}
	if a.EventCount != 2 {
		t.Errorf("actor event count = %d, want 2", a.EventCount)
	}
	stats, err := st.LoadJournalIPStats(actorID, ip)
	if err != nil {
		t.Fatalf("load journal IP stats: %v", err)
	}
	if stats.Count != 2 {
		t.Errorf("actor IP count = %d, want 2", stats.Count)
	}
	if got := stats.UserCounts["root"]; got != 2 {
		t.Errorf("actor user count = %d, want 2", got)
	}

	c.mu.Lock()
	ent := c.byIP[ip]
	lruLen := c.lru.Len()
	residentCount := 0
	if ent != nil {
		residentCount = ent.stats.Count
	}
	c.mu.Unlock()
	if ent == nil {
		t.Fatal("collector entry missing after concurrent syncs")
	}
	if residentCount != 2 {
		t.Errorf("collector count = %d, want 2", residentCount)
	}
	if lruLen != 1 {
		t.Errorf("collector LRU length = %d, want 1", lruLen)
	}
}

func waitForLiveJournalCount(c *liveJournalCollector, ip string, want int, timeout time.Duration) bool {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		c.mu.Lock()
		ent := c.byIP[ip]
		got := 0
		if ent != nil {
			got = ent.stats.Count
		}
		c.mu.Unlock()
		if got == want {
			return true
		}
		select {
		case <-deadline.C:
			return false
		case <-ticker.C:
		}
	}
}

// TestSyncJournalEventSkipsAdmin ensures admin-source events remain telemetry
// without polluting the live collector or creating actor rows.
func TestSyncJournalEventSkipsAdmin(t *testing.T) {
	resetLiveCollectorForTest()
	defer resetLiveCollectorForTest()

	st, err := store.Open(filepath.Join(t.TempDir(), "sync-admin.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	admin := AdminSet([]string{"10.0.0.5"})
	e := &models.Event{
		TS: time.Now(), Source: models.SourceJournal, Kind: models.KindFailedPass,
		SrcIP: "10.0.0.5", Username: "ops", ActorID: JournalActorID("10.0.0.5"),
		Raw: "{}",
	}
	inserted, err := SyncJournalEvent(st, e, admin)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !inserted {
		t.Fatal("admin event reported duplicate")
	}
	if e.ActorID != "" {
		t.Fatalf("admin event ActorID = %q, want blank", e.ActorID)
	}
	events, err := st.RecentEvents(10)
	if err != nil {
		t.Fatalf("recent events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("stored event count = %d, want 1", len(events))
	}
	if events[0].ActorID != "" {
		t.Errorf("stored admin event ActorID = %q, want blank", events[0].ActorID)
	}
	actors, err := st.ListActors(10)
	if err != nil {
		t.Fatalf("list actors: %v", err)
	}
	if len(actors) != 0 {
		t.Errorf("admin event created an actor row: %+v", actors)
	}
	if liveCollector != nil {
		t.Error("admin event initialized the live collector")
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
	if _, err := SyncJournalEvent(st, e, AdminSet([]string{"10.0.0.1"})); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	second := *e
	second.Raw = `{"distinct":true}`
	second.ActorID = "must-remain-unchanged"
	_, err = SyncJournalEvent(st, &second, AdminSet([]string{e.SrcIP}))
	if err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
	if second.ActorID != "must-remain-unchanged" {
		t.Fatalf("mismatched call changed ActorID to %q", second.ActorID)
	}
	events, countErr := st.EventCount()
	if countErr != nil {
		t.Fatalf("event count: %v", countErr)
	}
	if events != 1 {
		t.Fatalf("event count after mismatch = %d, want 1", events)
	}
}

// TestAdminSetsEqual is a small unit covering the helper used by
// SyncJournalEvent's mismatch check.
func TestAdminSetsEqual(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		want bool
	}{
		{"both nil", nil, nil, true},
		{"empty vs nil", []string{}, nil, true},
		{"same one", []string{"10.0.0.1"}, []string{"10.0.0.1"}, true},
		{"order independent", []string{"10.0.0.1", "10.0.0.2"}, []string{"10.0.0.2", "10.0.0.1"}, true},
		{"different size", []string{"10.0.0.1"}, []string{"10.0.0.1", "10.0.0.2"}, false},
		{"different key", []string{"10.0.0.1"}, []string{"10.0.0.2"}, false},
		{"same cidr", []string{"192.168.0.0/16"}, []string{"192.168.0.0/16"}, true},
		{"ip vs cidr", []string{"192.168.0.1"}, []string{"192.168.0.0/16"}, false},
	}
	for _, c := range cases {
		if got := adminSetsEqual(AdminSet(c.a), AdminSet(c.b)); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
