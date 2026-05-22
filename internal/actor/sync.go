package actor

import (
	"sync"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

// liveCollector is a process-wide JournalCollector that accumulates
// state across the lifetime of the live journal tail. Each new event
// is added in O(1); the resulting actor is upserted by IP without
// re-reading any history from the database. This replaces the old
// approach where every inbound event triggered an unbounded
// EventsByIP scan plus a per-event UpdateEventActor loop.
var (
	liveCollectorMu sync.Mutex
	liveCollector   *journalCollector
)

// resetLiveCollectorForTest is wired into tests via export_test.go
// so each test can start from a clean accumulator. Production code
// does not call this.
func resetLiveCollectorForTest() {
	liveCollectorMu.Lock()
	liveCollector = nil
	liveCollectorMu.Unlock()
}

// SyncJournalEvent updates the actor for a single freshly-inserted
// journal event. The event's ActorID must already be set to
// JournalActorID(e.SrcIP) (the live tail does this before InsertEvent).
//
// Behaviour: O(1) amortised. We accumulate per-IP stats in memory and
// upsert the actor + actor_ips + actor_users rows that changed. We
// do NOT iterate existing events for the IP - the only state needed
// to keep counters accurate is what we've seen during this process'
// lifetime, which is what the journal tail observes anyway.
func SyncJournalEvent(st *store.Store, e *models.Event, admin map[string]bool) error {
	if e == nil || e.SrcIP == "" || admin[e.SrcIP] {
		return nil
	}
	liveCollectorMu.Lock()
	if liveCollector == nil {
		liveCollector = newJournalCollector(admin)
	}
	liveCollector.add(e)
	agg := liveCollector.FinalizeIP(e.SrcIP)
	liveCollectorMu.Unlock()
	if agg == nil {
		return nil
	}
	if err := st.UpsertActor(agg.Actor); err != nil {
		return err
	}
	// IP row: there's only ever one IP per journal actor so we can
	// pass the totals straight through.
	ipStat := agg.IPs[e.SrcIP]
	if err := st.UpsertActorIP(agg.Actor.ID, e.SrcIP, ipStat.First, ipStat.Last, ipStat.Count); err != nil {
		return err
	}
	// User rows: only the one we just observed could have changed.
	// Skipping the full Users map keeps this O(1) instead of O(unique-users).
	if e.Username != "" && e.Username != "?" {
		if err := st.UpsertActorUser(agg.Actor.ID, e.Username, agg.Users[e.Username]); err != nil {
			return err
		}
	}
	return nil
}

// SyncJournalIP is kept as a backfill helper for paths that need to
// rebuild an actor from the full event history (e.g. one-shot CLI
// commands that import old logs). Live tailing must use
// SyncJournalEvent instead - calling SyncJournalIP per event is
// O(N) per insert and was the original perf bug.
//
// Deprecated: prefer SyncJournalEvent for streaming ingest.
func SyncJournalIP(st *store.Store, ip string, admin map[string]bool) error {
	events, err := st.EventsByIP(ip, 0)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	ptrs := make([]*models.Event, len(events))
	for i := range events {
		ptrs[i] = events[i]
	}
	actors := BuildFromJournal(ptrs, admin)
	if len(actors) == 0 {
		return nil
	}
	a := actors[0]
	if err := st.UpsertActor(a); err != nil {
		return err
	}
	users := map[string]int{}
	for _, e := range ptrs {
		if e.Username != "" {
			users[e.Username]++
		}
	}
	for u, c := range users {
		if err := st.UpsertActorUser(a.ID, u, c); err != nil {
			return err
		}
	}
	return st.UpsertActorIP(a.ID, ip, a.FirstSeen, a.LastSeen, len(ptrs))
}
