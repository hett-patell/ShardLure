package actor

import (
	"fmt"
	"sync"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

// liveCollector is a process-wide JournalCollector that accumulates
// state across the lifetime of the live journal tail. Each new event
// is added by the in-memory collector; the resulting actor is then
// upserted by IP without re-reading any history from the database.
// This replaces the old approach where every inbound event triggered
// an unbounded EventsByIP scan plus a per-event UpdateEventActor loop.
//
// The collector + its admin set are bound on first use; subsequent
// callers passing a different admin map will trip an assertion. This
// is intentional - if you need a fresh admin set you must restart
// the process (the live tail is single-goroutine in production so
// the constraint is trivially satisfied).
var (
	liveCollectorMu    sync.Mutex
	liveCollector      *journalCollector
	liveCollectorAdmin map[string]bool
)

// resetLiveCollectorForTest clears process-wide state. Lowercase by
// design - test files in the same package call it directly.
func resetLiveCollectorForTest() {
	liveCollectorMu.Lock()
	liveCollector = nil
	liveCollectorAdmin = nil
	liveCollectorMu.Unlock()
}

// adminSetsEqual is a cheap structural comparison used to detect the
// "different admin map across goroutines" misuse.
func adminSetsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// SyncJournalEvent updates the actor row for a single freshly-
// inserted journal event. The event's ActorID must already be set to
// JournalActorID(e.SrcIP) (the live tail does this before InsertEvent).
//
// Cost: O(U log U) where U is the unique-username count for this IP
// (the FinalizeIP sort + the user-map copy). Database work is three
// upserts inside one transaction - constant in event count, never
// scans event history. This is the function that replaced the
// per-event O(N) scan that earlier versions of SyncJournalIP did.
func SyncJournalEvent(st *store.Store, e *models.Event, admin map[string]bool) error {
	if e == nil || e.SrcIP == "" || admin[e.SrcIP] {
		return nil
	}
	liveCollectorMu.Lock()
	if liveCollector == nil {
		liveCollector = newJournalCollector(admin)
		liveCollectorAdmin = admin
	} else if !adminSetsEqual(liveCollectorAdmin, admin) {
		// Catch the "different goroutine with a different admin map"
		// misuse before it produces silently wrong counters. The
		// journal tail is single-goroutine in production, so seeing
		// this in the wild means a structural mistake.
		liveCollectorMu.Unlock()
		return fmt.Errorf("actor: SyncJournalEvent admin set changed between calls; restart process to pick up new admin IPs")
	}
	liveCollector.add(e)
	agg := liveCollector.FinalizeIP(e.SrcIP)
	// Snapshot the user count under the lock so we can release it
	// before the (potentially slow) DB call.
	var userCount int
	if agg != nil && e.Username != "" && e.Username != "?" {
		userCount = agg.Users[e.Username]
	}
	liveCollectorMu.Unlock()
	if agg == nil {
		return nil
	}
	ipStat := agg.IPs[e.SrcIP]
	// One transaction so a crash between the three writes can't
	// leave actor/ip/user rows out of sync. Self-healing on the
	// next event, but the tx makes the recovery path simpler.
	return st.UpsertJournalActorAtomic(
		agg.Actor,
		e.SrcIP, ipStat.First, ipStat.Last, ipStat.Count,
		e.Username, userCount,
	)
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
