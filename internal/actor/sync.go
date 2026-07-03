package actor

import (
	"container/list"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/networkshard/shardlure/internal/netmatch"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

// Tunables for the bounded live collector. These are package-level
// vars (not consts) so tests can shrink them to force eviction.
//
//   - liveMaxIPs caps the number of distinct source IPs the live tail
//     keeps fully resident. Each entry is a small IPStats with a
//     username sub-map; the DB upsert is what makes a row durable, so
//     evicting only loses the in-memory cache (it's reloaded on the
//     next event for that IP).
//   - liveMaxUsersPerIP caps the cardinality of the per-IP username
//     map. Overflow names are collapsed into liveUserOverflowKey so
//     the IP's distinct-user count keeps incrementing while we stop
//     allocating new map entries. This protects against a single
//     scanner trying to exhaust memory with a million unique probed
//     names.
//   - liveIdleTTL is a defensive sweep ceiling: an IP not touched in
//     this long becomes a candidate for eviction even if the LRU is
//     under capacity. Without it, a single bot from a fixed IP that
//     hammers us for an hour and then disappears would otherwise
//     stay pinned until the LRU rolls over (which could be days on
//     a quiet honeypot).
var (
	liveMaxIPs          = 4096
	liveMaxUsersPerIP   = 256
	liveUserOverflowKey = "_overflow_"
	liveIdleTTL         = 12 * time.Hour
)

// liveCollector is a process-wide bounded journal aggregator. State
// accumulates across the lifetime of the live tail but the LRU + TTL
// keep RSS flat: the previous version held one IPStats forever per
// source IP and one map entry forever per probed username, which on
// a busy honeypot was the dominant lifetime allocation.
//
// The DB is the source of truth: every Add() ends in an
// UpsertJournalActorAtomic. When an entry is evicted, the row stays
// authoritative; on the IP's next event we re-hydrate from
// store.LoadJournalIPStats so the upsert continues to write the true
// running totals instead of clobbering them with a small post-evict
// count.
//
// The collector is locked by a single mutex. The live journal tail is
// single-goroutine so contention is nil; the mutex exists for the
// pprof/test-introspection paths.
type liveJournalCollector struct {
	mu       sync.Mutex
	admin    *netmatch.Set
	byIP     map[string]*liveIPEntry
	lru      *list.List // front = most recently touched, back = eviction candidate
	maxIPs   int
	maxUsers int
	idleTTL  time.Duration
	now      func() time.Time // injectable for tests
}

// liveIPEntry wraps the existing IPStats with an LRU pointer and a
// last-touched timestamp. The element value stored in c.lru is the
// IP string (we keep the entry struct off the list to avoid extra
// dereferencing on each access).
type liveIPEntry struct {
	stats   IPStats
	elem    *list.Element
	touched time.Time
}

func newLiveJournalCollector(admin *netmatch.Set) *liveJournalCollector {
	return &liveJournalCollector{
		admin:    admin,
		byIP:     map[string]*liveIPEntry{},
		lru:      list.New(),
		maxIPs:   liveMaxIPs,
		maxUsers: liveMaxUsersPerIP,
		idleTTL:  liveIdleTTL,
		now:      time.Now,
	}
}

var (
	liveCollectorMu    sync.Mutex
	liveCollector      *liveJournalCollector
	liveCollectorAdmin *netmatch.Set
)

// LiveJournalCollectorStats returns a snapshot of the live
// collector's resident size for the /debug/runtime endpoint.
// Returns zeroes when the collector has not been initialised yet
// (no journal events have been processed since process start).
//
// Returned fields:
//   - ips:   distinct source IPs currently resident in the byIP map
//   - lru:   the LRU list length (should match ips; divergence is
//     a structural bug)
//   - max:   the IP cap (liveMaxIPs) — when ips == max, eviction
//     is the steady state
//   - users: the per-IP username cap (liveMaxUsersPerIP)
func LiveJournalCollectorStats() (ips, lru, max, users int) {
	liveCollectorMu.Lock()
	c := liveCollector
	liveCollectorMu.Unlock()
	if c == nil {
		return 0, 0, liveMaxIPs, liveMaxUsersPerIP
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.byIP), c.lru.Len(), c.maxIPs, c.maxUsers
}

// adminSetsEqual is a cheap structural comparison used to detect the
// "different admin set across goroutines" misuse. The live tail passes the
// identical *Set on every call, so the pointer fast-path eliminates the
// sort+join in Key() from the per-event steady state; content comparison is
// kept for callers that rebuild an equivalent set from the same config.
func adminSetsEqual(a, b *netmatch.Set) bool {
	if a == b {
		return true
	}
	return a.Key() == b.Key()
}

// SyncJournalEvent updates the actor row for a single freshly-
// inserted journal event. The event's ActorID must already be set to
// JournalActorID(e.SrcIP) (the live tail does this before
// InsertEvent).
//
// Steady-state cost: O(U log U) where U is the unique-username count
// for this IP. On an evicted-then-returning IP, plus a single
// indexed SELECT to re-hydrate counters from the DB. Bounded RSS in
// either case.
func SyncJournalEvent(st *store.Store, e *models.Event, admin *netmatch.Set) error {
	if e == nil || e.SrcIP == "" || admin.Has(e.SrcIP) {
		return nil
	}
	liveCollectorMu.Lock()
	if liveCollector == nil {
		liveCollector = newLiveJournalCollector(admin)
		liveCollectorAdmin = admin
	} else if !adminSetsEqual(liveCollectorAdmin, admin) {
		liveCollectorMu.Unlock()
		return fmt.Errorf("actor: SyncJournalEvent admin set changed between calls; restart process to pick up new admin IPs")
	}
	c := liveCollector
	liveCollectorMu.Unlock()

	// Hydrate the IP from the DB on first sight after process start
	// or after eviction. Done outside c.mu to avoid holding the
	// collector lock across the SELECT.
	if !c.has(e.SrcIP) {
		stored, err := st.LoadJournalIPStats(e.SrcIP)
		if err != nil {
			return fmt.Errorf("hydrate journal ip stats: %w", err)
		}
		c.hydrate(e.SrcIP, stored)
	}

	a, ipStat, userCount := c.addAndFinalize(e)
	if a == nil {
		return nil
	}
	return st.UpsertJournalActorAtomic(
		a,
		e.SrcIP, ipStat.First, ipStat.Last, ipStat.Count,
		e.Username, userCount,
	)
}

// has reports whether the collector currently holds an entry for ip.
// Always returns false for admin IPs (they're filtered upstream by
// SyncJournalEvent before this is reached, so the value is moot, but
// the check keeps the helper safe to call on any input).
func (c *liveJournalCollector) has(ip string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.byIP[ip]
	return ok
}

// hydrate installs counters loaded from the DB. Idempotent: if the
// entry already exists (a concurrent caller raced us), the existing
// values win — they were just hydrated too and any subsequent add()
// from the racing event will roll forward correctly.
func (c *liveJournalCollector) hydrate(ip string, stored store.JournalIPStats) {
	if c.admin.Has(ip) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.byIP[ip]; exists {
		return
	}
	users := stored.UserCounts
	if users == nil {
		users = map[string]int{}
	}
	// Cap on hydration to honor the maxUsers invariant. We can't
	// recover the exact mapping from before the cap, so we keep the
	// top-N by count and put the rest in overflow. Sort by count
	// descending; pick a deterministic tie-breaker so the snapshot
	// is reproducible.
	if len(users) > c.maxUsers {
		users = capUsersMap(users, c.maxUsers)
	}
	now := c.now()
	ent := &liveIPEntry{
		stats: IPStats{
			Count: stored.Count,
			Users: users,
			First: stored.First,
			Last:  stored.Last,
		},
		touched: now,
	}
	ent.elem = c.lru.PushFront(ip)
	c.byIP[ip] = ent
	c.evictIfNeededLocked(now)
}

// addAndFinalize records one event and returns the rebuilt Actor row, the
// per-IP stat snapshot, and the post-update username count for the event's
// username. It deliberately returns scalars/value types only — the previous
// version built a full AggregatedActor per event, copying the entire per-IP
// users map (up to maxUsers entries) and allocating a one-entry IPs map that
// the caller immediately unpacked and discarded.
func (c *liveJournalCollector) addAndFinalize(e *models.Event) (*models.Actor, IPStat, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.admin.Has(e.SrcIP) {
		return nil, IPStat{}, 0
	}
	now := c.now()
	ent, ok := c.byIP[e.SrcIP]
	if !ok {
		ent = &liveIPEntry{
			stats: IPStats{Users: map[string]int{}},
		}
		ent.elem = c.lru.PushFront(e.SrcIP)
		c.byIP[e.SrcIP] = ent
		c.evictIfNeededLocked(now)
	} else {
		c.lru.MoveToFront(ent.elem)
	}
	ent.touched = now
	ent.stats.Count++
	if e.Username != "" && e.Username != "?" {
		c.bumpUserLocked(&ent.stats, e.Username)
	}
	if ent.stats.First.IsZero() || e.TS.Before(ent.stats.First) {
		ent.stats.First = e.TS
	}
	if e.TS.After(ent.stats.Last) {
		ent.stats.Last = e.TS
	}
	userCount := 0
	if e.Username != "" && e.Username != "?" {
		// After bumpUserLocked the map either holds the real key or
		// has rolled it into the overflow bucket. Either way the
		// stored value is the count we want to upsert.
		if v, ok := ent.stats.Users[e.Username]; ok {
			userCount = v
		} else {
			userCount = ent.stats.Users[liveUserOverflowKey]
		}
	}
	a := journalActor(e.SrcIP, &ent.stats)
	ipStat := IPStat{Count: ent.stats.Count, First: ent.stats.First, Last: ent.stats.Last}
	return a, ipStat, userCount
}

// bumpUserLocked increments the per-IP username counter, rolling
// new usernames into the overflow bucket once the per-IP map is at
// capacity. Existing usernames always continue to increment.
func (c *liveJournalCollector) bumpUserLocked(st *IPStats, u string) {
	if _, ok := st.Users[u]; ok {
		st.Users[u]++
		return
	}
	if len(st.Users) >= c.maxUsers {
		st.Users[liveUserOverflowKey]++
		return
	}
	st.Users[u] = 1
}

// evictIfNeededLocked enforces the IP-cap and the idle-TTL ceiling.
// Idle entries are walked from the LRU tail; we cap the per-call work
// at a small constant so a hot add doesn't pay for a global sweep.
func (c *liveJournalCollector) evictIfNeededLocked(now time.Time) {
	// Strict size cap: drop the oldest until we're at the limit.
	for c.lru.Len() > c.maxIPs {
		c.dropOldestLocked()
	}
	// Opportunistic idle sweep: at most 4 entries per call.
	for i := 0; i < 4; i++ {
		e := c.lru.Back()
		if e == nil {
			return
		}
		ip := e.Value.(string)
		ent := c.byIP[ip]
		if ent == nil || now.Sub(ent.touched) < c.idleTTL {
			return
		}
		c.dropOldestLocked()
	}
}

func (c *liveJournalCollector) dropOldestLocked() {
	e := c.lru.Back()
	if e == nil {
		return
	}
	ip := e.Value.(string)
	c.lru.Remove(e)
	delete(c.byIP, ip)
}

// capUsersMap returns a new map containing the top-n entries of in
// (by count, ties broken by lexical key) plus an overflow bucket
// holding the summed counts of the dropped entries. Used during
// hydration when the persisted user count exceeds the per-IP cap.
func capUsersMap(in map[string]int, n int) map[string]int {
	if n <= 0 || len(in) <= n {
		out := make(map[string]int, len(in))
		for k, v := range in {
			out[k] = v
		}
		return out
	}
	type kv struct {
		k string
		v int
	}
	all := make([]kv, 0, len(in))
	for k, v := range in {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	out := make(map[string]int, n+1)
	overflow := 0
	for i, e := range all {
		if i < n {
			out[e.k] = e.v
		} else {
			overflow += e.v
		}
	}
	if overflow > 0 {
		out[liveUserOverflowKey] = overflow
	}
	return out
}
