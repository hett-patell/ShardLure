package web

import (
	"context"
	"sync"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// actorUsersTTL is how long an actor's top-username list is served before a
// background refresh. The lists are the "top users" chips in /api/intel's
// actor table: an actor's ranking by attempt count moves slowly (a
// brute-forcer's top 8 of tens of thousands of names barely change within a
// minute), so a minute of staleness is invisible, while computing them is
// not. store.ActorUsersForActors is a ROW_NUMBER() window over EVERY username
// of the ~80 listed actors: on the production copy (98,913 actor_users rows,
// brute-force actors holding tens of thousands each) it was 4.05 s of a 4.38 s
// /api/intel CPU profile on ARM, paid on every 5 s poll. An index on
// actor_users(actor_id, count DESC, username) would make the sort cheap but
// move an index entry on every username-count increment during journal
// ingest, the hottest write path, so the result is cached instead.
const actorUsersTTL = time.Minute

// actorUsersRetain bounds the cache: an actor not requested for this long has
// left the listed set and its entry is dropped on the next fill.
const actorUsersRetain = 10 * time.Minute

// actorUsersPerActor is how many top usernames /api/intel shows per actor.
const actorUsersPerActor = 8

type actorUsersEntry struct {
	users []models.ActorUser
	at    time.Time // when computed
	used  time.Time // last requested
}

// actorUsersCache caches the top usernames PER ACTOR, not per listed set: the
// 80-actor list is ordered by last_seen and changes whenever a new attacker
// appears, so a set key would miss on almost every change while most actors
// stay the same. It follows swrCache's policy:
//   - actors with no entry are fetched synchronously (one batched query for
//     all of them, serialised by fillMu so concurrent cold requests share it);
//   - expired entries are served at once and refreshed by at most one
//     background query at a time, admitted through the server's handlerDrain
//     and run on its context, so shutdown cancels it (sqlite3_interrupt) and
//     RunContext joins it before the store closes;
//   - a failed or cancelled refresh keeps the last-good lists.
type actorUsersCache struct {
	mu         sync.Mutex
	entries    map[string]actorUsersEntry
	refreshing bool
	fillMu     sync.Mutex
}

type actorUsersFetch func(ctx context.Context, ids []string, perActor int) (map[string][]models.ActorUser, error)

// get returns the top usernames for ids. Only an actor never fetched before
// can make it return an error.
func (c *actorUsersCache) get(bg *handlerDrain, fetch actorUsersFetch, ids []string) (map[string][]models.ActorUser, error) {
	now := time.Now()
	out, missing, stale := c.lookup(ids, now)
	if len(missing) > 0 {
		c.fillMu.Lock()
		// Another request may have filled them while this one waited.
		_, missing, _ = c.lookup(missing, now)
		if len(missing) > 0 {
			got, err := fetch(bg.context(), missing, actorUsersPerActor)
			if err != nil {
				c.fillMu.Unlock()
				return nil, err
			}
			c.store(missing, got, time.Now())
		}
		c.fillMu.Unlock()
		out, _, stale = c.lookup(ids, now)
	}
	if len(stale) > 0 {
		c.mu.Lock()
		start := !c.refreshing && bg.enter()
		if start {
			c.refreshing = true
		}
		c.mu.Unlock()
		if start {
			ctx := bg.context()
			go func() {
				defer bg.leave()
				got, err := fetch(ctx, stale, actorUsersPerActor)
				if err == nil && ctx.Err() == nil {
					c.store(stale, got, time.Now())
				}
				c.mu.Lock()
				c.refreshing = false
				c.mu.Unlock()
			}()
		}
	}
	return out, nil
}

// lookup splits ids into cached lists (out), ids with no entry and ids whose
// entry has expired (served, but owed a refresh), and marks them used.
func (c *actorUsersCache) lookup(ids []string, now time.Time) (out map[string][]models.ActorUser, missing, stale []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out = make(map[string][]models.ActorUser, len(ids))
	for _, id := range ids {
		e, ok := c.entries[id]
		if !ok {
			missing = append(missing, id)
			continue
		}
		e.used = now
		c.entries[id] = e
		out[id] = e.users
		if now.Sub(e.at) >= actorUsersTTL {
			stale = append(stale, id)
		}
	}
	return out, missing, stale
}

// store records a fetch for every requested id (an actor with no usernames
// caches an empty list, so it is not refetched on every poll) and drops
// entries no request has used for actorUsersRetain.
func (c *actorUsersCache) store(ids []string, got map[string][]models.ActorUser, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]actorUsersEntry, len(ids))
	}
	for id, e := range c.entries {
		if at.Sub(e.used) > actorUsersRetain {
			delete(c.entries, id)
		}
	}
	for _, id := range ids {
		used := at
		if e, ok := c.entries[id]; ok {
			used = e.used
		}
		c.entries[id] = actorUsersEntry{users: got[id], at: at, used: used}
	}
}

// expire backdates every entry so the next get refreshes; tests use it.
func (c *actorUsersCache) expire(by time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, e := range c.entries {
		e.at = e.at.Add(-by)
		c.entries[id] = e
	}
}

// actorUsersCached is the /api/intel read of the listed actors' top users.
func (s *Server) actorUsersCached(ids []string) (map[string][]models.ActorUser, error) {
	fetch := s.actorUsersFetch
	if fetch == nil {
		fetch = func(ctx context.Context, ids []string, n int) (map[string][]models.ActorUser, error) {
			return s.st.ActorUsersForActorsContext(ctx, ids, n)
		}
	}
	return s.actorUsers.get(&s.bg, fetch, ids)
}
