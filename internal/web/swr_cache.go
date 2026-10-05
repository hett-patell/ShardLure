package web

import (
	"context"
	"sync"
	"time"
)

// swrCache is the hasshCoverageCached pattern for the other poll-path caches:
// once a value exists, an expired read returns it immediately and starts at
// most one background refresh, admitted through the server's handlerDrain so
// RunContext joins it before the store closes.
//
// Before this, whichever dashboard request landed on an expiry ran the scans
// itself while every other poller queued on the cache mutex: on ARM, with the
// dashboard polled every 10 s, the summary tiers cost 3.6 s and
// RecentShellSessions 3.5 s of a 60 s CPU profile, paid in request latency.
//
// Two differences from hasshCoverageCached, both deliberate:
//   - The FIRST value is computed synchronously, under mu, so concurrent first
//     callers share one computation and a cold request still gets real data
//     (WarmCaches fills these before the server reports ready). Coverage can
//     render "-" while it loads; an empty summary cannot.
//   - compute returns the stamp to store, so the lifetime tier keeps
//     lifetimeStamp's rule: a degenerate value expires on statsTTL and is
//     refreshed in the background that much sooner.
//
// A failed refresh keeps the last good value and its stamp (so the next read
// retries), the policy every tier already had. Only a cache that has never
// succeeded returns an error.
//
// compute runs on the drain's context, which bg.stop() cancels: a shutdown
// interrupts an in-flight scan instead of waiting for it (a lifetime-tier
// refresh is seconds on ARM), and a refresh cancelled that way is dropped
// like any failed one, so cancellation can never replace good data with a
// partial or errored result.
type swrCache[T any] struct {
	mu         sync.Mutex
	val        T
	ok         bool
	at         time.Time
	refreshing bool
	// gen counts invalidations, so a background refresh that started before
	// one cannot publish the value it computed from pre-invalidation state.
	gen uint64
}

func (c *swrCache[T]) get(bg *handlerDrain, ttl time.Duration, compute func(context.Context) (T, time.Time, error)) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx := bg.context()
	if !c.ok {
		v, at, err := compute(ctx)
		if err != nil {
			return c.val, err
		}
		c.val, c.at, c.ok = v, at, true
		return c.val, nil
	}
	if time.Since(c.at) >= ttl && !c.refreshing && bg.enter() {
		c.refreshing = true
		gen := c.gen
		go func() {
			defer bg.leave()
			v, at, err := compute(ctx)
			c.mu.Lock()
			defer c.mu.Unlock()
			c.refreshing = false
			if err == nil && ctx.Err() == nil && gen == c.gen {
				c.val, c.at = v, at
			}
		}()
	}
	return c.val, nil
}

// peek returns the cached value without computing or refreshing; tests and
// warm-up checks use it.
func (c *swrCache[T]) peek() (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.val, c.ok
}

// invalidate drops the cached value so the next get recomputes synchronously.
// It is for state changes this process itself makes and must show at once
// (a MalwareBazaar upload removing a sample from the candidate pool), where
// serving one more stale read would advertise an action the server now
// refuses. A refresh already in flight is discarded rather than published.
func (c *swrCache[T]) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ok = false
	c.gen++
}

// expire backdates the stamp so the next get refreshes; tests use it.
func (c *swrCache[T]) expire(by time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = time.Now().Add(-by)
}
