package web

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
)

func hourlyHits(rows []store.HourCount) int {
	n := 0
	for _, r := range rows {
		n += r.Hits
	}
	return n
}

// An expired poll-path tier is served from memory while one background
// refresh recomputes it: the request that happens to land on the expiry no
// longer pays the scan (summary tiers 3.6 s and RecentShellSessions 3.5 s of a
// 60 s ARM profile with the dashboard polled every 10 s).
func TestPollPathTiersServeStaleWhileRefreshing(t *testing.T) {
	s, _ := hasshTestServer(t)
	addSummaryEvent(t, s, "192.0.2.1")
	if _, err := s.summaryStatsCached(); err != nil {
		t.Fatal(err)
	}
	if hourly, _ := s.dashExtraCachedValues(); hourlyHits(hourly) != 1 {
		t.Fatalf("hourly = %v, want 1 hit", hourly)
	}
	rates := s.recentRatesCached()
	if rates["cowrie:192.0.2.1"] == 0 {
		t.Fatalf("rates not computed: %v", rates)
	}

	addSummaryEvent(t, s, "192.0.2.2")
	expireLiveTiers(s)

	got, err := s.summaryStatsCached()
	if err != nil {
		t.Fatal(err)
	}
	if got.Events != 1 {
		t.Fatalf("expired live tier recomputed on the request: events %d, want last-good 1", got.Events)
	}
	if r := s.recentRatesCached(); r["cowrie:192.0.2.2"] != 0 {
		t.Fatalf("expired rates recomputed on the request: %v", r)
	}
	if hourly, _ := s.dashExtraCachedValues(); hourlyHits(hourly) != 1 {
		t.Fatalf("expired dashboard extras recomputed on the request: %v", hourly)
	}
	s.bg.wait()
	if hourly, _ := s.dashExtraCachedValues(); hourlyHits(hourly) != 2 {
		t.Fatalf("background extras refresh did not publish: %v", hourly)
	}
	got, err = s.summaryStatsCached()
	if err != nil {
		t.Fatal(err)
	}
	if got.Events != 2 {
		t.Fatalf("background refresh did not publish: events %d, want 2", got.Events)
	}
	if r := s.recentRatesCached(); r["cowrie:192.0.2.2"] == 0 {
		t.Fatalf("background rates refresh did not publish: %v", r)
	}
}

func expireLiveTiers(s *Server) {
	s.liveStats.expire(statsTTL + time.Second)
	s.extraCache.expire(statsTTL + time.Second)
	s.ratesCache.expire(statsTTL + time.Second)
}

// The mechanics, with a compute that blocks like a cold scan on ARM: the first
// value is computed on the caller (a cold request must get data, not zeroes),
// an expired read never waits, exactly one refresh runs at a time, and a
// failed refresh keeps the last good value.
func TestSWRCacheMechanics(t *testing.T) {
	var bg handlerDrain
	var c swrCache[int]
	var calls atomic.Int32
	release := make(chan struct{})
	fail := atomic.Bool{}
	compute := func(context.Context) (int, time.Time, error) {
		n := calls.Add(1)
		if n > 1 {
			<-release
		}
		if fail.Load() {
			return 0, time.Time{}, errors.New("transient")
		}
		return int(n), time.Now(), nil
	}

	// First ever: synchronous, and an error is returned to the caller.
	fail.Store(true)
	if _, err := c.get(&bg, time.Minute, func(context.Context) (int, time.Time, error) { return 0, time.Time{}, errors.New("cold") }); err == nil {
		t.Fatal("first computation's error was swallowed")
	}
	fail.Store(false)
	if v, err := c.get(&bg, time.Minute, compute); err != nil || v != 1 {
		t.Fatalf("first get = %d, %v; want 1 computed on the caller", v, err)
	}
	if v, _ := c.get(&bg, time.Minute, compute); v != 1 || calls.Load() != 1 {
		t.Fatalf("fresh get recomputed: v=%d calls=%d", v, calls.Load())
	}

	c.expire(time.Hour)
	returnsWithin(t, time.Second, func() {
		for i := 0; i < 5; i++ {
			if v, err := c.get(&bg, time.Minute, compute); err != nil || v != 1 {
				t.Errorf("stale get = %d, %v; want last-good 1", v, err)
			}
		}
	})
	for deadline := time.Now().Add(time.Second); calls.Load() < 2 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("%d computations, want the first plus exactly one refresh", n)
	}
	close(release)
	bg.wait()
	if v, _ := c.get(&bg, time.Minute, compute); v != 2 {
		t.Fatalf("after refresh = %d, want 2", v)
	}

	// A failed refresh keeps the last good value and retries on the next read.
	fail.Store(true)
	c.expire(time.Hour)
	c.get(&bg, time.Minute, compute)
	bg.wait()
	if v, err := c.get(&bg, time.Minute, compute); err != nil || v != 2 {
		t.Fatalf("after failed refresh = %d, %v; want last-good 2", v, err)
	}
	bg.wait()
	if n := calls.Load(); n != 4 {
		t.Fatalf("%d computations, want the failed refresh retried on the next read", n)
	}

	// Once the drain is stopping no refresh is admitted, so nothing can
	// outlive RunContext and query a closed store.
	bg.stop()
	c.expire(time.Hour)
	c.get(&bg, time.Minute, compute)
	if n := calls.Load(); n != 4 {
		t.Fatalf("refresh started after stop: %d computations", n)
	}
}

// A refresh in flight at shutdown is cancelled, not awaited: bg.stop()
// cancels the context compute runs on, the refresh returns at once, bg.wait()
// does not block on the scan, and the cancelled result never replaces the
// last good value (whether compute returned an error or a partial value).
func TestSWRCacheRefreshIsCancelledByStop(t *testing.T) {
	for _, returnsValue := range []bool{false, true} {
		var bg handlerDrain
		var c swrCache[int]
		started := make(chan struct{})
		compute := func(ctx context.Context) (int, time.Time, error) {
			if ctx.Err() != nil { // only the refresh blocks; the first value is immediate
				return 0, time.Time{}, ctx.Err()
			}
			select {
			case <-started:
			default:
				close(started)
				return 1, time.Now(), nil
			}
			<-ctx.Done() // a long scan, interrupted by shutdown
			if returnsValue {
				return 99, time.Now(), nil // a partial result must still be dropped
			}
			return 0, time.Time{}, ctx.Err()
		}
		if v, err := c.get(&bg, time.Minute, compute); err != nil || v != 1 {
			t.Fatalf("first get = %d, %v", v, err)
		}
		c.expire(time.Hour)
		if v, _ := c.get(&bg, time.Minute, compute); v != 1 {
			t.Fatalf("stale get = %d, want last-good 1", v)
		}
		returnsWithin(t, time.Second, func() {
			bg.stop()
			bg.wait()
		})
		if v, ok := c.peek(); !ok || v != 1 {
			t.Fatalf("returnsValue=%v: cancelled refresh replaced the value: %d %v", returnsValue, v, ok)
		}
	}
}

// invalidate makes the next read recompute synchronously, and a refresh that
// was already in flight is discarded instead of overwriting the newer value.
// The MalwareBazaar candidate cache needs both: after an upload the shipped
// sample must leave the pool on the very next read, and a refresh computed
// before the upload must not put it back.
func TestSWRCacheInvalidateDiscardsInFlightRefresh(t *testing.T) {
	var bg handlerDrain
	var c swrCache[int]
	var calls atomic.Int32
	release := make(chan struct{})
	compute := func(context.Context) (int, time.Time, error) {
		n := calls.Add(1)
		if n == 2 { // the background refresh, computed from pre-invalidation state
			<-release
		}
		return int(n), time.Now(), nil
	}
	if v, _ := c.get(&bg, time.Minute, compute); v != 1 {
		t.Fatalf("first get = %d", v)
	}
	c.expire(time.Hour)
	c.get(&bg, time.Minute, compute) // starts refresh #2, which blocks
	for deadline := time.Now().Add(time.Second); calls.Load() < 2 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	c.invalidate()
	if v, err := c.get(&bg, time.Minute, compute); err != nil || v != 3 {
		t.Fatalf("get after invalidate = %d, %v; want a synchronous recompute (3)", v, err)
	}
	close(release)
	bg.wait()
	if v, _ := c.peek(); v != 3 {
		t.Fatalf("stale in-flight refresh published over the invalidated value: %d", v)
	}
}
