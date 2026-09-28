package web

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// blockingCoverage stands in for store.HASSHCoverage on a large database: on
// ARM (1.68M Cowrie rows) the query took 4-18 s cold, and every dashboard
// request waited behind it.
type blockingCoverage struct {
	calls   atomic.Int32
	release chan struct{}
	f, t    int
}

func (b *blockingCoverage) query() (int, int, error) {
	b.calls.Add(1)
	<-b.release
	return b.f, b.t, nil
}

func returnsWithin(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("call blocked for more than %s", d)
	}
}

func TestHASSHCoverageNeverBlocksARequest(t *testing.T) {
	s, _ := hasshTestServer(t)
	slow := &blockingCoverage{release: make(chan struct{}), f: 7, t: 9}
	s.hasshCoverage = slow.query

	// Never computed: answer at once (the page shows "-") and refresh behind.
	returnsWithin(t, time.Second, func() {
		if f, total := s.hasshCoverageCached(); f != 0 || total != 0 {
			t.Errorf("uncomputed = (%d, %d), want (0, 0)", f, total)
		}
	})
	for deadline := time.Now().Add(time.Second); slow.calls.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	returnsWithin(t, time.Second, func() { s.hasshCoverageCached() })
	if n := slow.calls.Load(); n != 1 {
		t.Fatalf("%d refreshes in flight, want exactly 1", n)
	}
	close(slow.release)
	s.bg.wait()
	if f, total := s.hasshCoverageCached(); f != 7 || total != 9 {
		t.Fatalf("after refresh = (%d, %d), want (7, 9)", f, total)
	}

	// Expired: keep serving the last value while one refresh runs.
	slow2 := &blockingCoverage{release: make(chan struct{}), f: 8, t: 10}
	s.hasshCoverage = slow2.query
	s.hasshMu.Lock()
	s.hasshAt = time.Now().Add(-hasshCoverageTTL - time.Second)
	s.hasshMu.Unlock()
	returnsWithin(t, time.Second, func() {
		if f, total := s.hasshCoverageCached(); f != 7 || total != 9 {
			t.Errorf("stale call = (%d, %d), want last-good (7, 9)", f, total)
		}
	})
	close(slow2.release)
	s.bg.wait()
	if f, total := s.hasshCoverageCached(); f != 8 || total != 10 {
		t.Fatalf("after second refresh = (%d, %d), want (8, 10)", f, total)
	}
}

// Startup warms every cache the landing dashboard reads, so the first request
// after a restart is served from memory instead of filling them cold.
func TestWarmCachesFillsDashboardTiers(t *testing.T) {
	s, st := hasshTestServer(t)
	addCowrieEvent(t, st, "aa:bb")
	addCowrieEvent(t, st, "")
	if err := s.WarmCaches(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.hasshMu.Lock()
	ok, f, total := s.hasshOK, s.hasshFingerprinted, s.hasshTotal
	s.hasshMu.Unlock()
	if !ok || f != 1 || total != 2 {
		t.Fatalf("coverage not warmed: ok=%v (%d, %d)", ok, f, total)
	}
	s.statsMu.Lock()
	live := s.statsCached != nil
	s.statsMu.Unlock()
	s.lifetimeMu.Lock()
	lifetime := s.lifetimeCached != nil
	s.lifetimeMu.Unlock()
	s.dashExtraMu.Lock()
	extra := s.dashExtraCached != nil
	s.dashExtraMu.Unlock()
	if !live || !lifetime || !extra {
		t.Fatalf("tiers not warmed: live=%v lifetime=%v extra=%v", live, lifetime, extra)
	}
}

func TestWarmCachesStopsWhenCancelled(t *testing.T) {
	s, _ := hasshTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.WarmCaches(ctx); err == nil {
		t.Fatal("cancelled warm-up reported success")
	}
}

// v2.8.0 joins every worker before the store closes; a background refresh
// must not outlive RunContext and query a closed database.
func TestRunContextWaitsForBackgroundRefresh(t *testing.T) {
	s, _ := hasshTestServer(t)
	slow := &blockingCoverage{release: make(chan struct{})}
	s.hasshCoverage = slow.query
	ctx, cancel := context.WithCancel(context.Background())
	listening := make(chan struct{})
	s.onListening = func(net.Addr) { close(listening) }
	done := make(chan error, 1)
	go func() { done <- s.RunContext(ctx) }()
	<-listening
	s.hasshCoverageCached()
	cancel()
	select {
	case <-done:
		t.Fatal("RunContext returned while a background refresh was still running")
	case <-time.After(300 * time.Millisecond):
	}
	close(slow.release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunContext did not return after the refresh finished")
	}
}
