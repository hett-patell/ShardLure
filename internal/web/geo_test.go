package web

import (
	"container/list"
	"strconv"
	"testing"
	"time"
)

// newTestResolver builds a geoResolver wired for unit tests:
// enabled-true so cache writes go through but http never fires
// because the test calls putLocked() directly.
func newTestResolver(max int, now func() time.Time) *geoResolver {
	return &geoResolver{
		cache:    map[string]*geoEntry{},
		lru:      list.New(),
		inflight: map[string]bool{},
		enabled:  true,
		maxSize:  max,
		now:      now,
	}
}

// TestGeoResolverEvictsByLRU stuffs more entries than the cap and
// confirms the oldest are dropped. Previously the cache grew
// unbounded with every distinct attacker IP the dashboard rendered.
func TestGeoResolverEvictsByLRU(t *testing.T) {
	now := time.Now().UTC()
	r := newTestResolver(8, func() time.Time { return now })

	for i := 0; i < 32; i++ {
		ip := "203.0.113." + strconv.Itoa(i+1)
		r.mu.Lock()
		r.putLocked(ip, geoEntry{OK: true, CC: "ZZ", Expiry: now.Add(24 * time.Hour)})
		r.mu.Unlock()
	}
	if got := len(r.cache); got != 8 {
		t.Errorf("cache size = %d, want 8", got)
	}
	if got := r.lru.Len(); got != 8 {
		t.Errorf("lru len = %d, want 8", got)
	}
	// Earliest inserts must be gone.
	for i := 0; i < 24; i++ {
		ip := "203.0.113." + strconv.Itoa(i+1)
		if _, ok := r.cache[ip]; ok {
			t.Errorf("expected %s evicted but it's still present", ip)
		}
	}
	// Last 8 must be retained.
	for i := 24; i < 32; i++ {
		ip := "203.0.113." + strconv.Itoa(i+1)
		if _, ok := r.cache[ip]; !ok {
			t.Errorf("expected %s retained but it's missing", ip)
		}
	}
}

// TestGeoResolverSweepsExpired confirms that inserts opportunistically
// remove stale tail entries even when the LRU isn't full. Previously
// expired entries lived forever because the only "expiry" was the
// read-side time check, which never deleted.
func TestGeoResolverSweepsExpired(t *testing.T) {
	t0 := time.Now().UTC()
	clock := t0
	r := newTestResolver(64, func() time.Time { return clock })

	// Insert 3 entries that expire after 1 minute.
	for i := 0; i < 3; i++ {
		ip := "198.51.100." + strconv.Itoa(i+1)
		r.mu.Lock()
		r.putLocked(ip, geoEntry{Expiry: clock.Add(time.Minute)})
		r.mu.Unlock()
	}
	if got := r.lru.Len(); got != 3 {
		t.Fatalf("setup len = %d, want 3", got)
	}

	// Advance past expiry and insert one more entry. The sweep
	// should pick up the three stale ones.
	clock = t0.Add(2 * time.Minute)
	r.mu.Lock()
	r.putLocked("192.0.2.1", geoEntry{Expiry: clock.Add(24 * time.Hour)})
	r.mu.Unlock()

	if got := r.lru.Len(); got != 1 {
		t.Errorf("post-sweep lru = %d, want 1 (3 stale + 1 fresh, sweep clears the stale)", got)
	}
	if _, ok := r.cache["192.0.2.1"]; !ok {
		t.Error("fresh insert was not retained")
	}
}

// TestGeoResolverCachedPromotesLRU confirms that a cache hit moves
// the entry to the front of the LRU so frequently-rendered IPs
// aren't evicted by passing dashboard traffic.
func TestGeoResolverCachedPromotesLRU(t *testing.T) {
	now := time.Now().UTC()
	r := newTestResolver(4, func() time.Time { return now })

	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"} {
		r.mu.Lock()
		r.putLocked(ip, geoEntry{OK: true, Expiry: now.Add(time.Hour)})
		r.mu.Unlock()
	}
	// Touch 1.1.1.1 — it should hop to MRU.
	_ = r.cached("1.1.1.1")
	// Insert a 5th distinct IP — eviction should drop 2.2.2.2,
	// not 1.1.1.1 (which we just promoted).
	r.mu.Lock()
	r.putLocked("5.5.5.5", geoEntry{OK: true, Expiry: now.Add(time.Hour)})
	r.mu.Unlock()
	if _, ok := r.cache["1.1.1.1"]; !ok {
		t.Error("promoted entry 1.1.1.1 was evicted; LRU promotion is broken")
	}
	if _, ok := r.cache["2.2.2.2"]; ok {
		t.Error("oldest non-promoted entry 2.2.2.2 still present; LRU eviction is broken")
	}
}

// TestGeoResolverPutUpdatesInPlace confirms that re-putting a key
// updates the value without growing the cache size or leaking the
// previous list element.
func TestGeoResolverPutUpdatesInPlace(t *testing.T) {
	now := time.Now().UTC()
	r := newTestResolver(8, func() time.Time { return now })

	ip := "203.0.113.50"
	r.mu.Lock()
	r.putLocked(ip, geoEntry{Country: "AA", Expiry: now.Add(time.Hour)})
	r.mu.Unlock()
	r.mu.Lock()
	r.putLocked(ip, geoEntry{Country: "BB", Expiry: now.Add(time.Hour)})
	r.mu.Unlock()
	if got := r.lru.Len(); got != 1 {
		t.Errorf("lru len = %d, want 1 after in-place update", got)
	}
	if r.cache[ip].Country != "BB" {
		t.Errorf("country = %q, want BB (update did not stick)", r.cache[ip].Country)
	}
}
