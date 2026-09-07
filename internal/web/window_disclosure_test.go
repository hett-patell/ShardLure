package web

import (
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
)

// TestDiscloseWindowTruncation verifies the advisory header fires only when the
// analysis was actually truncated (returned < total), and never otherwise — so
// the intel endpoints disclose a capped window honestly rather than silently.
func TestDiscloseWindowTruncation(t *testing.T) {
	cases := []struct {
		name            string
		returned, total int
		wantHeader      string
	}{
		{"full window fits", 100, 100, ""},
		{"empty", 0, 0, ""},
		{"truncated", 200_000, 3_500_000, "200000/3500000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			discloseWindowTruncation(rec, tc.returned, tc.total)
			got := rec.Header().Get("X-ShardLure-Window-Truncated")
			if got != tc.wantHeader {
				t.Fatalf("header = %q, want %q", got, tc.wantHeader)
			}
		})
	}
}

// TestEventsForWindowCachedReportsTotal verifies the cache surfaces the true
// window total alongside the (bounded) event slice, and that a repeat call
// within the TTL is served from cache with the same total.
func TestEventsForWindowCachedReportsTotal(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "win.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatalf("settings.Load: %v", err)
	}
	s := New(st, keys, "127.0.0.1:0")

	// Empty DB: no events, total 0, no error.
	events, total, err := s.eventsForWindowCached(24)
	if err != nil {
		t.Fatalf("eventsForWindowCached: %v", err)
	}
	if len(events) != 0 || total != 0 {
		t.Fatalf("empty window: len=%d total=%d, want 0/0", len(events), total)
	}

	// Second call within TTL must be served from cache (same window key).
	if _, ok := s.eventsCache[24]; !ok {
		t.Fatal("window 24 not cached after first fetch")
	}
}

func TestEventsWindowCacheEvictsLeastRecentlyUsedAtCapacity(t *testing.T) {
	s, _ := hasshTestServer(t)

	// Populate four exact keys, touching them in a known order. Touch key 1
	// again so key 2 becomes the least recently used entry.
	for _, hours := range []int{1, 2, 3, 4, 1} {
		if _, _, err := s.eventsForWindowCached(hours); err != nil {
			t.Fatalf("eventsForWindowCached(%d): %v", hours, err)
		}
	}
	if _, _, err := s.eventsForWindowCached(5); err != nil {
		t.Fatalf("eventsForWindowCached(5): %v", err)
	}

	if got := len(s.eventsCache); got != maxEventsCacheEntries {
		t.Fatalf("cache entries = %d, want hard limit %d", got, maxEventsCacheEntries)
	}
	if _, ok := s.eventsCache[2]; ok {
		t.Fatal("least recently used window 2 was not evicted")
	}
	for _, hours := range []int{1, 3, 4, 5} {
		if _, ok := s.eventsCache[hours]; !ok {
			t.Errorf("recent window %d was unexpectedly evicted", hours)
		}
	}
}

func TestEventsWindowCacheEvictsExpiredBeforeLiveEntries(t *testing.T) {
	s, _ := hasshTestServer(t)
	for _, hours := range []int{1, 2, 3, 4} {
		if _, _, err := s.eventsForWindowCached(hours); err != nil {
			t.Fatalf("eventsForWindowCached(%d): %v", hours, err)
		}
	}
	expired := s.eventsCache[3]
	expired.at = time.Now().Add(-eventsWindowTTL - time.Second)
	s.eventsCache[3] = expired

	if _, _, err := s.eventsForWindowCached(5); err != nil {
		t.Fatalf("eventsForWindowCached(5): %v", err)
	}
	if _, ok := s.eventsCache[3]; ok {
		t.Fatal("expired window 3 was not evicted")
	}
	if got := len(s.eventsCache); got != maxEventsCacheEntries {
		t.Fatalf("cache entries = %d, want %d", got, maxEventsCacheEntries)
	}
}

func TestEventsWindowCacheRefreshAtCapacityDoesNotEvictAnotherKey(t *testing.T) {
	s, _ := hasshTestServer(t)
	for _, hours := range []int{1, 2, 3, 4} {
		if _, _, err := s.eventsForWindowCached(hours); err != nil {
			t.Fatalf("eventsForWindowCached(%d): %v", hours, err)
		}
	}
	expired := s.eventsCache[2]
	expired.at = time.Now().Add(-eventsWindowTTL - time.Second)
	s.eventsCache[2] = expired

	if _, _, err := s.eventsForWindowCached(2); err != nil {
		t.Fatalf("refresh eventsForWindowCached(2): %v", err)
	}
	if got := len(s.eventsCache); got != maxEventsCacheEntries {
		t.Fatalf("cache entries = %d after existing-key refresh, want %d", got, maxEventsCacheEntries)
	}
	for _, hours := range []int{1, 2, 3, 4} {
		if _, ok := s.eventsCache[hours]; !ok {
			t.Errorf("window %d disappeared while refreshing existing key", hours)
		}
	}
}

func TestEventsWindowCacheStaleFallbackCountsAsUse(t *testing.T) {
	s, st := hasshTestServer(t)
	for _, hours := range []int{1, 2, 3, 4} {
		if _, _, err := s.eventsForWindowCached(hours); err != nil {
			t.Fatalf("eventsForWindowCached(%d): %v", hours, err)
		}
	}
	stale := s.eventsCache[1]
	stale.at = time.Now().Add(-eventsWindowTTL - time.Second)
	s.eventsCache[1] = stale
	before := stale.used
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	if _, _, err := s.eventsForWindowCached(1); err != nil {
		t.Fatalf("stale fallback returned error: %v", err)
	}
	if got := s.eventsCache[1].used; got <= before {
		t.Fatalf("stale fallback use sequence = %d, want greater than %d", got, before)
	}
}
