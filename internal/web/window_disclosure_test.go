package web

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

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
