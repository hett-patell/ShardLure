package web

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func hasshTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "hassh.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatalf("settings.Load: %v", err)
	}
	return New(st, keys, "127.0.0.1:0"), st
}

func addCowrieEvent(t *testing.T, st *store.Store, hassh string) {
	t.Helper()
	if err := st.InsertEvent(&models.Event{
		TS: time.Now().UTC(), Source: models.SourceCowrie, Kind: models.KindFailedPass,
		SrcIP: "10.1.1.1", Username: "root", ActorID: "cowrie:10.1.1.1", HASSH: hassh,
	}); err != nil {
		t.Fatalf("InsertEvent: %v", err)
	}
}

// HASSHCoverage is an unbounded COUNT + SUM over every cowrie event ever
// ingested — 1.28s of the 2.0s of SQL behind /api/dashboard on a 1M-row
// production database, and the single largest contributor to a 4.6s response
// on each 10s cache expiry. It reports a LIFETIME ratio that moves by fractions
// of a percent per hour, so it does not belong on the 10s statsTTL.
func TestHASSHCoverageIsMemoizedBeyondStatsTTL(t *testing.T) {
	s, st := hasshTestServer(t)
	addCowrieEvent(t, st, "aa:bb")
	addCowrieEvent(t, st, "")

	f, total := s.hasshCoverageCached()
	if f != 1 || total != 2 {
		t.Fatalf("first call = (%d, %d), want (1, 2)", f, total)
	}

	// New telemetry arrives. Within the coverage TTL the memo must hold — that
	// is the whole point: no second whole-table scan.
	addCowrieEvent(t, st, "cc:dd")
	addCowrieEvent(t, st, "")
	if f, total = s.hasshCoverageCached(); f != 1 || total != 2 {
		t.Fatalf("within TTL = (%d, %d), want the memoized (1, 2)", f, total)
	}

	// The TTL must be long enough that a statsTTL-length gap does NOT refresh
	// it, otherwise the fix does nothing for the 5s dashboard poll.
	if hasshCoverageTTL <= statsTTL {
		t.Fatalf("hasshCoverageTTL (%s) must exceed statsTTL (%s)", hasshCoverageTTL, statsTTL)
	}
}

// It is a cache, not a freeze: once the TTL lapses the figure must catch up,
// or the dashboard would report a stale coverage ratio forever.
func TestHASSHCoverageRefreshesAfterTTL(t *testing.T) {
	s, st := hasshTestServer(t)
	addCowrieEvent(t, st, "aa:bb")
	addCowrieEvent(t, st, "")
	if f, total := s.hasshCoverageCached(); f != 1 || total != 2 {
		t.Fatalf("first call = (%d, %d), want (1, 2)", f, total)
	}

	addCowrieEvent(t, st, "cc:dd")
	addCowrieEvent(t, st, "")
	s.hasshMu.Lock()
	s.hasshAt = time.Now().Add(-hasshCoverageTTL - time.Second)
	s.hasshMu.Unlock()

	if f, total := s.hasshCoverageCached(); f != 2 || total != 4 {
		t.Fatalf("after TTL = (%d, %d), want the refreshed (2, 4)", f, total)
	}
}

// The memoized figure must agree with the store — a cache that returns a
// different number than the query it stands in for is worse than no cache.
func TestHASSHCoverageMatchesStore(t *testing.T) {
	s, st := hasshTestServer(t)
	for i := 0; i < 3; i++ {
		addCowrieEvent(t, st, "aa:bb")
	}
	addCowrieEvent(t, st, "")

	wantF, wantT, err := st.HASSHCoverage()
	if err != nil {
		t.Fatalf("HASSHCoverage: %v", err)
	}
	if f, total := s.hasshCoverageCached(); f != wantF || total != wantT {
		t.Fatalf("cached = (%d, %d), store = (%d, %d)", f, total, wantF, wantT)
	}
}
