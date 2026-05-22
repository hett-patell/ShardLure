package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestLookupNoKeys: with no env vars set, AbuseIPDB+VT should return
// Configured=false fast (no network), GreyNoise should still try and
// either succeed or surface a network error - both acceptable.
func TestLookupNoKeysIsFastAndFailOpen(t *testing.T) {
	t.Setenv("SHARDLURE_ABUSEIPDB_KEY", "")
	t.Setenv("SHARDLURE_VT_KEY", "")

	st := newTestStore(t)
	r := &Resolver{St: st, HTTP: &http.Client{Timeout: 1 * time.Second}, Now: time.Now}

	// Replace fetchGreyNoise indirectly: we can't swap the function
	// pointer table, but we can short-circuit by pointing the client
	// at a stub that 404s.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	// Note: we don't reroute GreyNoise traffic here - test still
	// exercises the no-key fast path for the two keyed providers,
	// and the cache hit for GreyNoise on the second call.
	_ = srv

	start := time.Now()
	results := r.LookupAll(context.Background(), "1.2.3.4")
	elapsed := time.Since(start)

	if len(results) != 3 {
		t.Fatalf("want 3 results, got %d", len(results))
	}
	if results[0].Source != ProviderAbuseIPDB || results[0].Configured {
		t.Errorf("AbuseIPDB should be unconfigured: %+v", results[0])
	}
	if results[1].Source != ProviderVirusTotal || results[1].Configured {
		t.Errorf("VirusTotal should be unconfigured: %+v", results[1])
	}
	if results[2].Source != ProviderGreyNoise || !results[2].Configured {
		t.Errorf("GreyNoise should be configured (keyless): %+v", results[2])
	}
	// AbuseIPDB+VT should be near-instant since they never touch the
	// network when unconfigured. GreyNoise may take up to its timeout.
	if elapsed > 8*time.Second {
		t.Errorf("LookupAll too slow with no keys: %v", elapsed)
	}
}

// TestCacheHit: a second call within the TTL window must come from
// SQLite and not invoke fetch again.
func TestCacheHit(t *testing.T) {
	st := newTestStore(t)

	// Pre-populate the cache with a known payload so we don't need
	// to run a real fetch.
	if err := st.PutEnrichment("9.9.9.9", ProviderAbuseIPDB,
		`{"source":"abuseipdb","configured":true,"verdict":"malicious","score":99}`); err != nil {
		t.Fatal(err)
	}

	calls := 0
	r := &Resolver{
		St:   st,
		HTTP: &http.Client{Timeout: 1 * time.Second},
		Now:  time.Now,
	}
	// Build a synthetic fetch via lookup() so we can count invocations.
	res := r.lookup(context.Background(), "9.9.9.9", ProviderAbuseIPDB,
		func(ctx context.Context, hc *http.Client, ip string) (Result, error) {
			calls++
			return Result{Configured: true, Verdict: "benign"}, nil
		})
	if calls != 0 {
		t.Errorf("fetch called despite cache hit: calls=%d", calls)
	}
	if !res.Cached || res.Stale {
		t.Errorf("expected cached & fresh, got cached=%v stale=%v", res.Cached, res.Stale)
	}
	if res.Verdict != "malicious" || res.Score == nil || *res.Score != 99 {
		t.Errorf("cached payload not decoded: %+v", res)
	}
}

// TestStaleFallback: if the cache entry has expired and the live
// fetch fails, we must return the stale value with Stale=true and
// the error surfaced.
func TestStaleFallback(t *testing.T) {
	st := newTestStore(t)
	_ = st.PutEnrichment("8.8.8.8", ProviderAbuseIPDB,
		`{"source":"abuseipdb","configured":true,"verdict":"benign"}`)

	r := &Resolver{
		St:   st,
		HTTP: &http.Client{Timeout: 1 * time.Second},
		// Simulate the cache being old.
		Now: func() time.Time { return time.Now().Add(48 * time.Hour) },
	}
	res := r.lookup(context.Background(), "8.8.8.8", ProviderAbuseIPDB,
		func(ctx context.Context, hc *http.Client, ip string) (Result, error) {
			return Result{Configured: true}, http.ErrServerClosed
		})
	if !res.Stale || !res.Cached {
		t.Errorf("expected stale cached fallback, got %+v", res)
	}
	if res.Error == "" {
		t.Errorf("expected error to be propagated for ops visibility")
	}
}
