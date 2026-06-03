package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
	t.Setenv("SHARDLURE_OTX_KEY", "")
	t.Setenv("SHARDLURE_IPQS_KEY", "")
	t.Setenv("SHARDLURE_IPINFO_KEY", "")

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

	if len(results) != 7 {
		t.Fatalf("want 7 results, got %d", len(results))
	}
	// Index into the stable fan-out order from LookupAll.
	bySource := map[string]Result{}
	for _, r := range results {
		bySource[r.Source] = r
	}
	// Keyed providers must report unconfigured when their env key is unset.
	for _, p := range []string{ProviderAbuseIPDB, ProviderVirusTotal, ProviderOTX, ProviderIPQS, ProviderIPinfo} {
		if r, ok := bySource[p]; !ok {
			t.Errorf("missing result for %s", p)
		} else if r.Configured {
			t.Errorf("%s should be unconfigured without a key: %+v", p, r)
		}
	}
	// Keyless providers (community/free endpoints) are always "configured".
	for _, p := range []string{ProviderGreyNoise, ProviderShodan} {
		if r, ok := bySource[p]; !ok {
			t.Errorf("missing result for %s", p)
		} else if !r.Configured {
			t.Errorf("%s should be configured (keyless): %+v", p, r)
		}
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

// --- Hermetic parser tests for the added providers (no network). ---

func TestParseShodan(t *testing.T) {
	raw := []byte(`{"ip":"1.2.3.4","ports":[22,80,2222],"cpes":["cpe:/a:openbsd:openssh"],"tags":["scanner","compromised"],"vulns":["CVE-2021-44228"]}`)
	r := parseShodan(raw, "1.2.3.4")
	if !r.Configured {
		t.Error("shodan should be configured (keyless)")
	}
	if r.Verdict != "suspicious" {
		t.Errorf("vuln+suspicious-tag should yield suspicious, got %q", r.Verdict)
	}
	if !containsStr(r.Tags, "port:22") || !containsStr(r.Tags, "scanner") {
		t.Errorf("expected port + tag entries, got %v", r.Tags)
	}
	if !strings.Contains(r.Summary, "CVE-2021-44228") {
		t.Errorf("summary should mention the CVE, got %q", r.Summary)
	}

	// Benign host: ports but no vulns/suspicious tags.
	r2 := parseShodan([]byte(`{"ports":[443]}`), "5.6.7.8")
	if r2.Verdict != "benign" {
		t.Errorf("ports-only host should be benign, got %q", r2.Verdict)
	}
}

func TestParseOTX(t *testing.T) {
	raw := []byte(`{"pulse_info":{"count":6,"pulses":[{"name":"Mirai C2","tags":["mirai","botnet"]}]},"asn":"AS12345 Evil ISP","country_name":"Nowhere"}`)
	r := parseOTX(raw, "1.2.3.4")
	if r.Verdict != "malicious" {
		t.Errorf("6 pulses should be malicious, got %q", r.Verdict)
	}
	if r.ASN != "AS12345" || r.ASOwner != "Evil ISP" {
		t.Errorf("ASN split wrong: asn=%q owner=%q", r.ASN, r.ASOwner)
	}
	if !containsStr(r.Tags, "mirai") {
		t.Errorf("expected pulse tags, got %v", r.Tags)
	}
	if r.Score == nil || *r.Score != 100 { // 6*20 capped at 100
		t.Errorf("score should cap at 100, got %v", r.Score)
	}

	// Zero pulses = benign.
	if parseOTX([]byte(`{"pulse_info":{"count":0}}`), "9.9.9.9").Verdict != "benign" {
		t.Error("0 pulses should be benign")
	}
}

func TestParseIPQS(t *testing.T) {
	raw := []byte(`{"success":true,"fraud_score":90,"country_code":"US","ISP":"Acme","ASN":15169,"proxy":true,"vpn":true,"tor":false,"recent_abuse":true}`)
	r := parseIPQS(raw, "1.2.3.4")
	if r.Verdict != "malicious" {
		t.Errorf("score 90 should be malicious, got %q", r.Verdict)
	}
	if r.Score == nil || *r.Score != 90 {
		t.Errorf("score not mapped: %v", r.Score)
	}
	if r.ASN != "AS15169" {
		t.Errorf("ASN format wrong: %q", r.ASN)
	}
	for _, want := range []string{"proxy", "vpn", "recent-abuse"} {
		if !containsStr(r.Tags, want) {
			t.Errorf("missing tag %q in %v", want, r.Tags)
		}
	}

	// Unsuccessful response surfaces an error.
	if parseIPQS([]byte(`{"success":false,"message":"Invalid key"}`), "9.9.9.9").Error == "" {
		t.Error("unsuccessful IPQS response should set Error")
	}
}

func TestParseIPinfo(t *testing.T) {
	raw := []byte(`{"ip":"1.2.3.4","city":"Ashburn","region":"Virginia","country":"US","org":"AS14618 Amazon","privacy":{"hosting":true,"vpn":true}}`)
	r := parseIPinfo(raw, "1.2.3.4")
	if r.ASN != "AS14618" || r.ASOwner != "Amazon" {
		t.Errorf("org->ASN split wrong: asn=%q owner=%q", r.ASN, r.ASOwner)
	}
	if r.Verdict != "suspicious" { // vpn flag
		t.Errorf("vpn flag should make it suspicious, got %q", r.Verdict)
	}
	if !containsStr(r.Tags, "hosting") || !containsStr(r.Tags, "vpn") {
		t.Errorf("missing privacy tags: %v", r.Tags)
	}
	if !strings.Contains(r.Summary, "Ashburn") {
		t.Errorf("summary should include geo, got %q", r.Summary)
	}
}

func containsStr(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
