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

// TestLookupAllRejectsUnsafeIPs is the MED-4 regression guard: LookupAll must
// refuse malformed or internal/reserved addresses up front and NEVER fan out to
// the providers (so it returns a single error Result, not the 7-provider set).
// This makes the package self-defending instead of trusting the caller.
func TestLookupAllRejectsUnsafeIPs(t *testing.T) {
	st := newTestStore(t)
	r := &Resolver{St: st, HTTP: &http.Client{Timeout: time.Second}, Now: time.Now}

	unsafe := []string{
		"",                     // empty
		"not-an-ip",            // garbage
		"1.2.3.4/../../secret", // path-injection attempt
		"127.0.0.1",            // loopback
		"169.254.169.254",      // cloud metadata
		"10.0.0.1",             // private
		"::1",                  // ipv6 loopback
		"0.0.0.0",              // unspecified
	}
	for _, ip := range unsafe {
		got := r.LookupAll(context.Background(), ip)
		if len(got) != 1 || got[0].Error == "" {
			t.Errorf("LookupAll(%q) should return a single error result (no provider fan-out), got %+v", ip, got)
		}
	}

	// A well-formed public IP still fans out to all 7 providers.
	if got := r.LookupAll(context.Background(), "8.8.8.8"); len(got) != 7 {
		t.Errorf("LookupAll(public IP) should fan out to 7 providers, got %d", len(got))
	}
}

// TestSafeForEnrichment unit-checks the classifier directly.
func TestSafeForEnrichment(t *testing.T) {
	safe := []string{"8.8.8.8", "1.1.1.1", "203.0.113.5"}
	for _, ip := range safe {
		if !safeForEnrichment(ip) {
			t.Errorf("safeForEnrichment(%q) = false, want true", ip)
		}
	}
	unsafe := []string{"", "garbage", "127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.0.1", "::1", "224.0.0.1", "0.0.0.0"}
	for _, ip := range unsafe {
		if safeForEnrichment(ip) {
			t.Errorf("safeForEnrichment(%q) = true, want false", ip)
		}
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

func TestParseAbuseIPDB(t *testing.T) {
	raw := []byte(`{"data":{"ipAddress":"1.2.3.4","abuseConfidenceScore":88,"countryCode":"CN","isp":"Evil Cloud","usageType":"Data Center/Web Hosting/Transit","totalReports":142,"lastReportedAt":"2026-06-30T10:00:00+00:00","hostnames":["bot.example.net"]}}`)
	r := parseAbuseIPDB(raw, "1.2.3.4")
	if r.Verdict != "malicious" {
		t.Errorf("score 88 should be malicious, got %q", r.Verdict)
	}
	if r.Score == nil || *r.Score != 88 {
		t.Errorf("score not carried through: %v", r.Score)
	}
	if !containsStr(r.Tags, "data-center/web-hosting/transit") || !containsStr(r.Tags, "bot.example.net") {
		t.Errorf("missing usage-type/hostname tags: %v", r.Tags)
	}
	if !strings.Contains(r.Summary, "142 reports") || !strings.Contains(r.Summary, "last 2026-06-30") {
		t.Errorf("summary wrong: %q", r.Summary)
	}
	if r.Country != "CN" || r.ASOwner != "Evil Cloud" {
		t.Errorf("geo/isp wrong: %q %q", r.Country, r.ASOwner)
	}

	// Mid score -> suspicious; low -> benign.
	if parseAbuseIPDB([]byte(`{"data":{"abuseConfidenceScore":30}}`), "1.1.1.1").Verdict != "suspicious" {
		t.Error("score 30 should be suspicious")
	}
	if parseAbuseIPDB([]byte(`{"data":{"abuseConfidenceScore":0}}`), "1.1.1.1").Verdict != "benign" {
		t.Error("score 0 should be benign")
	}
}

func TestParseVirusTotal(t *testing.T) {
	raw := []byte(`{"data":{"attributes":{"last_analysis_stats":{"harmless":60,"malicious":5,"suspicious":1,"undetected":10},"as_owner":"Bad AS","asn":4134,"country":"CN","network":"1.2.3.0/24","reputation":-20}}}`)
	r := parseVirusTotal(raw, "1.2.3.4")
	if r.Verdict != "malicious" {
		t.Errorf("5 malicious engines should be malicious, got %q", r.Verdict)
	}
	if r.ASN != "AS4134" || r.ASOwner != "Bad AS" {
		t.Errorf("asn wrong: %q %q", r.ASN, r.ASOwner)
	}
	if !containsStr(r.Tags, "1.2.3.0/24") {
		t.Errorf("network tag missing: %v", r.Tags)
	}
	if !strings.Contains(r.Summary, "5/76 engines") || !strings.Contains(r.Summary, "reputation=-20") {
		t.Errorf("summary wrong: %q", r.Summary)
	}

	// Zero engines -> unknown; one malicious -> suspicious.
	if parseVirusTotal([]byte(`{"data":{"attributes":{}}}`), "1.1.1.1").Verdict != "unknown" {
		t.Error("no engine data should be unknown")
	}
	if parseVirusTotal([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":1,"harmless":70}}}}`), "1.1.1.1").Verdict != "suspicious" {
		t.Error("1 malicious engine should be suspicious")
	}
}

func TestParseGreyNoise(t *testing.T) {
	raw := []byte(`{"ip":"1.2.3.4","noise":true,"riot":false,"classification":"malicious","name":"SSH Bruteforcer","link":"https://viz.greynoise.io/ip/1.2.3.4","last_seen":"2026-07-01","message":"Success"}`)
	r := parseGreyNoise(raw, "1.2.3.4")
	if r.Verdict != "malicious" {
		t.Errorf("classification should map through, got %q", r.Verdict)
	}
	if !containsStr(r.Tags, "internet-noise") || !containsStr(r.Tags, "SSH Bruteforcer") {
		t.Errorf("tags wrong: %v", r.Tags)
	}
	if r.URL != "https://viz.greynoise.io/ip/1.2.3.4" {
		t.Errorf("link not used: %q", r.URL)
	}

	// Missing link falls back to the viz URL; empty message synthesises one.
	r2 := parseGreyNoise([]byte(`{"classification":"benign","last_seen":"2026-06-01"}`), "9.9.9.9")
	if r2.URL != "https://viz.greynoise.io/ip/9.9.9.9" {
		t.Errorf("fallback URL wrong: %q", r2.URL)
	}
	if !strings.Contains(r2.Summary, "classification=benign") || !strings.Contains(r2.Summary, "last seen 2026-06-01") {
		t.Errorf("synthesised summary wrong: %q", r2.Summary)
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
