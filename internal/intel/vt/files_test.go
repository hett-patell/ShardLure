package vt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const goodSHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestIsSHA256(t *testing.T) {
	cases := map[string]bool{
		goodSHA:                  true,
		strings.ToUpper(goodSHA): true,
		"abc":                    false,
		"":                       false,
		goodSHA[:63]:             false,
		goodSHA + "a":            false,
		strings.Repeat("z", 64):  false,
		"../../etc/passwd":       false,
		goodSHA[:62] + "/x":      false,
	}
	for in, want := range cases {
		if got := isSHA256(in); got != want {
			t.Errorf("isSHA256(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseFileReportVerdictBuckets(t *testing.T) {
	mk := func(mal, susp, harm, undet int) []byte {
		body := map[string]any{
			"data": map[string]any{
				"attributes": map[string]any{
					"last_analysis_stats": map[string]int{
						"malicious": mal, "suspicious": susp,
						"harmless": harm, "undetected": undet,
					},
				},
			},
		}
		raw, _ := json.Marshal(body)
		return raw
	}
	cases := []struct {
		name                   string
		mal, susp, harm, undet int
		want                   string
	}{
		{"clearly malicious", 40, 2, 0, 20, "malicious"},
		{"exactly at threshold", 3, 0, 10, 50, "malicious"},
		{"one engine only", 1, 0, 10, 50, "suspicious"},
		{"two suspicious", 0, 2, 10, 50, "suspicious"},
		{"clean", 0, 0, 60, 10, "benign"},
		{"no engines", 0, 0, 0, 0, "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := ParseFileReport(mk(c.mal, c.susp, c.harm, c.undet), goodSHA)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if v.Verdict != c.want {
				t.Errorf("verdict = %q, want %q", v.Verdict, c.want)
			}
			if !v.Found {
				t.Error("Found should be true for a parsed report")
			}
			if v.Permalink == "" || !strings.Contains(v.Permalink, goodSHA) {
				t.Errorf("permalink = %q", v.Permalink)
			}
		})
	}
}

func TestParseFileReportRichFields(t *testing.T) {
	raw := []byte(`{"data":{"attributes":{
		"last_analysis_stats":{"malicious":42,"suspicious":1,"harmless":0,"undetected":18},
		"meaningful_name":"x86","type_description":"ELF",
		"reputation":-12,"times_submitted":57,
		"first_submission_date":1700000000,"last_analysis_date":1750000000,
		"popular_threat_classification":{"suggested_threat_label":"trojan.mirai/gafgyt"}}}}`)
	v, err := ParseFileReport(raw, goodSHA)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if v.ThreatLabel != "trojan.mirai/gafgyt" {
		t.Errorf("threat label = %q", v.ThreatLabel)
	}
	if v.TypeDescription != "ELF" || v.MeaningfulName != "x86" {
		t.Errorf("type/name = %q/%q", v.TypeDescription, v.MeaningfulName)
	}
	if v.Reputation != -12 || v.TimesSubmitted != 57 {
		t.Errorf("reputation=%d times=%d", v.Reputation, v.TimesSubmitted)
	}
	if v.FirstSeen == nil || v.LastAnalysis == nil {
		t.Error("expected both VT timestamps to be populated")
	}
	if v.TotalEngine != 61 {
		t.Errorf("total engines = %d, want 61", v.TotalEngine)
	}
}

func TestLookupNotFoundIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	v, err := NewClient(srv.URL).Lookup(context.Background(), "k", goodSHA)
	if err != nil {
		t.Fatalf("404 should not be an error: %v", err)
	}
	if v.Found {
		t.Error("Found should be false")
	}
	if v.Verdict != "unknown" {
		t.Errorf("verdict = %q, want unknown", v.Verdict)
	}
}

func TestLookupErrorMapping(t *testing.T) {
	cases := []struct {
		code int
		want error
	}{
		{http.StatusUnauthorized, ErrUnauthorized},
		{http.StatusForbidden, ErrUnauthorized},
		{http.StatusTooManyRequests, ErrRateLimited},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.code)
		}))
		_, err := NewClient(srv.URL).Lookup(context.Background(), "k", goodSHA)
		if !errors.Is(err, c.want) {
			t.Errorf("HTTP %d -> err %v, want %v", c.code, err, c.want)
		}
		srv.Close()
	}
}

func TestLookupValidatesInputs(t *testing.T) {
	c := NewClient("")
	if _, err := c.Lookup(context.Background(), "k", "not-a-hash"); !errors.Is(err, ErrBadHash) {
		t.Errorf("err = %v, want ErrBadHash", err)
	}
	if _, err := c.Lookup(context.Background(), "", goodSHA); !errors.Is(err, ErrMissingAPIKey) {
		t.Errorf("err = %v, want ErrMissingAPIKey", err)
	}
}

func TestLookupSendsAPIKeyHeaderAndHashPath(t *testing.T) {
	var gotKey, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-apikey")
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":5}}}}`))
	}))
	defer srv.Close()

	if _, err := NewClient(srv.URL).Lookup(context.Background(), "secret-key", goodSHA); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if gotKey != "secret-key" {
		t.Errorf("x-apikey = %q", gotKey)
	}
	if !strings.HasSuffix(gotPath, goodSHA) {
		t.Errorf("path = %q, want suffix %q", gotPath, goodSHA)
	}
}

func TestExpiredUsesShorterTTLForNotFound(t *testing.T) {
	now := time.Now()
	found := Verdict{Found: true, FetchedAt: now.Add(-20 * 24 * time.Hour)}
	if Expired(found, now) {
		t.Error("a 20-day-old found verdict should still be fresh (30d TTL)")
	}
	notFound := Verdict{Found: false, FetchedAt: now.Add(-20 * 24 * time.Hour)}
	if !Expired(notFound, now) {
		t.Error("a 20-day-old not-found verdict should be expired (7d TTL)")
	}
	if Expired(Verdict{Found: false, FetchedAt: now.Add(-1 * time.Hour)}, now) {
		t.Error("a 1-hour-old not-found verdict should be fresh")
	}
}

// ---- resolver (cache-then-fetch) ----------------------------------------

type memCache struct {
	mu   sync.Mutex
	rows map[string]string
	at   map[string]time.Time
}

func newMemCache() *memCache {
	return &memCache{rows: map[string]string{}, at: map[string]time.Time{}}
}

func (m *memCache) GetPayloadIntel(sha, source string) (string, time.Time, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.rows[sha+"|"+source]
	return p, m.at[sha+"|"+source], ok, nil
}

func (m *memCache) PutPayloadIntel(sha, source, payload string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[sha+"|"+source] = payload
	m.at[sha+"|"+source] = time.Now()
	return nil
}

type mapKeys map[string]string

func (k mapKeys) Get(key string) string { return k[key] }

func TestResolverCachesAndAvoidsSecondCall(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":9,"undetected":50}}}}`))
	}))
	defer srv.Close()

	r := NewResolver(newMemCache(), mapKeys{KeyEnvVar: "k"}, srv.URL)
	v1, err := r.Lookup(context.Background(), goodSHA)
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if v1.Verdict != "malicious" || v1.Cached {
		t.Errorf("first lookup = %+v, want fresh malicious", v1)
	}
	v2, err := r.Lookup(context.Background(), goodSHA)
	if err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if !v2.Cached {
		t.Error("second lookup should be served from cache")
	}
	if calls != 1 {
		t.Errorf("upstream calls = %d, want 1 (quota is ~4/min)", calls)
	}
}

// A transient failure must not blank out a verdict the analyst already had,
// and must not be written to the cache.
func TestResolverFallsBackToStaleOnError(t *testing.T) {
	cache := newMemCache()
	// Seed a stale verdict.
	stale := Verdict{SHA256: goodSHA, Found: true, Verdict: "malicious",
		FetchedAt: time.Now().Add(-100 * 24 * time.Hour)}
	raw, _ := json.Marshal(stale)
	_ = cache.PutPayloadIntel(goodSHA, Source, string(raw))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	r := NewResolver(cache, mapKeys{KeyEnvVar: "k"}, srv.URL)
	v, err := r.Lookup(context.Background(), goodSHA)
	if err != nil {
		t.Fatalf("should fall back to stale, got error: %v", err)
	}
	if v.Verdict != "malicious" || !v.Cached {
		t.Errorf("got %+v, want the stale cached malicious verdict", v)
	}
}

func TestResolverRateLimitNotCached(t *testing.T) {
	cache := newMemCache()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	r := NewResolver(cache, mapKeys{KeyEnvVar: "k"}, srv.URL)
	if _, err := r.Lookup(context.Background(), goodSHA); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	if _, _, found, _ := cache.GetPayloadIntel(goodSHA, Source); found {
		t.Error("a rate-limit response must never be cached")
	}
}

func TestResolverRequiresKey(t *testing.T) {
	r := NewResolver(newMemCache(), mapKeys{}, "")
	if r.Configured() {
		t.Error("no key should report unconfigured")
	}
	if _, err := r.Lookup(context.Background(), goodSHA); !errors.Is(err, ErrMissingAPIKey) {
		t.Errorf("err = %v, want ErrMissingAPIKey", err)
	}
}

// Two analysts opening the same payload must cost ONE API call.
func TestResolverCollapsesConcurrentLookups(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		time.Sleep(60 * time.Millisecond) // widen the race window
		_, _ = w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":7,"undetected":40}}}}`))
	}))
	defer srv.Close()

	r := NewResolver(newMemCache(), mapKeys{KeyEnvVar: "k"}, srv.URL)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Lookup(context.Background(), goodSHA); err != nil {
				t.Errorf("concurrent lookup: %v", err)
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("upstream calls = %d, want 1 (single-flight)", calls)
	}
}

func TestResolverCachedNeverHitsNetwork(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Cached() must never make a request")
	}))
	defer srv.Close()

	r := NewResolver(newMemCache(), mapKeys{KeyEnvVar: "k"}, srv.URL)
	if _, ok := r.Cached(goodSHA); ok {
		t.Error("empty cache should miss")
	}
}

// omitempty does NOT omit a zero time.Time (it's a struct), which made the API
// emit "0001-01-01T00:00:00Z" for samples VT had no dates for. The fields are
// pointers so absent dates are genuinely absent from the JSON.
func TestVerdictOmitsAbsentTimestamps(t *testing.T) {
	// A report with no date fields at all.
	v, err := ParseFileReport([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":1}}}}`), goodSHA)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(raw)
	for _, forbidden := range []string{"0001-01-01", "first_seen", "last_analysis"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("absent timestamp leaked %q into JSON: %s", forbidden, body)
		}
	}

	// And when VT DOES report them, they are present and correct.
	withDates, err := ParseFileReport([]byte(`{"data":{"attributes":{
		"last_analysis_stats":{"malicious":1},
		"first_submission_date":1700000000,"last_analysis_date":1750000000}}}`), goodSHA)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if withDates.FirstSeen == nil || withDates.LastAnalysis == nil {
		t.Fatal("expected both timestamps to be set")
	}
	if withDates.FirstSeen.Unix() != 1700000000 {
		t.Errorf("first_seen = %v", withDates.FirstSeen)
	}
	raw2, _ := json.Marshal(withDates)
	if !strings.Contains(string(raw2), "first_seen") {
		t.Errorf("present timestamp missing from JSON: %s", raw2)
	}
}
