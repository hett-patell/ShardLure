package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/intel/vt"
	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
)

const vtTestSHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// newIntelTestServer builds a Server with a real store + keystore and no
// dashboard token (so guard() lets requests through in open mode).
func newIntelTestServer(t *testing.T, kv map[string]string) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "intel.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatalf("settings.Load: %v", err)
	}
	for k, v := range kv {
		if err := keys.Set(k, v); err != nil {
			t.Fatalf("keys.Set(%s): %v", k, err)
		}
	}
	return &Server{st: st, keys: keys}
}

func TestHandleIntelPayloadVTRequiresSHA(t *testing.T) {
	s := newIntelTestServer(t, nil)
	w := httptest.NewRecorder()
	s.handleIntelPayloadVT(w, httptest.NewRequest(http.MethodGet, "/api/intel/payload/vt", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", w.Code)
	}
}

// With no key configured the endpoint must report that in-band (HTTP 200 with
// configured=false), so the panel can prompt instead of showing a broken widget.
func TestHandleIntelPayloadVTUnconfigured(t *testing.T) {
	s := newIntelTestServer(t, nil)
	w := httptest.NewRecorder()
	s.handleIntelPayloadVT(w, httptest.NewRequest(http.MethodGet,
		"/api/intel/payload/vt?sha="+vtTestSHA, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", w.Code)
	}
	var out vtVerdictResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Configured {
		t.Error("configured should be false with no key")
	}
	if out.Error == "" {
		t.Error("expected an explanatory error string")
	}
	if out.Verdict != nil {
		t.Error("no verdict should be returned")
	}
}

// cache=1 must never spend quota, even with a key configured.
func TestHandleIntelPayloadVTCacheOnlyNeverCallsUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("cache=1 must not reach VirusTotal")
	}))
	defer upstream.Close()

	s := newIntelTestServer(t, map[string]string{settings.KeyVT: "k"})
	s.vtEndpoint = upstream.URL

	w := httptest.NewRecorder()
	s.handleIntelPayloadVT(w, httptest.NewRequest(http.MethodGet,
		"/api/intel/payload/vt?cache=1&sha="+vtTestSHA, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	var out vtVerdictResponse
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Verdict != nil {
		t.Error("empty cache should yield no verdict")
	}
	if !out.Configured {
		t.Error("configured should be true (key present)")
	}
}

func TestHandleIntelPayloadVTLiveLookupAndCaching(t *testing.T) {
	var calls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"data":{"attributes":{
			"last_analysis_stats":{"malicious":38,"suspicious":0,"harmless":0,"undetected":22},
			"type_description":"ELF","meaningful_name":"x86",
			"popular_threat_classification":{"suggested_threat_label":"trojan.mirai/gafgyt"}}}}`))
	}))
	defer upstream.Close()

	s := newIntelTestServer(t, map[string]string{settings.KeyVT: "k"})
	s.vtEndpoint = upstream.URL

	do := func() vtVerdictResponse {
		w := httptest.NewRecorder()
		s.handleIntelPayloadVT(w, httptest.NewRequest(http.MethodGet,
			"/api/intel/payload/vt?sha="+vtTestSHA, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("code = %d: %s", w.Code, w.Body.String())
		}
		var out vtVerdictResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	first := do()
	if first.Verdict == nil {
		t.Fatalf("expected a verdict, got error %q", first.Error)
	}
	if first.Verdict.Verdict != "malicious" {
		t.Errorf("verdict = %q, want malicious", first.Verdict.Verdict)
	}
	if first.Verdict.ThreatLabel != "trojan.mirai/gafgyt" {
		t.Errorf("threat label = %q", first.Verdict.ThreatLabel)
	}

	// Second call is served from the store cache — quota is ~4/min.
	second := do()
	if second.Verdict == nil || !second.Verdict.Cached {
		t.Errorf("second call should be cached, got %+v", second.Verdict)
	}
	if calls != 1 {
		t.Errorf("upstream calls = %d, want 1", calls)
	}

	// And the bulk cache-only endpoint now sees it.
	w := httptest.NewRecorder()
	s.handleIntelPayloadsVTCached(w, httptest.NewRequest(http.MethodGet,
		"/api/intel/payloads/vt/cached?shas="+vtTestSHA+",deadbeef", nil))
	var bulk vtBulkResponse
	if err := json.Unmarshal(w.Body.Bytes(), &bulk); err != nil {
		t.Fatalf("decode bulk: %v", err)
	}
	if len(bulk.Verdicts) != 1 {
		t.Fatalf("bulk verdicts = %d, want 1", len(bulk.Verdicts))
	}
	got, ok := bulk.Verdicts[vtTestSHA]
	if !ok {
		t.Fatal("expected the cached sha in the bulk response")
	}
	if got.Verdict != "malicious" || !got.Cached {
		t.Errorf("bulk entry = %+v", got)
	}
	if calls != 1 {
		t.Errorf("bulk endpoint must not call upstream; calls = %d", calls)
	}
}

func TestHandleIntelPayloadsVTCachedEmptyRequest(t *testing.T) {
	s := newIntelTestServer(t, nil)
	w := httptest.NewRecorder()
	s.handleIntelPayloadsVTCached(w, httptest.NewRequest(http.MethodGet,
		"/api/intel/payloads/vt/cached", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	var out vtBulkResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Verdicts) != 0 {
		t.Errorf("verdicts = %v, want empty", out.Verdicts)
	}
}

// A rate-limit must surface as an in-band message, not a 5xx.
func TestHandleIntelPayloadVTRateLimitIsInBand(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer upstream.Close()

	s := newIntelTestServer(t, map[string]string{settings.KeyVT: "k"})
	s.vtEndpoint = upstream.URL

	w := httptest.NewRecorder()
	s.handleIntelPayloadVT(w, httptest.NewRequest(http.MethodGet,
		"/api/intel/payload/vt?sha="+vtTestSHA, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (in-band error)", w.Code)
	}
	var out vtVerdictResponse
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Error == "" {
		t.Error("expected a rate-limit message")
	}
	if out.Verdict != nil {
		t.Error("no verdict on rate limit with an empty cache")
	}
}

func TestHandleIntelURLhausReportsStateAndKeySharing(t *testing.T) {
	s := newIntelTestServer(t, nil)

	// Seed an eligible artifact and one submission.
	now := time.Now().UTC()
	if err := s.st.RecordArtifact(store.Artifact{
		TS: now.Add(-time.Hour), URL: "http://evil.tld/x86", Origin: "quarantine_fetch",
		Status: "fetched", SHA256: "aa", SizeBytes: 4096, LocalPath: "/tmp/x",
	}); err != nil {
		t.Fatalf("record artifact: %v", err)
	}
	if err := s.st.RecordURLhausSubmission("http://old.tld/a", "ok", now.Add(-2*time.Hour)); err != nil {
		t.Fatalf("record submission: %v", err)
	}

	get := func() urlhausResponse {
		w := httptest.NewRecorder()
		s.handleIntelURLhaus(w, httptest.NewRequest(http.MethodGet, "/api/intel/urlhaus", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("code = %d: %s", w.Code, w.Body.String())
		}
		var out urlhausResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	out := get()
	if out.Configured {
		t.Error("no abuse.ch key yet -> configured should be false")
	}
	if out.TotalSubmitted != 1 {
		t.Errorf("totalSubmitted = %d, want 1", out.TotalSubmitted)
	}
	if out.Pending != 1 {
		t.Errorf("pending = %d, want 1", out.Pending)
	}
	if len(out.Rows) != 1 || out.Rows[0].URL != "http://old.tld/a" {
		t.Errorf("rows = %+v", out.Rows)
	}

	// The MalwareBazaar key doubles as the URLhaus key (one abuse.ch account).
	if err := s.keys.Set(settings.KeyBazaar, "abusech-key"); err != nil {
		t.Fatalf("set bazaar key: %v", err)
	}
	if out := get(); !out.Configured {
		t.Error("the bazaar key should make URLhaus report configured")
	}
}

// Verdict JSON field names are BOTH the dashboard API contract and the
// on-disk cache format. They are camelCase to match every other endpoint; a
// rename silently zeroes cached rows (Resolver.Cached self-heals that, but the
// contract should still be pinned).
func TestVerdictJSONFieldNamesAreStable(t *testing.T) {
	raw, err := json.Marshal(vt.Verdict{SHA256: "aa", Found: true, Verdict: "malicious", Malicious: 3})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"sha256", "found", "verdict", "malicious", "totalEngines", "fetchedAt"} {
		if _, ok := m[key]; !ok {
			t.Errorf("missing expected JSON key %q in %s", key, raw)
		}
	}
}
