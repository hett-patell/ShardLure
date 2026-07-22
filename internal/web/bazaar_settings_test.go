package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
)

func TestValidateBazaarEndpoint(t *testing.T) {
	meta, ok := metaFor(settings.KeyBazaarEndpoint)
	if !ok {
		t.Fatal("bazaar.endpoint missing from settingsRegistry")
	}
	if msg := validateSetting(meta, "https://mb-api.abuse.ch/api/v1/"); msg != "" {
		t.Fatalf("valid endpoint rejected: %s", msg)
	}
	if msg := validateSetting(meta, "ftp://example.com"); msg == "" {
		t.Fatal("expected ftp endpoint to be rejected")
	}
}

func TestBazaarSettingsLive(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "bazaar-settings.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatalf("settings.Load: %v", err)
	}
	s := New(st, keys, "127.0.0.1:0", Options{
		BazaarEndpoint:      "https://default.example/api/v1/",
		BazaarTags:          []string{"shardlure", "honeypot"},
		BazaarMaxBytes:      32 << 20,
		BazaarFreshnessDays: 10,
	})

	save := func(key, value string) {
		body, _ := json.Marshal(map[string]string{"key": key, "value": value})
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/settings/save", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		s.handleSettingsSave(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("save %s=%q: %d %s", key, value, rec.Code, rec.Body.String())
		}
	}

	save(settings.KeyBazaarEndpoint, "https://custom.example/api/v1/")
	save(settings.KeyBazaarTags, "lab, honeypot")
	save(settings.KeyBazaarMaxBytes, "16777216")
	save(settings.KeyBazaarFreshnessDays, "7")

	if got := s.bazaarEndpointLive(); got != "https://custom.example/api/v1/" {
		t.Fatalf("endpoint live = %q", got)
	}
	if got := s.bazaarTagsLive(); len(got) != 2 || got[0] != "lab" || got[1] != "honeypot" {
		t.Fatalf("tags live = %#v", got)
	}
	if got := s.bazaarMaxBytesLive(); got != 16777216 {
		t.Fatalf("max bytes live = %d", got)
	}
	if got := s.bazaarFreshnessDaysLive(); got != 7 {
		t.Fatalf("freshness live = %d", got)
	}
}

func TestBazaarFreshnessSettingRejectsLooserPolicyAndPreservesSavedValue(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "bazaar-freshness-settings.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatalf("settings.Load: %v", err)
	}
	s := New(st, keys, "127.0.0.1:0", Options{BazaarFreshnessDays: 10})

	meta, ok := metaFor(settings.KeyBazaarFreshnessDays)
	if !ok {
		t.Fatal("bazaar.freshness_days missing from settingsRegistry")
	}
	if !meta.HasIntRange || meta.MinInt != 1 || meta.MaxInt != 10 {
		t.Errorf("freshness range = enabled:%v %d..%d, want 1..10", meta.HasIntRange, meta.MinInt, meta.MaxInt)
	}

	post := func(value string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"key": settings.KeyBazaarFreshnessDays, "value": value})
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/settings/save", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		s.handleSettingsSave(rec, r)
		return rec
	}

	if rec := post("10"); rec.Code != http.StatusOK {
		t.Fatalf("save freshness=10: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post("7"); rec.Code != http.StatusOK {
		t.Fatalf("save freshness=7: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post("11"); rec.Code != http.StatusBadRequest {
		t.Errorf("save freshness=11: got %d, want 400; body=%s", rec.Code, rec.Body.String())
	}

	stored, exists, err := st.GetAppSetting(settings.KeyBazaarFreshnessDays)
	if err != nil {
		t.Fatalf("GetAppSetting: %v", err)
	}
	if !exists || stored != "7" {
		t.Errorf("stored freshness = (%q, exists=%v), want (7, true)", stored, exists)
	}
	if got := s.bazaarFreshnessDaysLive(); got != 7 {
		t.Errorf("live freshness = %d, want preserved value 7", got)
	}
}
