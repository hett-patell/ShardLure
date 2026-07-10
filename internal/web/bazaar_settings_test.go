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
