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

func TestValidateUITheme(t *testing.T) {
	meta, ok := metaFor(settings.KeyUITheme)
	if !ok {
		t.Fatal("ui.theme missing from settingsRegistry")
	}
	for _, good := range []string{"dragon", "meridian", "sprite"} {
		if msg := validateSetting(meta, good); msg != "" {
			t.Fatalf("%q rejected: %s", good, msg)
		}
	}
	if msg := validateSetting(meta, "neon"); msg == "" {
		t.Fatal("expected neon to be rejected")
	}
}

func TestSettingsSaveUITheme(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "theme.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatalf("settings.Load: %v", err)
	}
	s := New(st, keys, "127.0.0.1:0")

	save := func(value string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"key": settings.KeyUITheme, "value": value})
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/settings/save", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		s.handleSettingsSave(rec, r)
		return rec
	}

	rec := save("meridian")
	if rec.Code != 200 {
		t.Fatalf("save meridian: %d %s", rec.Code, rec.Body.String())
	}
	if got := keys.Get(settings.KeyUITheme); got != "meridian" {
		t.Fatalf("keystore got %q", got)
	}

	rec = save("neon")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("save neon: want 400, got %d %s", rec.Code, rec.Body.String())
	}
	if got := keys.Get(settings.KeyUITheme); got != "meridian" {
		t.Fatalf("rejected save mutated keystore to %q", got)
	}

	rec = save("sprite")
	if rec.Code != 200 {
		t.Fatalf("save sprite: %d %s", rec.Code, rec.Body.String())
	}

	// GET snapshot includes value
	rec = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	s.handleSettings(rec, r)
	if rec.Code != 200 {
		t.Fatalf("GET settings: %d", rec.Code)
	}
	var snap struct {
		Settings []settingRow `json:"settings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range snap.Settings {
		if row.Key == settings.KeyUITheme {
			found = true
			if row.Value != "sprite" {
				t.Fatalf("snapshot value %q", row.Value)
			}
			if row.Kind != "text" {
				t.Fatalf("kind %q", row.Kind)
			}
		}
	}
	if !found {
		t.Fatal("ui.theme missing from snapshot")
	}

	// empty clears
	rec = save("")
	if rec.Code != 200 {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body.String())
	}
	if keys.Has(settings.KeyUITheme) {
		t.Fatal("expected ui.theme cleared")
	}
}
