package main

import (
	"path/filepath"
	"testing"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
)

func newKeystore(t *testing.T, kv map[string]string) *settings.Keystore {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "keys.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	k, err := settings.Load(st)
	if err != nil {
		t.Fatalf("settings.Load: %v", err)
	}
	for key, v := range kv {
		if err := k.Set(key, v); err != nil {
			t.Fatalf("set %s: %v", key, err)
		}
	}
	return k
}

// The bug this guards: the CLI used to read the Auth-Key from config/env only.
// On a deployment where the operator saved the key in the dashboard Settings
// panel it lives ONLY in app_settings (config is seeded INTO the keystore, never
// the reverse), so `share bazaar` / `share urlhaus` reported "no key" on exactly
// the deployments that had one.
func TestAbuseCHKeyPrefersKeystoreOverConfig(t *testing.T) {
	var cfg config.Config
	cfg.Intel.Bazaar.APIKey = "from-config"

	keys := newKeystore(t, map[string]string{settings.KeyBazaar: "from-db"})
	if got := abuseCHKey(cfg, keys); got != "from-db" {
		t.Errorf("abuseCHKey = %q, want the keystore value", got)
	}
	// Same key must reach URLhaus — one abuse.ch account, one Auth-Key.
	if got := urlhausAPIKey(cfg, keys); got != "from-db" {
		t.Errorf("urlhausAPIKey = %q, want the keystore value", got)
	}
}

func TestAbuseCHKeyFallsBackToConfigThenEmpty(t *testing.T) {
	var cfg config.Config
	cfg.Intel.Bazaar.APIKey = "from-config"
	empty := newKeystore(t, nil)

	if got := abuseCHKey(cfg, empty); got != "from-config" {
		t.Errorf("abuseCHKey = %q, want config fallback", got)
	}
	if got := urlhausAPIKey(cfg, empty); got != "from-config" {
		t.Errorf("urlhausAPIKey = %q, want config fallback", got)
	}

	var blank config.Config
	if got := abuseCHKey(blank, empty); got != "" {
		t.Errorf("abuseCHKey = %q, want empty", got)
	}
	// Nil keystore must not panic (CLI paths that run before settings load).
	if got := abuseCHKey(blank, nil); got != "" {
		t.Errorf("nil keystore: %q", got)
	}
}

// Both subcommands resolve the SAME key by default; the urlhaus-specific
// override exists only so an operator can deliberately point them at
// different accounts.
func TestBazaarAndURLhausShareOneKeyUnlessOverridden(t *testing.T) {
	var cfg config.Config
	keys := newKeystore(t, map[string]string{settings.KeyBazaar: "shared"})

	if abuseCHKey(cfg, keys) != urlhausAPIKey(cfg, keys) {
		t.Error("bazaar and urlhaus must resolve the same key by default")
	}

	cfg.Intel.URLhaus.APIKey = "urlhaus-only"
	if got := urlhausAPIKey(cfg, keys); got != "urlhaus-only" {
		t.Errorf("explicit urlhaus override ignored: %q", got)
	}
	if got := abuseCHKey(cfg, keys); got != "shared" {
		t.Errorf("urlhaus override must not affect bazaar: %q", got)
	}
}

func TestAbuseCHKeyHonoursAltKeyName(t *testing.T) {
	var cfg config.Config
	keys := newKeystore(t, map[string]string{settings.KeyBazaarAlt: "alt"})
	if got := abuseCHKey(cfg, keys); got != "alt" {
		t.Errorf("abuseCHKey = %q, want alt", got)
	}
	if got := urlhausAPIKey(cfg, keys); got != "alt" {
		t.Errorf("urlhausAPIKey = %q, want alt", got)
	}
}

// ---- AbuseIPDB settings resolution ---------------------------------------

// The CLI and the dashboard were reading DIFFERENT sources for the same
// AbuseIPDB settings. An operator who configured everything from the Settings
// panel got a CLI that refused to run, could not find the key, and would have
// used the config's categories/comment/thresholds instead of the live ones.
func TestResolveAbuseSettingsPrefersKeystore(t *testing.T) {
	var cfg config.Config
	cfg.Intel.AbuseIPDB.ReportEnabled = false
	cfg.Intel.AbuseIPDB.MinProbeScore = 60
	cfg.Intel.AbuseIPDB.RewindowHours = 24
	cfg.Intel.AbuseIPDB.Categories = []int{18, 22}
	cfg.Intel.AbuseIPDB.Comment = "from-config"

	keys := newKeystore(t, map[string]string{
		settings.KeyAbuseIPDB:          "db-key",
		settings.KeyAbuseReportEnabled: "1",
		settings.KeyAbuseMinProbe:      "75",
		settings.KeyAbuseRewindowHours: "48",
		settings.KeyAbuseCategories:    "18,22,15",
		settings.KeyAbuseComment:       "from-db",
	})

	got := resolveAbuseSettings(cfg, keys)
	if got.APIKey != "db-key" {
		t.Errorf("APIKey = %q, want db-key", got.APIKey)
	}
	if !got.Enabled {
		t.Error("Enabled should be true from the keystore (config said false)")
	}
	if got.MinProbe != 75 {
		t.Errorf("MinProbe = %d, want 75", got.MinProbe)
	}
	if got.RewindowH != 48 {
		t.Errorf("RewindowH = %d, want 48", got.RewindowH)
	}
	if len(got.Categories) != 3 {
		t.Errorf("Categories = %v, want 3 entries from the keystore", got.Categories)
	}
	if got.Comment != "from-db" {
		t.Errorf("Comment = %q, want from-db", got.Comment)
	}
}

func TestResolveAbuseSettingsFallsBackToConfigAndDefaults(t *testing.T) {
	var cfg config.Config
	cfg.Intel.AbuseIPDB.ReportEnabled = true
	cfg.Intel.AbuseIPDB.Comment = "cfg-comment"
	empty := newKeystore(t, nil)

	got := resolveAbuseSettings(cfg, empty)
	if !got.Enabled || got.Comment != "cfg-comment" {
		t.Errorf("config values not honoured: %+v", got)
	}
	// Sane defaults when neither source specifies them.
	if got.MinProbe != 60 {
		t.Errorf("MinProbe = %d, want default 60", got.MinProbe)
	}
	if got.RewindowH != 24 {
		t.Errorf("RewindowH = %d, want default 24", got.RewindowH)
	}
	if len(got.Categories) != 2 || got.Categories[0] != 18 || got.Categories[1] != 22 {
		t.Errorf("Categories = %v, want default [18 22]", got.Categories)
	}
	// A nil keystore must not panic (parity with abuseCHKey).
	if got := resolveAbuseSettings(cfg, nil); got.MinProbe != 60 {
		t.Errorf("nil keystore: %+v", got)
	}
}

// Disabling from the Settings panel must disable the CLI too — the flag is a
// safety gate, so the two surfaces disagreeing is the dangerous direction.
func TestResolveAbuseSettingsKeystoreCanDisable(t *testing.T) {
	var cfg config.Config
	cfg.Intel.AbuseIPDB.ReportEnabled = true // config says on
	keys := newKeystore(t, map[string]string{settings.KeyAbuseReportEnabled: "0"})
	if resolveAbuseSettings(cfg, keys).Enabled {
		t.Error("keystore 'off' must win over config 'on'")
	}
}

// share bazaar must apply the bazaar knobs saved in the dashboard Settings
// panel, exactly as the server's bazaar*Live accessors do (keystore first,
// config second). It read config only, so an operator who tightened freshness
// in the dashboard got a CLI that uploaded what the panel called stale.
func TestResolveBazaarSettingsPrefersKeystore(t *testing.T) {
	var cfg config.Config
	cfg.Intel.Bazaar.Endpoint = "https://cfg.example/api/"
	cfg.Intel.Bazaar.Tags = []string{"cfg"}
	cfg.Intel.Bazaar.MaxBytes = 1 << 20
	cfg.Intel.Bazaar.FreshnessDays = 9
	keys := newKeystore(t, map[string]string{
		settings.KeyBazaarEndpoint:      "https://db.example/api/",
		settings.KeyBazaarTags:          "db1, db2",
		settings.KeyBazaarMaxBytes:      "2048",
		settings.KeyBazaarFreshnessDays: "3",
	})
	got := resolveBazaarSettings(cfg, keys)
	if got.Endpoint != "https://db.example/api/" {
		t.Errorf("Endpoint = %q, want the keystore value", got.Endpoint)
	}
	if len(got.Tags) != 2 || got.Tags[0] != "db1" || got.Tags[1] != "db2" {
		t.Errorf("Tags = %v, want [db1 db2]", got.Tags)
	}
	if got.MaxBytes != 2048 {
		t.Errorf("MaxBytes = %d, want 2048", got.MaxBytes)
	}
	if got.FreshnessDays != 3 {
		t.Errorf("FreshnessDays = %d, want 3", got.FreshnessDays)
	}
}

func TestResolveBazaarSettingsFallsBackToConfigAndDefaults(t *testing.T) {
	var cfg config.Config
	cfg.Intel.Bazaar.Endpoint = "https://cfg.example/api/"
	cfg.Intel.Bazaar.Tags = []string{"cfg"}
	cfg.Intel.Bazaar.FreshnessDays = 7
	got := resolveBazaarSettings(cfg, newKeystore(t, nil))
	if got.Endpoint != "https://cfg.example/api/" || len(got.Tags) != 1 || got.FreshnessDays != 7 {
		t.Errorf("config values not honoured: %+v", got)
	}
	if got.MaxBytes != 32<<20 {
		t.Errorf("MaxBytes = %d, want default 32 MiB", got.MaxBytes)
	}
	// Non-positive keystore values are ignored, as bazaarMaxBytesLive and
	// bazaarFreshnessDaysLive ignore them.
	bad := newKeystore(t, map[string]string{settings.KeyBazaarMaxBytes: "-5", settings.KeyBazaarFreshnessDays: "-1"})
	if got := resolveBazaarSettings(cfg, bad); got.MaxBytes != 32<<20 || got.FreshnessDays != 7 {
		t.Errorf("non-positive keystore values applied: %+v", got)
	}
	var empty config.Config
	if got := resolveBazaarSettings(empty, nil); got.FreshnessDays != 10 || got.MaxBytes != 32<<20 {
		t.Errorf("nil keystore / empty config: %+v, want 10 days and 32 MiB", got)
	}
}
