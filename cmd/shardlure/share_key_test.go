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
