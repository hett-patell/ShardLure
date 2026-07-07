// Package settings provides a mutable, concurrency-safe runtime keystore for
// the API keys and operator-tunable knobs the dashboard Settings panel edits
// live. Values persist in the SQLite app_settings table (a 0600 DB) and take
// effect WITHOUT a service restart.
//
// Precedence on read: a value SET in the DB wins; if unset, we fall back to the
// process environment (os.Getenv) so existing systemd/env deployments keep
// working unchanged. Saving a value writes the DB (the environment is never
// mutated); clearing a value removes the DB row, reverting to the env fallback.
//
// This package is a leaf: it imports only internal/store and the stdlib. It
// must never import internal/web or internal/intel/enrich, both of which depend
// (directly or via a local interface) on the Keystore.
package settings

import (
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/networkshard/shardlure/internal/store"
)

// Setting key names. Centralised here so web and enrich reference the same
// strings (no drift). Secret keys reuse the existing SHARDLURE_* env-var names
// so a DB value and an env value address the same setting; the non-secret
// knobs use dotted names that have no env equivalent today.
const (
	// Provider API keys (secrets) — names match the env vars read historically.
	KeyAbuseIPDB = "SHARDLURE_ABUSEIPDB_KEY"
	KeyVT        = "SHARDLURE_VT_KEY"
	KeyGreyNoise = "SHARDLURE_GREYNOISE_KEY"
	KeyOTX       = "SHARDLURE_OTX_KEY"
	KeyIPQS      = "SHARDLURE_IPQS_KEY"
	KeyIPinfo    = "SHARDLURE_IPINFO_KEY"
	KeyBazaar    = "SHARDLURE_BAZAAR_KEY"
	KeyBazaarAlt = "SHARDLURE_BAZAAR_API_KEY"
	KeyDashToken = "SHARDLURE_DASH_TOKEN"
	KeyIPAPI     = "SHARDLURE_IPAPI_KEY"

	// Geo behaviour flags (non-secret; historically env-only).
	KeyGeoHTTP     = "SHARDLURE_GEO_HTTP"
	KeyGeoInsecure = "SHARDLURE_GEO_INSECURE_HTTP"

	// AbuseIPDB reporting knobs (non-secret; stored as text, read via typed
	// getters). No env equivalent — these were config-file-only before.
	KeyAbuseReportEnabled = "abuseipdb.report_enabled"
	KeyAbuseMinProbe      = "abuseipdb.min_probe_score"
	KeyAbuseRewindowHours = "abuseipdb.rewindow_hours"
	KeyAbuseCategories    = "abuseipdb.categories" // CSV of ints
	KeyAbuseComment       = "abuseipdb.comment"

	// Globe / home origin (non-secret).
	KeyHomeLat     = "home.lat"
	KeyHomeLon     = "home.lon"
	KeyHomeCity    = "home.city"
	KeyHomeCountry = "home.country"
	KeyHomeCC      = "home.cc"
)

// hasEnvFallback reports whether a key participates in the os.Getenv fallback.
// Only the SHARDLURE_* secret/flag keys do; the dotted knob keys have no env
// equivalent, so a missing DB row for them means "use the caller's default",
// not "read a coincidentally-named env var".
func hasEnvFallback(key string) bool {
	return strings.HasPrefix(key, "SHARDLURE_")
}

// Keystore is the mutable runtime view of settings. Reads take an RLock; the
// rare Set/Clear takes the write lock. It is safe for concurrent use.
type Keystore struct {
	mu   sync.RWMutex
	st   *store.Store
	vals map[string]string // DB-sourced values, seeded at Load and kept in sync
}

// Load builds a Keystore seeded from the DB's app_settings rows.
func Load(st *store.Store) (*Keystore, error) {
	vals, err := st.AllAppSettings()
	if err != nil {
		return nil, err
	}
	if vals == nil {
		vals = map[string]string{}
	}
	return &Keystore{st: st, vals: vals}, nil
}

// Get returns the effective value for key: the DB value if a row exists, else
// the trimmed environment variable of the same name (for SHARDLURE_* keys),
// else "".
func (k *Keystore) Get(key string) string {
	k.mu.RLock()
	v, ok := k.vals[key]
	k.mu.RUnlock()
	if ok {
		return v
	}
	if hasEnvFallback(key) {
		return strings.TrimSpace(os.Getenv(key))
	}
	return ""
}

// GetOr returns Get(key) or def if the effective value is empty.
func (k *Keystore) GetOr(key, def string) string {
	if v := k.Get(key); v != "" {
		return v
	}
	return def
}

// GetBool parses the effective value as a boolean flag. "1"/"true"/"yes"/"on"
// (case-insensitive) are true; anything else (including empty) is def. The
// geo flags historically compared against the literal "1", which this accepts.
func (k *Keystore) GetBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(k.Get(key)))
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

// GetInt parses the effective value as an int, returning def on empty/parse
// failure.
func (k *Keystore) GetInt(key string, def int) int {
	v := strings.TrimSpace(k.Get(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// GetFloat parses the effective value as a float64, returning def on
// empty/parse failure.
func (k *Keystore) GetFloat(key string, def float64) float64 {
	v := strings.TrimSpace(k.Get(key))
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

// GetIntCSV parses the effective value as a comma-separated list of ints
// (e.g. AbuseIPDB categories "18,22"), returning def on empty. Malformed
// entries are skipped; an all-malformed value yields def.
func (k *Keystore) GetIntCSV(key string, def []int) []int {
	v := strings.TrimSpace(k.Get(key))
	if v == "" {
		return def
	}
	var out []int
	for _, part := range strings.Split(v, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return def
	}
	return out
}

// Set persists value under key and updates the in-memory cache. An empty value
// is treated as Clear (removes the DB row, reverting to the env fallback).
func (k *Keystore) Set(key, value string) error {
	if value == "" {
		return k.Clear(key)
	}
	if err := k.st.SetAppSetting(key, value); err != nil {
		return err
	}
	k.mu.Lock()
	k.vals[key] = value
	k.mu.Unlock()
	return nil
}

// Clear deletes the DB row and the in-memory entry; subsequent Get falls back
// to the environment (for SHARDLURE_* keys) or the caller's default.
func (k *Keystore) Clear(key string) error {
	if err := k.st.DeleteAppSetting(key); err != nil {
		return err
	}
	k.mu.Lock()
	delete(k.vals, key)
	k.mu.Unlock()
	return nil
}

// HasDB reports whether a DB row exists for key (the operator saved it),
// independent of any env fallback.
func (k *Keystore) HasDB(key string) bool {
	k.mu.RLock()
	_, ok := k.vals[key]
	k.mu.RUnlock()
	return ok
}

// Has reports whether an effective value exists (DB row OR env fallback),
// without revealing the value. Drives the UI "set/unset" badge.
func (k *Keystore) Has(key string) bool {
	return k.Get(key) != ""
}

// Source describes where a key's effective value comes from, for the UI.
type Source string

const (
	SourceDB    Source = "db"
	SourceEnv   Source = "env"
	SourceUnset Source = "unset"
)

// SourceOf reports whether the effective value comes from the DB, the
// environment, or is unset — without revealing the value.
func (k *Keystore) SourceOf(key string) Source {
	if k.HasDB(key) {
		return SourceDB
	}
	if hasEnvFallback(key) && strings.TrimSpace(os.Getenv(key)) != "" {
		return SourceEnv
	}
	return SourceUnset
}
