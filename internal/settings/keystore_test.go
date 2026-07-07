package settings

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/networkshard/shardlure/internal/store"
)

func newTestKeystore(t *testing.T) *Keystore {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ks.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	k, err := Load(st)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return k
}

func TestKeystoreDBWinsOverEnv(t *testing.T) {
	t.Setenv(KeyAbuseIPDB, "env-value")
	k := newTestKeystore(t)

	// No DB row yet: env fallback applies.
	if got := k.Get(KeyAbuseIPDB); got != "env-value" {
		t.Fatalf("Get env fallback = %q, want env-value", got)
	}
	if src := k.SourceOf(KeyAbuseIPDB); src != SourceEnv {
		t.Fatalf("SourceOf = %q, want env", src)
	}

	// DB row wins.
	if err := k.Set(KeyAbuseIPDB, "db-value"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := k.Get(KeyAbuseIPDB); got != "db-value" {
		t.Fatalf("Get after Set = %q, want db-value", got)
	}
	if src := k.SourceOf(KeyAbuseIPDB); src != SourceDB {
		t.Fatalf("SourceOf after Set = %q, want db", src)
	}

	// Clear reverts to env.
	if err := k.Clear(KeyAbuseIPDB); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if got := k.Get(KeyAbuseIPDB); got != "env-value" {
		t.Fatalf("Get after Clear = %q, want env-value", got)
	}
}

func TestKeystoreSetEmptyClears(t *testing.T) {
	k := newTestKeystore(t)
	if err := k.Set(KeyVT, "abc"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := k.Set(KeyVT, ""); err != nil { // empty => Clear
		t.Fatalf("Set empty: %v", err)
	}
	if k.HasDB(KeyVT) {
		t.Fatalf("HasDB after Set empty: still present")
	}
}

func TestKeystoreNonEnvKeyNoFallback(t *testing.T) {
	// A dotted knob key must NOT read a coincidental env var.
	t.Setenv("abuseipdb.min_probe_score", "99") // env vars can't really have dots, but prove intent
	k := newTestKeystore(t)
	if got := k.GetInt(KeyAbuseMinProbe, 60); got != 60 {
		t.Fatalf("GetInt default = %d, want 60 (no env fallback for dotted keys)", got)
	}
	if src := k.SourceOf(KeyAbuseMinProbe); src != SourceUnset {
		t.Fatalf("SourceOf dotted unset = %q, want unset", src)
	}
}

func TestKeystoreTypedGetters(t *testing.T) {
	k := newTestKeystore(t)
	k.Set(KeyAbuseReportEnabled, "true")
	k.Set(KeyAbuseMinProbe, "72")
	k.Set(KeyHomeLat, "19.076")
	k.Set(KeyAbuseCategories, "18, 22, x, 4")

	if !k.GetBool(KeyAbuseReportEnabled, false) {
		t.Errorf("GetBool = false, want true")
	}
	if got := k.GetInt(KeyAbuseMinProbe, 60); got != 72 {
		t.Errorf("GetInt = %d, want 72", got)
	}
	if got := k.GetFloat(KeyHomeLat, 0); got != 19.076 {
		t.Errorf("GetFloat = %v, want 19.076", got)
	}
	got := k.GetIntCSV(KeyAbuseCategories, nil)
	want := []int{18, 22, 4} // "x" skipped
	if len(got) != len(want) {
		t.Fatalf("GetIntCSV = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("GetIntCSV = %v, want %v", got, want)
		}
	}
	// Defaults on empty.
	if got := k.GetInt("unset.key", 5); got != 5 {
		t.Errorf("GetInt default = %d, want 5", got)
	}
	if k.GetBool("unset.key", true) != true {
		t.Errorf("GetBool default lost")
	}
}

func TestKeystoreLoadSeedsFromDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seed.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.SetAppSetting(KeyOTX, "persisted"); err != nil {
		t.Fatalf("SetAppSetting: %v", err)
	}
	st.Close()

	st2, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	k, err := Load(st2)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := k.Get(KeyOTX); got != "persisted" {
		t.Fatalf("Get after Load = %q, want persisted", got)
	}
}

// TestKeystoreConcurrent exercises the RWMutex under -race.
func TestKeystoreConcurrent(t *testing.T) {
	k := newTestKeystore(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = k.Get(KeyIPQS) }()
		go func() { defer wg.Done(); _ = k.Set(KeyIPQS, "v") }()
	}
	wg.Wait()
}
