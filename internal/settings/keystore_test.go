package settings

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

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

func TestKeystoreSerializesSetSetPersistenceAndCache(t *testing.T) {
	assertKeystoreWriteOrdering(t, func(k *Keystore, key string) error {
		return k.Set(key, "B")
	})
}

func TestKeystoreSerializesSetClearPersistenceAndCache(t *testing.T) {
	assertKeystoreWriteOrdering(t, func(k *Keystore, key string) error {
		return k.Clear(key)
	})
}

// barrierSettingsStore wraps the real SQLite settings store and pauses write A
// after its DB commit but before Keystore.Set can mutate the cache. Without a
// keystore-level writer lock, write B can then commit and update the cache
// before A resumes, deterministically producing A-DB/B-DB/B-cache/A-cache.
type barrierSettingsStore struct {
	st           *store.Store
	firstDB      chan struct{}
	releaseFirst chan struct{}
	secondDB     chan struct{}
}

func (s *barrierSettingsStore) SetAppSetting(key, value string) error {
	if err := s.st.SetAppSetting(key, value); err != nil {
		return err
	}
	if value == "A" {
		close(s.firstDB)
		<-s.releaseFirst
	} else {
		close(s.secondDB)
	}
	return nil
}

func (s *barrierSettingsStore) DeleteAppSetting(key string) error {
	if err := s.st.DeleteAppSetting(key); err != nil {
		return err
	}
	close(s.secondDB)
	return nil
}

func assertKeystoreWriteOrdering(t *testing.T, second func(*Keystore, string) error) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ordering.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	barrier := &barrierSettingsStore{
		st:           st,
		firstDB:      make(chan struct{}),
		releaseFirst: make(chan struct{}),
		secondDB:     make(chan struct{}),
	}
	k := &Keystore{st: barrier, vals: map[string]string{}}
	const key = "ordering.test"

	firstDone := make(chan error, 1)
	go func() { firstDone <- k.Set(key, "A") }()
	waitKeystoreSignal(t, barrier.firstDB, "first DB write")
	writerHeld := !k.writeMu.TryLock()
	if !writerHeld {
		k.writeMu.Unlock()
		t.Error("keystore writer mutex was not held across the first DB/cache gap")
	}

	secondDone := make(chan error, 1)
	secondStarted := make(chan struct{})
	go func() {
		close(secondStarted)
		secondDone <- second(k, key)
	}()
	waitKeystoreSignal(t, secondStarted, "second goroutine start")

	// On the broken implementation B reaches the DB while A is paused. Wait
	// for B to finish its cache mutation before releasing A, forcing the stale
	// schedule exactly. On the fixed implementation TryLock proves A still owns
	// the writer mutex, so B is serialized behind it and can finish only after
	// A is released.
	secondFinished := false
	if !writerHeld {
		waitKeystoreSignal(t, barrier.secondDB, "unserialized second DB write")
		if err := waitKeystoreResult(t, secondDone, "second write"); err != nil {
			t.Fatalf("second write: %v", err)
		}
		secondFinished = true
	}
	close(barrier.releaseFirst)
	if err := waitKeystoreResult(t, firstDone, "first write"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if !secondFinished {
		waitKeystoreSignal(t, barrier.secondDB, "serialized second DB write")
		if err := waitKeystoreResult(t, secondDone, "serialized second write"); err != nil {
			t.Fatalf("second write: %v", err)
		}
	}

	dbValue, dbOK, err := st.GetAppSetting(key)
	if err != nil {
		t.Fatalf("read DB value: %v", err)
	}
	k.mu.RLock()
	cacheValue, cacheOK := k.vals[key]
	k.mu.RUnlock()
	if cacheOK != dbOK || cacheValue != dbValue {
		t.Fatalf("cache = (%q, %v), DB = (%q, %v)", cacheValue, cacheOK, dbValue, dbOK)
	}
}

func waitKeystoreSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func waitKeystoreResult(t *testing.T, ch <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return nil
	}
}
