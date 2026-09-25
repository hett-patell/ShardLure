package web

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
)

func TestBazaarUploadThrottleWaitIsCancellable(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "bazaar-throttle.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, keys, "127.0.0.1:0", Options{})
	s.lastBazaarAt = time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	err = s.waitForBazaarSlot(ctx, time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForBazaarSlot error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("cancelled Bazaar throttle waited %v", elapsed)
	}
}

func TestBazaarUploadSelectsPayloadBehindNewerTTY(t *testing.T) {
	t.Setenv("SHARDLURE_DASH_TOKEN", "")
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "share.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// Inert script text; the sole submission destination is a local fake.
	body := []byte("#!/bin/sh\n# inert regression fixture; never executed\n# " + strings.Repeat("padding ", 20) + "\n")
	p := filepath.Join(dir, "inert.txt")
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sha := fmt.Sprintf("%x", sha256.Sum256(body))
	now := time.Now()
	for _, a := range []store.Artifact{
		{URL: "https://example.com/payload", TS: now.Add(-time.Hour), SHA256: sha, Origin: "quarantine_fetch", Status: "fetched", LocalPath: p, SizeBytes: int64(len(body))},
		{URL: "cowrie-tty://fixture", TS: now, SHA256: sha, Origin: "cowrie_tty", Status: "fetched", LocalPath: p, SizeBytes: int64(len(body))},
	} {
		if err := st.RecordArtifact(a); err != nil {
			t.Fatal(err)
		}
	}
	var calls atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"query_status":"inserted"}`)
	}))
	defer endpoint.Close()
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, keys, "127.0.0.1:0", Options{BazaarAPIKey: "fixture-key", BazaarEndpoint: endpoint.URL})
	rec := httptest.NewRecorder()
	s.handleBazaarUpload(rec, httptest.NewRequest(http.MethodPost, "/api/intel/bazaar/upload?sha="+sha, nil))
	if rec.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("status=%d calls=%d body=%s", rec.Code, calls.Load(), rec.Body.String())
	}
	recorded, err := st.BazaarUploadRecorded(sha)
	if err != nil || !recorded {
		t.Fatalf("local fake submission not recorded: %v %v", recorded, err)
	}
}
