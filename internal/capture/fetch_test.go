package capture

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSafeFetcherStoresSample(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("#!/bin/sh\necho pwned\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	f := NewSafeFetcher(dir, 1<<20, 0, nil)
	f.TestLoopback = true
	res, err := f.Fetch(context.Background(), srv.URL+"/linux")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if res.Status != "fetched" || res.SHA256 == "" {
		t.Fatalf("bad result: %+v", res)
	}
	b, err := os.ReadFile(res.LocalPath)
	if err != nil || len(b) == 0 {
		t.Fatalf("missing file at %s", res.LocalPath)
	}
	if filepath.Base(res.LocalPath) != res.SHA256 {
		t.Fatalf("expected sha256 filename")
	}
}
