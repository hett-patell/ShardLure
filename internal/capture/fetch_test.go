package capture

import (
	"context"
	"net"
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

// TestSafeDialBlocksRebinding verifies that safeDial - the choke-
// point that defeats DNS rebinding - rejects a literal blocked IP
// even when called directly with an apparently safe address. This
// is the layer that closes the original TOCTOU: even if some other
// resolver had returned a benign IP earlier in the lookup, the
// runtime dial cannot bypass safeDial's filter.
func TestSafeDialBlocksRebinding(t *testing.T) {
	f := NewSafeFetcher(t.TempDir(), 1<<20, 0, nil)
	// TestLoopback intentionally false: loopback must be blocked.
	cases := []string{
		"127.0.0.1:80",
		"10.0.0.1:80",
		"192.168.1.1:80",
		"169.254.169.254:80", // cloud metadata - the classic SSRF target
	}
	for _, target := range cases {
		_, err := f.safeDial(context.Background(), "tcp", target)
		if err == nil {
			t.Errorf("safeDial(%s) accepted; expected blocked-target error", target)
		}
	}
}

// TestSafeDialAcceptsPublic confirms the dialer routes traffic for
// addresses the SSRF guard considers safe. We don't actually want
// to hit the internet from tests, so we use a fake net.Listener on
// a non-loopback bind isn't portable. Instead, exercise the literal
// IP branch with a TestLoopback escape that proves the dial path
// completes successfully when the IP passes the filter.
func TestSafeDialAcceptsAllowed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()

	f := NewSafeFetcher(t.TempDir(), 1<<20, 0, nil)
	f.TestLoopback = true // allow loopback only for this test

	conn, err := f.safeDial(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("safeDial: %v", err)
	}
	_ = conn.Close()
}
