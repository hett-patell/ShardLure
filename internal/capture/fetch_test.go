package capture

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// TestSafeDialResolvesHostname exercises the DNS path: a hostname
// (not a literal IP) goes through net.DefaultResolver.LookupIP,
// every returned address is checked against blockedIP, then the
// first survivor is dialed. localhost is used because every host
// resolves it without hitting the network.
//
// Two flavours:
//
//	1. TestLoopback=true: localhost resolves to 127.0.0.1 / ::1, both
//	   pass the loopback escape, dial should succeed.
//	2. TestLoopback=false: every resolved IP is loopback and thus
//	   blocked; the call must error with "blocked resolved target".
func TestSafeDialResolvesHostname(t *testing.T) {
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
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// Allow path: hostname resolves to loopback, loopback permitted.
	// safeDial picks the first resolved IP, which may be either v4
	// or v6 depending on the host; we already have a v4 listener,
	// so check what the resolver hands back and skip the dial leg
	// if it picked v6 (we still want to assert the no-error path).
	allowed := NewSafeFetcher(t.TempDir(), 1<<20, 0, nil)
	allowed.TestLoopback = true
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", "localhost")
	if err != nil || len(ips) == 0 {
		t.Skipf("localhost resolver unavailable: %v", err)
	}
	if ips[0].To4() != nil {
		conn, err := allowed.safeDial(context.Background(), "tcp", "localhost:"+port)
		if err != nil {
			t.Fatalf("safeDial(localhost) with TestLoopback=true: %v", err)
		}
		_ = conn.Close()
	} else {
		// IPv6 first - just confirm the filter passes; don't dial
		// because we only have a v4 listener.
		t.Logf("localhost resolves to %s first (IPv6); skipping dial leg", ips[0])
	}

	// Block path: same hostname, loopback now disallowed - the
	// rejection must come from the filter, not from the dial.
	blocked := NewSafeFetcher(t.TempDir(), 1<<20, 0, nil)
	// TestLoopback intentionally false.
	if _, err := blocked.safeDial(context.Background(), "tcp", "localhost:"+port); err == nil {
		t.Error("safeDial(localhost) without loopback escape: expected blocked-target error, got nil")
	}
}

// TestSafeDialRejectsUnresolvable confirms a DNS failure surfaces as
// a wrapped "dns lookup" error rather than crashing or returning a
// successful dial against some default. Uses .invalid (RFC 6761) so
// resolvers consistently say NXDOMAIN.
func TestSafeDialRejectsUnresolvable(t *testing.T) {
	f := NewSafeFetcher(t.TempDir(), 1<<20, 0, nil)
	f.TestLoopback = true
	_, err := f.safeDial(context.Background(), "tcp", "no-such-host.invalid:80")
	if err == nil {
		t.Fatal("expected DNS error, got nil")
	}
	if !strings.Contains(err.Error(), "dns lookup") {
		t.Errorf("error should mention dns lookup, got %v", err)
	}
}

// TestBlockedIPReservedRanges locks in the SSRF guard's coverage of ranges the
// net.IP predicates miss: unspecified (0.0.0.0/::), CGNAT 100.64/10, and
// benchmarking 198.18/15. Cloud metadata 169.254.169.254 is covered via
// link-local. Public IPs must pass.
func TestBlockedIPReservedRanges(t *testing.T) {
	blocked := []string{
		"0.0.0.0", "::", // unspecified -> localhost on Linux
		"100.64.1.1",      // CGNAT
		"198.18.0.1",      // benchmarking
		"169.254.169.254", // cloud metadata (link-local)
		"127.0.0.1",       // loopback
		"10.0.0.1",        // private
		"192.168.1.1",     // private
		"224.0.0.1",       // multicast
		"192.0.0.1",       // IETF protocol assignments
	}
	for _, s := range blocked {
		if !blockedIP(net.ParseIP(s), nil, false) {
			t.Errorf("blockedIP(%s) = false, want true (must be blocked)", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "203.0.113.10"}
	for _, s := range allowed {
		if blockedIP(net.ParseIP(s), nil, false) {
			t.Errorf("blockedIP(%s) = true, want false (public, should pass)", s)
		}
	}
	// adminIPs CIDR is also blocked (operator range must not be fetched).
	if !blockedIP(net.ParseIP("203.0.113.10"), []string{"203.0.113.0/24"}, false) {
		t.Error("blockedIP should block an IP inside an admin CIDR range")
	}
}
