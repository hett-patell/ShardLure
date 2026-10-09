package capture

import "testing"

func TestHostGate(t *testing.T) {
	g := NewHostGate()
	rel, ok := g.TryAcquire("http://Example.COM:8080/a")
	if !ok {
		t.Fatal("first acquire refused")
	}
	if _, ok := g.TryAcquire("https://example.com/b"); ok {
		t.Fatal("same host (case/port/scheme differ) acquired twice")
	}
	rel2, ok := g.TryAcquire("http://198.51.100.9/x")
	if !ok {
		t.Fatal("different host blocked")
	}
	rel()
	rel() // idempotent: must not free someone else's later hold
	rel3, ok := g.TryAcquire("http://example.com/c")
	if !ok {
		t.Fatal("release did not free the host")
	}
	rel() // stale release after a new holder
	if _, ok := g.TryAcquire("http://example.com/d"); ok {
		t.Fatal("stale release freed the new holder")
	}
	rel3()
	rel2()

	r6, ok := g.TryAcquire("http://[2001:DB8::1]:80/x")
	if !ok {
		t.Fatal("ipv6 refused")
	}
	if _, ok := g.TryAcquire("http://[2001:db8::1]/y"); ok {
		t.Fatal("ipv6 same host acquired twice")
	}
	r6()

	for _, bad := range []string{"", "::not a url", "http://", "cowrie-download:abc", "/just/a/path"} {
		if _, ok := g.TryAcquire(bad); ok {
			t.Fatalf("garbage %q accepted", bad)
		}
	}
}
