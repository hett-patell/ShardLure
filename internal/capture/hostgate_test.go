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

func TestHostGateCanonicalSpellings(t *testing.T) {
	pairs := [][2]string{
		{"http://[2001:db8::1]/a", "http://[2001:db8:0:0::1]/b"},
		{"http://[2001:DB8::1]/a", "http://[2001:0db8:0000::0001]:8080/b"},
		{"http://evil.com/a", "http://evil.com./b"},
		{"http://EVIL.com./a", "https://evil.COM:443/b"},
		{"http://1.2.3.4/a", "http://[::ffff:1.2.3.4]/b"},
		{"http://BÜCHER.de/a", "http://bücher.de/b"},
	}
	for _, p := range pairs {
		g := NewHostGate()
		rel, ok := g.TryAcquire(p[0])
		if !ok {
			t.Fatalf("%q refused", p[0])
		}
		if _, ok := g.TryAcquire(p[1]); ok {
			t.Fatalf("%q and %q got separate keys", p[0], p[1])
		}
		rel()
		if _, ok := g.TryAcquire(p[1]); !ok {
			t.Fatalf("%q blocked after release", p[1])
		}
	}
	// A bare trailing dot is not a host.
	if _, ok := NewHostGate().TryAcquire("http://./x"); ok {
		t.Fatal("root-dot host accepted")
	}
	// Distinct servers stay distinct.
	g := NewHostGate()
	if _, ok := g.TryAcquire("http://1.2.3.4/"); !ok {
		t.Fatal("refused")
	}
	if _, ok := g.TryAcquire("http://[::1.2.3.5]/"); !ok {
		t.Fatal("different address blocked")
	}
}
