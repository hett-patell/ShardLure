package main

import "testing"

func TestAddrPort(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		// Canonical forms accepted by net.Listen
		{":8080", 8080},
		{"0.0.0.0:8080", 8080},
		{"127.0.0.1:9090", 9090},
		{"[::1]:8080", 8080},
		{"[::]:443", 443},
		{"host:8080", 8080},

		// Permissive fallback: bare port number
		{"8080", 8080},

		// Malformed / out-of-range -> 0 so caller can detect
		{"", 0},
		{":", 0},
		{":abc", 0},
		{":-1", 0},
		{":0", 0},
		{":65536", 0},
		{":99999", 0},
		{"host", 0},
		{"random garbage", 0},
		{"[::1]", 0},
	}
	for _, c := range cases {
		got := addrPort(c.in)
		if got != c.want {
			t.Errorf("addrPort(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
