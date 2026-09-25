package main

import "testing"

func TestTailscaleBindFailsClosed(t *testing.T) {
	for _, tc := range []struct{ addr, ip, want string }{
		{":8080", "100.64.1.2", "100.64.1.2:8080"},
		{"0.0.0.0:8080", "100.64.1.2", "100.64.1.2:8080"},
		{":8080", "", ""}, {":8080", "8.8.8.8", ""}, {":8080", "127.0.0.1", ""}, {"bad", "100.64.1.2", ""},
	} {
		got, err := tailscaleBindAddress(tc.addr, tc.ip)
		if tc.want == "" {
			if err == nil {
				t.Errorf("%+v did not fail closed", tc)
			}
		} else if err != nil || got != tc.want {
			t.Errorf("%+v got %q %v", tc, got, err)
		}
	}
}
