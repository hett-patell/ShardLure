package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionIsSideEffectFreeWithoutWritableHome(t *testing.T) {
	if os.Getenv("SHARDLURE_VERSION_TEST_HELPER") == "1" {
		os.Args = []string{"shardlure", "version"}
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		main()
		os.Exit(0)
	}

	home := filepath.Join(t.TempDir(), "missing-home")
	cmd := exec.Command(os.Args[0], "-test.run=^TestVersionIsSideEffectFreeWithoutWritableHome$")
	cmd.Env = append(os.Environ(),
		"SHARDLURE_VERSION_TEST_HELPER=1",
		"SHARDLURE_CONFIG=",
		"HOME="+home,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version failed without a writable HOME: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	if want := fmt.Sprintf("shardlure %s (commit %s)", version, commit); got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("version created files under HOME %q (stat error: %v)", home, err)
	}
}

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
