package web

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/settings"
)

// Final audit M4: Tailscale derives a node's MagicDNS label from the OS
// hostname but sanitises it (characters outside [a-z0-9-] become '-') and
// de-duplicates a clash with a "-N" suffix, so a raw-hostname check refused
// the node's own name. The policy now also accepts the sanitised label with
// an optional numeric suffix, and the exact name the local tailscale CLI
// reports (Self.DNSName), read once at startup.
func TestHostPolicyAcceptsTailscaleNames(t *testing.T) {
	for _, tc := range []struct {
		machine, magic string
		host           string
		want           bool
	}{
		// Production: hostname arm, MagicDNS arm.kingfisher-typhon.ts.net.
		{"arm", "", "arm.kingfisher-typhon.ts.net", true},
		{"arm", "arm.kingfisher-typhon.ts.net.", "arm.kingfisher-typhon.ts.net", true},
		{"arm", "arm.kingfisher-typhon.ts.net.", "ARM.kingfisher-typhon.ts.net.:8080", true},
		{"arm", "", "arm", true},
		// Sanitised: my_box is not a DNS label, Tailscale calls it my-box.
		{"my_box", "", "my-box.tail1234.ts.net", true},
		{"my_box", "", "my-box", true},
		{"My.Box.lan", "", "my.tail1234.ts.net", true},
		// De-duplicated: a second node called arm is arm-1.
		{"arm", "", "arm-1.kingfisher-typhon.ts.net", true},
		{"arm", "", "arm-12", true},
		{"my_box", "", "my-box-2.tail1234.ts.net", true},
		// The CLI's name wins when it differs from the hostname (renamed).
		{"arm", "honeypot.kingfisher-typhon.ts.net.", "honeypot.kingfisher-typhon.ts.net", true},
		{"arm", "honeypot.kingfisher-typhon.ts.net.", "honeypot", true},
		// Still refused.
		{"arm", "", "arm-x.kingfisher-typhon.ts.net", false},
		{"arm", "", "arm-.kingfisher-typhon.ts.net", false},
		{"arm", "", "arm-12345.kingfisher-typhon.ts.net", false},
		{"arm", "", "arms.kingfisher-typhon.ts.net", false},
		{"arm", "", "arm.a.b.ts.net", false},
		{"arm", "", "x.arm.kingfisher-typhon.ts.net", false},
		{"arm", "", "arm.evil.example", false},
		{"arm", "", "arm-1.evil.example", false},
		{"arm", "honeypot.kingfisher-typhon.ts.net.", "honeypot.evil.example", false},
		{"arm", "honeypot.kingfisher-typhon.ts.net.", "x.honeypot.kingfisher-typhon.ts.net", false},
		{"arm", "not a name", "not a name", false},
		{"___", "", "-.tail1234.ts.net", false},
	} {
		p := newHostPolicy("100.124.3.67:8080", "", tc.machine).withMagicDNS(tc.magic)
		if got := p.allows(tc.host); got != tc.want {
			t.Errorf("machine %q magic %q: allows(%q) = %v, want %v", tc.machine, tc.magic, tc.host, got, tc.want)
		}
	}
}

// The server reads the MagicDNS name through tailscaleSelfDNSName; with it
// stubbed the live handler answers to that name.
func TestServerHostPolicyUsesTailscaleName(t *testing.T) {
	t.Setenv("SHARDLURE_DASH_TOKEN", "")
	prevHost, prevTS := machineHostname, tailscaleSelfDNSName
	machineHostname = func() (string, error) { return "arm", nil }
	tailscaleSelfDNSName = func(context.Context) string { return "renamed.kingfisher-typhon.ts.net." }
	t.Cleanup(func() { machineHostname, tailscaleSelfDNSName = prevHost, prevTS })
	s := newAuthTestServer(t, "")
	addr := startHostTestServer(t, s)
	for host, want := range map[string]int{
		"renamed.kingfisher-typhon.ts.net": http.StatusOK,
		"arm.kingfisher-typhon.ts.net":     http.StatusOK,
		"other.kingfisher-typhon.ts.net":   http.StatusMisdirectedRequest,
	} {
		if got := getWithHost(t, addr, host); got != want {
			t.Errorf("Host %q = %d, want %d", host, got, want)
		}
	}
}

func TestParseTailscaleSelfDNSName(t *testing.T) {
	for in, want := range map[string]string{
		`{"Self":{"DNSName":"arm.kingfisher-typhon.ts.net.","HostName":"arm"}}`: "arm.kingfisher-typhon.ts.net.",
		`{"Self":null}`: "",
		`{}`:            "",
		`not json`:      "",
		`{"Self":{"DNSName":` + strings.Repeat(" ", 10) + `""}}`: "",
	} {
		if got := parseTailscaleSelfDNSName([]byte(in)); got != want {
			t.Errorf("parse(%q) = %q, want %q", in, got, want)
		}
	}
}

// fakeTailscale puts an executable "tailscale" shell script with body on a
// PATH of its own and shortens the lookup budget to budget.
func fakeTailscale(t *testing.T, body string, budget time.Duration) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on PATH")
	}
	sh, _ := exec.LookPath("sh")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tailscale"), []byte("#!"+sh+"\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	prev := tailscaleStatusTimeout
	tailscaleStatusTimeout = budget
	t.Cleanup(func() { tailscaleStatusTimeout = prev })
}

// Final re-review, web item 1: exec.CommandContext kills only the direct
// child, and Output then waited for stdout to close. A CLI (or a wrapper
// script) that leaves a descendant holding stdout kept startup waiting for
// that descendant, measured at 30 s against the 2 s budget. WaitDelay bounds
// the wait once the CLI has exited or been killed, whether the CLI itself
// hangs or exits at once.
func TestTailscaleLookupBoundedWhenDescendantHoldsStdout(t *testing.T) {
	for name, body := range map[string]string{
		"cli hangs":      "sleep 8 &\nexec sleep 30",
		"cli exits fast": "sleep 8 &\necho '{\"Self\":{\"DNSName\":\"x.tail1.ts.net.\"}}'",
	} {
		t.Run(name, func(t *testing.T) {
			fakeTailscale(t, body, 300*time.Millisecond)
			start := time.Now()
			readTailscaleSelfDNSName(context.Background())
			if d := time.Since(start); d > 4*time.Second {
				t.Fatalf("lookup took %v with a descendant holding stdout (budget 300ms + WaitDelay %v)", d, tailscaleWaitDelay)
			}
		})
	}
}

// The lookup takes the server's run context: a SIGTERM during startup ends
// it at once instead of waiting out the budget.
func TestTailscaleLookupFollowsRunContext(t *testing.T) {
	fakeTailscale(t, "exec sleep 30", 20*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	if got := readTailscaleSelfDNSName(ctx); got != "" {
		t.Fatalf("cancelled lookup = %q", got)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("cancelled lookup took %v (budget 20s): the run context is ignored", d)
	}
}

// With a token set no request is Host-checked, so startup does not wait for
// the lookup; it runs in the background because the token is a live setting
// the Settings panel can clear, and the open-mode check that then applies
// must know the CLI's name.
func TestTokenModeStartupDoesNotWaitForTailscale(t *testing.T) {
	t.Setenv("SHARDLURE_DASH_TOKEN", "")
	prevHost, prevTS := machineHostname, tailscaleSelfDNSName
	machineHostname = func() (string, error) { return "arm", nil }
	release := make(chan struct{})
	tailscaleSelfDNSName = func(ctx context.Context) string {
		select {
		case <-release:
			return "renamed.kingfisher-typhon.ts.net."
		case <-ctx.Done():
			return ""
		}
	}
	t.Cleanup(func() { machineHostname, tailscaleSelfDNSName = prevHost, prevTS })
	s := newAuthTestServer(t, "tok")
	start := time.Now()
	addr := startHostTestServer(t, s) // the lookup is still blocked
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("token-mode startup waited %v for the tailscale lookup", d)
	}
	if err := s.keys.Clear(settings.KeyDashToken); err != nil {
		t.Fatal(err)
	}
	if got := getWithHost(t, addr, "renamed.kingfisher-typhon.ts.net"); got != http.StatusMisdirectedRequest {
		t.Fatalf("before the lookup landed: %d, want 421 (hostname rules only)", got)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for getWithHost(t, addr, "renamed.kingfisher-typhon.ts.net") != http.StatusOK {
		if time.Now().After(deadline) {
			t.Fatal("the background lookup's name never reached the live policy")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
