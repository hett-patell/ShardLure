package web

import (
	"net/http"
	"strings"
	"testing"
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
	tailscaleSelfDNSName = func() string { return "renamed.kingfisher-typhon.ts.net." }
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
