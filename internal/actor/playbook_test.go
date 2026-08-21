package actor

import "testing"

func TestClassifyPlaybook(t *testing.T) {
	cases := []struct {
		name  string
		users []string
		aph   float64
		want  string
	}{
		{"empty", nil, 100, "unknown"},
		{
			"fast cn-dictionary spray",
			[]string{"li", "wei", "wang", "zhang", "xu"}, 200,
			"fast_dictionary_spray",
		},
		{
			"service account enum",
			[]string{"jenkins", "tomcat", "postgres"}, 12,
			"service_account_enum",
		},
		{
			"crypto target two hits",
			[]string{"solana", "ethereum", "alice"}, 50,
			"crypto_target",
		},
		{
			"ops/k8s target",
			[]string{"k8s-admin", "deploy", "alice"}, 30,
			"ops_target",
		},
		{
			"default credential spray",
			[]string{"admin", "root", "user"}, 90,
			"default_credential_spray",
		},
		{
			"opportunistic low-volume",
			[]string{"frodo"}, 1,
			"opportunistic",
		},
	}
	for _, c := range cases {
		got := ClassifyPlaybook(c.users, c.aph)
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestClassifyCowriePlaybook(t *testing.T) {
	cases := []struct {
		name                                       string
		users                                      []string
		aph                                        float64
		client                                     string
		hasAuth, hasCommand, hasTunnel, hasPayload bool
		want                                       string
	}{
		// Handshake-only scanners (the live 74%-unknown bucket): no auth, no
		// command, no tunnel, no payload.
		{"libssh scanner", nil, 4, "SSH-2.0-libssh_0.9.6", false, false, false, false, "scanner_tool"},
		{"go scanner", nil, 8, "SSH-2.0-Go", false, false, false, false, "scanner_tool"},
		{"zgrab survey", nil, 2, "SSH-2.0-ZGrab ZGrab SSH Survey", false, false, false, false, "scanner_tool"},
		{"nmap hostkey probe", nil, 1, "SSH-1.5-Nmap-SSH1-Hostkey", false, false, false, false, "scanner_tool"},
		{"rawpasswordconnectonly", nil, 3, "SSH-2.0-RawPasswordConnectOnly_3.0_net10", false, false, false, false, "scanner_tool"},
		{"asyncssh", nil, 2, "SSH-2.0-AsyncSSH_2.1.0", false, false, false, false, "scanner_tool"},
		{"libssh2", nil, 2, "SSH-2.0-libssh2_1.11.0", false, false, false, false, "scanner_tool"},
		// Handshake completed, unrecognised banner: still a scan, generic bucket.
		{"handshake-only unknown banner", nil, 6, "SSH-2.0-OpenSSH_9.9", false, false, false, false, "handshake_scan"},
		{"handshake-only empty banner", nil, 1, "", false, false, false, false, "handshake_scan"},
		{"handshake-only http garbage", nil, 1, "GET / HTTP/1.1", false, false, false, false, "handshake_scan"},
		// Once an auth attempt exists, the username-corpus classifier takes over.
		{"libssh banner WITH auth defers to corpus", []string{"root", "admin"}, 90, "SSH-2.0-libssh_0.9.6", true, false, false, false, "default_credential_spray"},
		{"command present defers to corpus", []string{"frodo"}, 5, "SSH-2.0-libssh_0.9.6", false, true, false, false, "opportunistic"},
		{"tunnel present defers to corpus", []string{"frodo"}, 5, "SSH-2.0-libssh_0.9.6", false, false, true, false, "opportunistic"},
		{"payload present defers to corpus", []string{"frodo"}, 5, "SSH-2.0-libssh_0.9.6", false, false, false, true, "opportunistic"},
		// Edge: post-handshake activity but no recorded username — corpus
		// guard (len==0) applies; honest unknown rather than a forced label.
		{"command no username stays unknown", nil, 5, "SSH-2.0-libssh_0.9.6", false, true, false, false, "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyCowriePlaybook(c.users, c.aph, c.client, c.hasAuth, c.hasCommand, c.hasTunnel, c.hasPayload)
			if got != c.want {
				t.Errorf("ClassifyCowriePlaybook(%v, %v, %q, %t, %t, %t, %t) = %q, want %q",
					c.users, c.aph, c.client, c.hasAuth, c.hasCommand, c.hasTunnel, c.hasPayload, got, c.want)
			}
		})
	}
}

func TestClassifyIntentTruthTable(t *testing.T) {
	cases := []struct {
		name                                    string
		hasTunnel, hasPayload, hasProbe, deploy bool
		want                                    string
	}{
		{name: "none", want: "unknown"},
		{name: "deploy command", deploy: true, want: "deploy"},
		{name: "probe", hasProbe: true, want: "probe"},
		{name: "probe and deploy command", hasProbe: true, deploy: true, want: "deploy"},
		{name: "payload", hasPayload: true, want: "deploy"},
		{name: "payload and deploy command", hasPayload: true, deploy: true, want: "deploy"},
		{name: "payload and probe", hasPayload: true, hasProbe: true, want: "deploy"},
		{name: "payload probe and deploy command", hasPayload: true, hasProbe: true, deploy: true, want: "deploy"},
		{name: "tunnel", hasTunnel: true, want: "proxy"},
		{name: "tunnel and deploy command", hasTunnel: true, deploy: true, want: "mixed"},
		{name: "tunnel and probe", hasTunnel: true, hasProbe: true, want: "probe"},
		{name: "tunnel probe and deploy command", hasTunnel: true, hasProbe: true, deploy: true, want: "mixed"},
		{name: "tunnel and payload", hasTunnel: true, hasPayload: true, want: "mixed"},
		{name: "tunnel payload and deploy command", hasTunnel: true, hasPayload: true, deploy: true, want: "mixed"},
		{name: "tunnel payload and probe", hasTunnel: true, hasPayload: true, hasProbe: true, want: "mixed"},
		{name: "all", hasTunnel: true, hasPayload: true, hasProbe: true, deploy: true, want: "mixed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyIntent(tc.hasTunnel, tc.hasPayload, tc.hasProbe, tc.deploy)
			if got != tc.want {
				t.Fatalf("ClassifyIntent(%t, %t, %t, %t) = %q, want %q", tc.hasTunnel, tc.hasPayload, tc.hasProbe, tc.deploy, got, tc.want)
			}
		})
	}
}
