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
