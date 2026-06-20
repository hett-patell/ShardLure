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
