package bazaar

import (
	"bytes"
	"testing"
)

// elfHeader is a minimal valid-enough ELF magic prefix. matchELFFamily operates
// on a byte buffer, so a synthetic buffer carrying the exact signature bytes is
// a faithful input — no real malware needs to ship in the repo (which also
// respects the check-utf8 no-binary convention).
var elfHeader = []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func buf(parts ...[]byte) []byte {
	b := append([]byte{}, elfHeader...)
	for _, p := range parts {
		b = append(b, p...)
		b = append(b, 0)
	}
	// pad so entropy-based checks aren't skewed by a tiny buffer
	return append(b, bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog. "), 40)...)
}

// xorEncode builds a Mirai-style obfuscated .rodata run: the cleartext XORed by
// the single-byte collapsed key, which the classifier reverses.
func xorEncode(s string, key byte) []byte {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		out[i] = s[i] ^ key
	}
	return out
}

func TestMatchELFFamily_TierAAnchors(t *testing.T) {
	cases := []struct {
		name       string
		buf        []byte
		wantFamily string
	}{
		{"mozi literal", buf([]byte("Mozi.m"), []byte("random")), "Mozi"},
		{"mozi word-boundary", buf([]byte("config Mozi node")), "Mozi"},
		{"mozi xor key + marker", buf(moziXORKey, moziConfigMarker), "Mozi"},
		{"mirai cdn-cgi template", buf(miraiCdnCgiTemplate), "Mirai"},
		{"mirai xor wordlist 0x22", buf(xorEncode("nameserver", 0x22), xorEncode("administrator", 0x22)), "Mirai"},
		{"mirai xor wordlist 0x54", buf(xorEncode("listening", 0x54), xorEncode("/bin/busybox", 0x54)), "Mirai"},
		{"mirai busybox applet pair", buf([]byte("/bin/busybox ECCHI"), []byte("ECCHI: applet not found")), "Mirai"},
		{"mirai leaked symbols", buf([]byte("table_init"), []byte("table_unlock_val")), "Mirai"},
		{"gafgyt gayfgt handshake", buf([]byte("/bin/busybox;echo -e 'gayfgt'")), "Gafgyt"},
		{"gafgyt octal handshake", buf(gafgytOctalHandshake), "Gafgyt"},
		{"gafgyt telnet cracked", buf([]byte("TELNET LOGIN CRACKED - %s:%s:%s")), "Gafgyt"},
		{"gafgyt hold+junk", buf([]byte("HOLD"), []byte("JUNK"), []byte("/bin/busybox")), "Gafgyt"},
		{"tsunami getspoofs", buf([]byte("GETSPOOFS"), []byte("TSUNAMI"), []byte("NOTICE %s :")), "Tsunami"},
		{"xmrig donate host", buf([]byte("donate.v2.xmrig.com")), "XMRig"},
		{"xmrig two anchors", buf([]byte("XMRig/6.0 libuv/1.0"), []byte("rx/0"), []byte("cn/r")), "XMRig"},
		{"redtail literal", buf([]byte("# RedTail loader")), "RedTail"},
		{"komari literal", buf([]byte("komari-agent")), "Komari"},
		{"traffmonetizer literal", buf([]byte("docker pull traffmonetizer/cli")), "Traffmonetizer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fam, tags := matchELFFamily(tc.buf)
			if fam != tc.wantFamily {
				t.Fatalf("family = %q, want %q (tags=%v)", fam, tc.wantFamily, tags)
			}
			if len(tags) == 0 {
				t.Error("a matched family must carry descriptive tags")
			}
		})
	}
}

// TestLowPrecisionMarkersNeverAttribute is the account-safety guard: a buffer
// containing ONLY a low-precision / shared / benign marker must classify as
// family-unknown. If a future edit promotes one of these to an anchor, this
// fails — which is the point.
func TestLowPrecisionMarkersNeverAttribute(t *testing.T) {
	for _, marker := range lowPrecisionMarkers {
		b := buf(marker)
		if fam, _ := matchELFFamily(b); fam != "" {
			t.Errorf("buffer containing only the low-precision marker %q attributed family %q "+
				"— this string is shared/benign and must NEVER attribute alone (account-ban risk)",
				marker, fam)
		}
	}
	// Specific benign lookalikes that must stay unknown:
	benign := [][]byte{
		[]byte("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"),     // browser UA, not Mozi
		[]byte("dht.transmissionbt.com router.bittorrent.com bttracker"), // real BitTorrent client
		[]byte("/bin/busybox\nPING\nPONG\n8.8.8.8"),                      // generic embedded-Linux tool
		[]byte("stratum+tcp://pool.example.com argon2 support"),          // a miner, but not XMRig-attributable
		[]byte("TSource Engine Query"),                                   // in games AND malware — ambiguous
	}
	for _, b := range benign {
		if fam, _ := matchELFFamily(buf(b)); fam != "" {
			t.Errorf("benign lookalike %q attributed family %q — false positive", b, fam)
		}
	}
}

// TestMoziWordBoundaryNotMozilla pins that "Mozilla" (browser UA) does not
// match the Mozi word signature.
func TestMoziWordBoundaryNotMozilla(t *testing.T) {
	if fam, _ := matchELFFamily(buf([]byte("User-Agent: Mozilla/5.0"))); fam == "Mozi" {
		t.Error("Mozilla UA matched Mozi — word-boundary check failed (this is a real FP path)")
	}
}

func TestIsPackedELF(t *testing.T) {
	// UPX magic in the head.
	if packed, tags := isPackedELF(append([]byte("UPX!"), bytes.Repeat([]byte{0}, 500)...), nil); !packed {
		t.Error("UPX magic not detected as packed")
	} else if !hasTag(tags, "upx") {
		t.Errorf("packed tags = %v, want upx", tags)
	}
	// Stub banner.
	if packed, _ := isPackedELF([]byte("$Info: This file is packed with the UPX executable packer"), nil); !packed {
		t.Error("UPX stub banner not detected")
	}
	// A normal buffer is not packed.
	if packed, _ := isPackedELF(buf([]byte("just some normal strings and code")), nil); packed {
		t.Error("benign buffer flagged as packed")
	}
}

func hasTag(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
