// Package deobf decodes commonly-observed obfuscation wrappers in
// attacker shell commands. The intent is forensic: surface the
// "real" command alongside the encoded form so defenders can reason
// about intent without having to manually run `base64 -d` on every
// line of a session transcript.
//
// We deliberately do NOT execute or evaluate anything - the package
// only mutates strings. Recursion is bounded so a self-referential
// payload can't drive runaway decoding.
package deobf

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/networkshard/shardlure/internal/intel/intelutil"
)

// MaxDepth caps recursive decoding (e.g. base64-of-base64-of-hex).
// Three layers covers every real-world sample we've encountered;
// going deeper invites pathological loops on adversarial input.
const MaxDepth = 3

// Layer is one decoding step in the chain - the kind tells you what
// we recognised, the decoded text is what we produced from it.
type Layer struct {
	Kind    string `json:"kind"`    // base64 | hex | urlencoded | eval | echo-pipe
	Encoded string `json:"encoded"` // the matched substring (truncated for display)
	Decoded string `json:"decoded"` // result of decoding
}

// Result is the full deobfuscation report for one command. Layers
// is empty when nothing recognisable was found - callers should
// check len(Layers)==0 to decide whether the command was clean.
type Result struct {
	Original string  `json:"original"`
	Final    string  `json:"final"`
	Layers   []Layer `json:"layers"`
}

// Patterns we strip from "wrapper" commands before looking at the
// payload. Order matters: more-specific patterns first so a generic
// fallback doesn't gobble a structured form.
var (
	// `echo "<b64>" | base64 -d | bash` and variants. The capture
	// group is the encoded payload.
	echoB64Pipe = regexp.MustCompile(
		`(?i)\becho\s+(?:-[neE]+\s+)?["']?([A-Za-z0-9+/=_-]{16,})["']?\s*\|\s*base64\s+(?:-[diD]+\s*)+\s*(?:\|\s*(?:bash|sh|/bin/[bs]h)\s*)?`,
	)
	// `bash -c "$(echo <b64>|base64 -d)"`
	bashCSubshell = regexp.MustCompile(
		`(?i)\b(?:bash|sh)\s+-c\s+["']?\$\(\s*echo\s+(?:-[neE]+\s+)?["']?([A-Za-z0-9+/=_-]{8,})["']?\s*\|\s*base64\s+-[diD]+\s*\)["']?`,
	)
	// `printf '\x68\x65...'` hex sequences
	printfHex = regexp.MustCompile(`(?i)\bprintf\s+["']((?:\\x[0-9A-Fa-f]{2})+)["']`)
	// `eval $(...)` / `eval "..."`
	evalWrap = regexp.MustCompile(`(?i)\beval\s+["']?(.+?)["']?$`)
	// Bare standalone base64 blobs of meaningful length. 12 chars
	// covers ~9-byte payloads which is the smallest "interesting"
	// command we'd want to surface (e.g. "rm -rf /").
	bareB64 = regexp.MustCompile(`(^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{12,}={0,2})($|[^A-Za-z0-9+/=])`)
	// Bare hex blob (must be even length, ≥16 chars)
	bareHex = regexp.MustCompile(`(?i)\b([0-9a-f]{16,})\b`)
	// URL-encoded sequences with at least two %xx tokens
	urlEnc = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2}){2,}`)
)

// Decode produces a Result describing every obfuscation layer
// recognised in cmd. Layers are returned in decode order, so the
// last layer's Decoded value matches Result.Final.
func Decode(cmd string) Result {
	r := Result{Original: cmd, Final: cmd}
	current := cmd
	for depth := 0; depth < MaxDepth; depth++ {
		layer, next, ok := stepDecode(current)
		if !ok {
			break
		}
		r.Layers = append(r.Layers, layer)
		current = next
		r.Final = next
	}
	return r
}

// stepDecode applies one decoding pass. Returns ok=false if nothing
// recognisable was found in the current string.
func stepDecode(s string) (Layer, string, bool) {
	// 1) echo "<b64>" | base64 -d wrapper
	if m := echoB64Pipe.FindStringSubmatch(s); len(m) == 2 {
		if dec, ok := tryBase64(m[1]); ok {
			return Layer{Kind: "echo-pipe-base64", Encoded: intelutil.Truncate(m[1], 80), Decoded: dec}, dec, true
		}
	}
	// 2) bash -c "$(echo … | base64 -d)" wrapper
	if m := bashCSubshell.FindStringSubmatch(s); len(m) == 2 {
		if dec, ok := tryBase64(m[1]); ok {
			return Layer{Kind: "bash-c-subshell-base64", Encoded: intelutil.Truncate(m[1], 80), Decoded: dec}, dec, true
		}
	}
	// 3) printf '\xNN...' hex sequence
	if m := printfHex.FindStringSubmatch(s); len(m) == 2 {
		dec := decodePrintfHex(m[1])
		return Layer{Kind: "printf-hex", Encoded: intelutil.Truncate(m[1], 80), Decoded: dec}, dec, true
	}
	// 4) eval "..." wrapper: strip and continue decoding the inner
	if m := evalWrap.FindStringSubmatch(s); len(m) == 2 {
		inner := strings.TrimSpace(m[1])
		if inner != "" && inner != s {
			return Layer{Kind: "eval", Encoded: intelutil.Truncate(s, 80), Decoded: inner}, inner, true
		}
	}
	// 5) Bare base64 token (longest-match heuristic)
	if m := bareB64.FindStringSubmatch(s); len(m) == 4 {
		if dec, ok := tryBase64(m[2]); ok && looksPrintable(dec) {
			return Layer{Kind: "base64", Encoded: intelutil.Truncate(m[2], 80), Decoded: dec}, dec, true
		}
	}
	// 6) Bare hex blob
	if m := bareHex.FindStringSubmatch(s); len(m) == 2 {
		if dec, ok := tryHex(m[1]); ok && looksPrintable(dec) {
			return Layer{Kind: "hex", Encoded: intelutil.Truncate(m[1], 80), Decoded: dec}, dec, true
		}
	}
	// 7) URL-encoded
	if urlEnc.MatchString(s) {
		if dec, err := url.QueryUnescape(s); err == nil && dec != s {
			return Layer{Kind: "urlencoded", Encoded: intelutil.Truncate(s, 80), Decoded: dec}, dec, true
		}
	}
	return Layer{}, "", false
}

// tryBase64 attempts standard then URL-safe base64; returns the
// decoded string and a success flag. Padding-tolerant.
func tryBase64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	// Pad to a multiple of 4 - cowrie often shows stripped padding.
	pad := len(s) % 4
	if pad != 0 {
		s = s + strings.Repeat("=", 4-pad)
	}
	for _, dec := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if out, err := dec.DecodeString(s); err == nil && len(out) > 0 && looksPrintable(string(out)) {
			return string(out), true
		}
	}
	return "", false
}

// tryHex decodes a hex blob iff the result is mostly printable
// (otherwise we'd surface binary garbage that adds no signal).
func tryHex(s string) (string, bool) {
	out, err := hex.DecodeString(s)
	if err != nil || len(out) == 0 {
		return "", false
	}
	return string(out), true
}

// decodePrintfHex reads `\xNN\xNN…` sequences into raw bytes. This
// is purely string-level - no shell evaluation occurs.
func decodePrintfHex(s string) string {
	var b strings.Builder
	for i := 0; i+3 < len(s)+1; {
		if i+3 < len(s)+1 && s[i] == '\\' && i+1 < len(s) && s[i+1] == 'x' {
			if i+4 > len(s) {
				break
			}
			byteStr := s[i+2 : i+4]
			n, err := hex.DecodeString(byteStr)
			if err != nil || len(n) != 1 {
				break
			}
			b.WriteByte(n[0])
			i += 4
			continue
		}
		i++
	}
	return b.String()
}

// looksPrintable rejects strings that are mostly control bytes - we
// don't want to advertise a "decode" that produced binary noise.
func looksPrintable(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	printable := 0
	for _, r := range s {
		if r == '\n' || r == '\t' || r == '\r' || (r >= 0x20 && r < 0x7f) || r >= 0x80 {
			printable++
		}
	}
	return float64(printable)/float64(len([]rune(s))) >= 0.85
}


