package main

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// termSafe makes attacker-controlled text inert on an operator's terminal.
// Every C0 control (newline and tab included: one would break a table row,
// the other a tabwriter column), DEL, C1 control, every format character
// (unicode.Cf: bidi overrides, zero-width characters, U+FEFF, soft hyphen,
// tag characters) and the line/paragraph separators are replaced with a
// visible escape. Bytes that are not valid UTF-8 are escaped individually,
// so a lone 0x9b (8-bit CSI on terminals that honour C1) can never slip
// through as "invalid, pass it along". A backslash is doubled so literal
// attacker text such as `\x1b` cannot pass for a sanitised ESC.
func termSafe(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\\':
			b.WriteString(`\\`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r > 0xffff && unicode.Is(unicode.Cf, r):
			fmt.Fprintf(&b, `\U%08x`, r)
		case (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029 || unicode.Is(unicode.Cf, r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// jsonTermSafe re-escapes, as \uXXXX, the runes encoding/json leaves raw but a
// terminal may act on: DEL, the C1 controls (U+009B is an 8-bit CSI), the
// line/paragraph separators and every format character. The input must be
// encoding/json output: every non-ASCII rune then sits inside a string
// literal, so the result is still valid JSON and decodes to the same data.
// Escaping after marshalling, rather than sanitising fields before, keeps the
// output lossless for machine consumers.
func jsonTermSafe(js string) string {
	var b strings.Builder
	for _, r := range js {
		if r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029 || unicode.Is(unicode.Cf, r) {
			if r > 0xffff {
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
