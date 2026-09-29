// Package script normalises attacker shell commands so sessions running the
// same bot script fingerprint identically. Bots vary isolated tokens (IPs,
// URLs, random file names and passwords), not the script's structure.
package script

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Version identifies the encoding EncodeLine produces. Stored script lines
// hold pre-computed encodings (the recorder encodes each command once), so a
// normaliser change that alters any encoding would leave old sessions and new
// sessions of the same script with different fingerprints, and settled
// scripts keep values computed from the encoding (Distinctive, CommandCount,
// Display, and scripts.token_count = len(Tokens), which MaxDistanceTokens
// caps), while families are assigned once per script (FamilyThreshold and
// the length band). Bump Version with every change that can alter an
// encoding or one of those values (tokenising, placeholders, program
// detection, escaping, separators, the recon list, the heredoc body bound,
// Tokens and its cap, the family constants; not a pure refactor or a
// comment): the campaign worker compares it with the version stored in the
// database and, on a mismatch, deletes the script-derived rows and rewinds
// the recorder so every line is re-encoded (store.ResetScriptsForVersion).
// TestVersionPinsEncoding fails when any of these values changes while
// Version does not.
//
// History: 1 = first release (implicit: no stored version); 2 = wrapped
// programs keep their name (nice/sudo/timeout/env/nohup/stdbuf), literal
// < and > in attacker text are escaped, redirection targets are skipped,
// command/type/hash probes count as recon, a leading redirection keeps the
// program slot (47ae767), and Display counts its ellipsis inside the cap
// (25b5d4e); 3 = a leading heredoc or here-string keeps the program slot, a
// redirection target keeps its $(...) group, and >& / <& tokenise as
// redirections; 4 (unreleased; everything below landed before any build
// shipped it, so it stays one version) = a heredoc delimiter is read from
// the source as one bash word with bash's quote removal (quotes, escapes,
// line continuations, $'...' and $"...") and ends on a whole source line
// (<<\EOF, <<E"OF", <<"E O F" and <<E\ OF no longer hide later commands);
// a heredoc's body is part of its placeholder token, bounded to
// MaxHeredocBodyBytes of encoding; reserved words and braces are not
// programs (and keep the program slot open); N<file, <>, >| and
// fd-prefixed heredocs and here-strings (0<<EOF) are redirections; a quoted
// program name ('id') keeps its name; URLs, IPs and /tmp names stop at a
// backtick; quoted text replaces hex runs (>= 16) and numbers (>= 6
// digits) and encodes a real line break as <nl>/<cr>.
const Version = 4

const (
	MaxNormalizedBytes = 65536
	MaxCommands        = 300
	MaxLinkActors      = 25
	MinCommonActors    = 5
	MaxLinkPercent     = 2.0

	// Unit and record separators: stripped from input, so the encoding is
	// exactly reversible without re-parsing quotes.
	tokSep  = "\x1f"
	lineSep = "\x1e"

	// An attacker's literal < and > inside a word (see escapeLiterals).
	litLT = "<lt>"
	litGT = "<gt>"

	// A heredoc's placeholder; its body follows inside the same token, one
	// litNL per body line, and litMore marks a body cut at
	// MaxHeredocBodyBytes.
	heredocTok = "<heredoc>"
	litNL      = "<nl>"
	litCR      = "<cr>"
	litMore    = "<more>"

	// MaxHeredocBodyBytes bounds one heredoc body inside its token, counted
	// as encoded: every line's litNL and its escapes (<lt>, <cr>) included,
	// so the token is at most len(heredocTok) + MaxHeredocBodyBytes +
	// len(litNL+litMore). Counting raw line bytes let blank lines through
	// free (65,000 newlines encoded to 260 KB; re-review item 4). Bodies are
	// part of the fingerprint, but a dropper carrying a large payload in a heredoc must
	// not push its whole line past the per-session byte cap: the recorder
	// refuses a line that does not fit, and the script's later commands
	// with it. 4 KiB keeps any script a bot writes this way (the loader
	// commands) while a base64 blob is cut.
	MaxHeredocBodyBytes = 4096
)

var (
	redirRe  = regexp.MustCompile(`^(?:\d*<<<|\d*(?:>>?|<)&(?:\d+|-)?|&>>?|\d+>>?|\d+<|\d*<>|\d*>\|)$`)
	bareRe   = regexp.MustCompile(`^[a-z_][a-z0-9_.+-]*$`)
	keyTypes = regexp.MustCompile(`^(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-\S+|sk-\S+@openssh\.com)$`)
	keyBody  = regexp.MustCompile(`AAAA[0-9A-Za-z+/]{36,}={0,3}`)
	// A backtick ends a URL, an IP's path and a /tmp name: it closes a
	// command substitution, and swallowing it made `wget <url>` collide
	// with the unclosed form (audit M3).
	urlRe    = regexp.MustCompile("(?i)\\b[a-z][a-z0-9+.-]*://[^\\s\"'|;&<>()`]+")
	ipRe     = regexp.MustCompile("\\b\\d{1,3}(?:\\.\\d{1,3}){3}(?::\\d+)?(?:/[^\\s\"'|;&<>()`]*)?")
	hexRe    = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	b64Re    = regexp.MustCompile(`^[0-9A-Za-z+/=]{24,}$`)
	numRe    = regexp.MustCompile(`^\d+$`)
	randRe   = regexp.MustCompile(`\b(?:[A-Za-z]*\d[A-Za-z0-9]*[A-Za-z]|[A-Za-z]+\d)[A-Za-z0-9]*\b`)
	tmpRe    = regexp.MustCompile("/tmp/[^\\s/\"'|;&<>()`]+")
	markerRe = regexp.MustCompile(`^[A-Za-z0-9]{1,4}$`)
	// Inside quoted text: hex runs and numbers long enough to be per-victim
	// (the 6-digit floor keeps ports and modes such as 8080 and 777).
	hexIn = regexp.MustCompile(`\b[0-9a-fA-F]{16,}\b`)
	numIn = regexp.MustCompile(`\b\d{6,}\b`)
)

var (
	operators = map[string]bool{";": true, "&&": true, "||": true, "|": true, "&": true}
	// wrappers run a later word as the program (sudo wget, nohup ./x).
	// Their options are listed conservatively, from the tools' own usage:
	// an option not listed here stops wrapper parsing, so the words after it
	// are normalised as plain arguments (the behaviour before options were
	// understood) rather than one of them being guessed to be the program.
	// sudo -e/-l/-v and command -v/-V do not run their operand, and env -S
	// carries the command inside its value, so they are deliberately absent.
	wrappers = map[string]*wrapSpec{
		"sudo": {flags: "AbEHiKknPSs", valued: "CDgpRrTtUu", long: map[string]bool{
			"user": true, "group": true, "prompt": true, "chdir": true, "chroot": true, "role": true,
			"type": true, "command-timeout": true, "other-user": true, "close-from": true,
			"preserve-env": false, "login": false, "shell": false, "non-interactive": false,
			"background": false, "askpass": false, "stdin": false, "set-home": false,
		}},
		"nice": {valued: "n", long: map[string]bool{"adjustment": true}, numeric: true},
		"timeout": {flags: "v", valued: "ks", operands: 1, long: map[string]bool{
			"signal": true, "kill-after": true, "preserve-status": false, "foreground": false, "verbose": false,
		}},
		"env":     {flags: "i", valued: "Cu", long: map[string]bool{"ignore-environment": false, "unset": true, "chdir": true}},
		"stdbuf":  {valued: "eio", long: map[string]bool{"input": true, "output": true, "error": true}},
		"exec":    {flags: "cl", valued: "a"},
		"command": {flags: "p"},
		"time":    {flags: "p"},
		"nohup":   {},
		"busybox": {},
	}
	keyTypeWords = map[string]bool{"ed25519": true, "nistp256": true, "nistp384": true, "nistp521": true}
	stripSeps    = strings.NewReplacer(tokSep, " ", lineSep, " ")
	// A real line break inside a word encodes as a placeholder, not as \n:
	// a typed backslash-n and a real newline used to encode alike (audit M4).
	escapeNL = strings.NewReplacer("\r", litCR, "\n", litNL)
)

// NormalizeCommand splits cmd into shell tokens and replaces the parts bots
// randomise with placeholders, including inside quoted strings.
func NormalizeCommand(cmd string) []string {
	cmd = stripSeps.Replace(cmd)
	out := make([]string, 0, 16)
	start := true
	var wrap *wrapState // non-nil while a wrapper's own words precede its program
	target := false     // the previous word was a leading redirection awaiting its target
	var pending []heredoc
	sc := scanner{s: cmd}
	sc.next()
	for ; sc.ok(); sc.next() {
		t := sc.tok
		// A heredoc body is data, not commands: it starts after the newline
		// that ends the line holding the << and runs to the delimiter line,
		// so `cat <<EOF\nid\nw\nEOF` stays one command. The body is cut out
		// of the source by lines, never by tokens (a quote inside it must not
		// pair with one after it), and the tokenizer resumes at the newline
		// ending the terminator line, which separates the next command. An
		// unterminated body runs to the end of the event, as in bash.
		if t == "\n" && len(pending) > 0 {
			for _, b := range sc.skipBodies(pending) {
				out[b.slot] = b.token()
			}
			pending = pending[:0]
			continue
		}
		// A heredoc or here-string ahead of the program is a redirection like
		// the ones below: it and its word keep the program slot open, as
		// program() already assumes (`<<EOF python3 x` runs python3). The
		// here-string's word is the pending target; the heredoc's delimiter
		// is consumed here and its body starts at the next newline.
		if hereString(t) {
			out = append(out, t)
			target = start
			continue
		}
		if isHeredoc(t) {
			out = append(out, strings.TrimSuffix(t, "-"))
			if d, ok := sc.delimiter(); ok {
				pending = append(pending, heredoc{delim: d, tabs: strings.HasSuffix(t, "-"), slot: len(out)})
				out = append(out, heredocTok)
			} else {
				start = false // no delimiter: a syntax error, not a redirection
			}
			target = false
			continue
		}
		// A redirection ahead of the program (`> /tmp/a python3`, `2>/dev/null
		// id`) is not the program and neither is its target: both are kept
		// (the target normalised) and the program slot stays open, matching
		// program(). fd duplications (2>&1) hold their target in the token.
		// A newline or operator ends a dangling redirection.
		if start && t != "\n" && !operators[t] {
			if target {
				target = false
				out = append(out, normalizeToken(t))
				out = sc.group(out)
				continue
			}
			if t == ">" || t == ">>" || t == "<" || redirRe.MatchString(t) {
				target = takesTarget(t)
				out = append(out, t)
				continue
			}
		}
		target = false
		// A wrapper's options, option values and operands are ordinary
		// arguments, but they keep the program slot open for the word after
		// them. The role is decided on the normalised word, the form
		// program() sees, so both agree on where the program is.
		if start && wrap != nil && t != "\n" {
			n := normalizeToken(t)
			if r := wrap.next(n); r != wrapProgram {
				out = append(out, n)
				if r == wrapStop {
					start, wrap = false, nil
				}
				continue
			}
		}
		wrap = nil
		switch {
		case t == "\n":
			t = ";" // a newline separates commands exactly like ";"
		case start && (bareRe.MatchString(t) || quotedBare(t)):
			// A program resolved through PATH (base64, python3) is never
			// per-victim random; paths such as /tmp/x or ./x still are.
			// Quoted ('id', "wget") it is the same program: markerRe made
			// short ones <tok>, a non-recon program (audit M2).
		default:
			t = normalizeToken(t)
		}
		out = append(out, t)
		if start && wrappers[t] != nil {
			wrap = &wrapState{name: t, spec: wrappers[t], operands: wrappers[t].operands}
		}
		start = operators[t] || t == "(" || (start && (wrap != nil || isAssignment(t) || reserved[t]))
	}
	return out
}

// heredoc is a << awaiting its body: the delimiter after quote removal,
// whether <<- strips leading tabs, and the index of its placeholder token.
// skipBodies fills in the body's lines.
type heredoc struct {
	delim string
	tabs  bool
	slot  int
	lines []string // encoded, with their litNLs at most MaxHeredocBodyBytes
	cut   bool     // the body had more than that
}

// token is the heredoc's placeholder followed by its body, each line
// normalised like a quoted word's text and introduced by litNL, so the body
// is data inside one token: it never adds commands or a program (the
// program slot sees the placeholder prefix), but two droppers that write
// different scripts through the same wrapper no longer share a fingerprint
// (audit I2; the echo "..." > f form always kept its content). An empty
// body leaves the bare placeholder.
func (h heredoc) token() string {
	var b strings.Builder
	b.WriteString(heredocTok)
	for _, l := range h.lines {
		b.WriteString(litNL)
		b.WriteString(l)
	}
	if h.cut {
		b.WriteString(litNL + litMore)
	}
	return b.String()
}

// scanner yields shell tokens one at a time, so a heredoc body can be cut
// out of the source by lines and tokenising resumes after it. Tokens are
// what tokenRe (normalize_test.go) specifies: operators and redirections,
// a newline, a quoted string, or a run of other non-space bytes. Every
// step only moves forward, and the one search that can fail (a quote with
// no partner) fails at most once per quote character, so a pass is linear.
type scanner struct {
	s          string
	pos        int
	tok        string
	start, end int // tok's source span
	word       bool
}

func (sc *scanner) ok() bool { return sc.start >= 0 }

// next advances to the next token; ok() is false at the end.
func (sc *scanner) next() {
	s, p := sc.s, sc.pos
	for p < len(s) && (s[p] == ' ' || s[p] == '\t' || s[p] == '\r' || s[p] == '\f') {
		p++
	}
	if p >= len(s) {
		sc.start, sc.end, sc.tok, sc.word, sc.pos = -1, len(s), "", false, len(s)
		return
	}
	n, word := tokenLen(s[p:])
	sc.start, sc.end, sc.word, sc.pos = p, p+n, word, p+n
	sc.tok = s[p : p+n]
}

// tokenLen returns the length of the token at the start of s (s[0] is not
// blank) and whether it is a word (quoted or bare) rather than syntax.
func tokenLen(s string) (int, bool) {
	has := func(p string) bool { return strings.HasPrefix(s, p) }
	d := 0
	for d < len(s) && s[d] >= '0' && s[d] <= '9' {
		d++
	}
	// \d*<<<, \d*<<-?: a here-string or heredoc, with an optional fd
	// (`0<<EOF` read the 0 as the program; re-review item 3).
	switch t := s[d:]; {
	case strings.HasPrefix(t, "<<<"), strings.HasPrefix(t, "<<-"):
		return d + 3, false
	case strings.HasPrefix(t, "<<"):
		return d + 2, false
	}
	if d < len(s) && (s[d] == '>' || s[d] == '<') {
		// \d*(?:>>?|<)&(?:\d+|-)? : an fd duplication or close.
		r := d + 1
		if s[d] == '>' && r < len(s) && s[r] == '>' && r+1 < len(s) && s[r+1] == '&' {
			r++
		}
		if r < len(s) && s[r] == '&' {
			r++
			if r < len(s) && s[r] == '-' {
				return r + 1, false
			}
			for r < len(s) && s[r] >= '0' && s[r] <= '9' {
				r++
			}
			return r, false
		}
		// \d*>| (clobber) and \d*<> (read-write) are one redirection; so is
		// \d+< (`0</dev/null id` read the 0 as the program).
		if d+1 < len(s) && (s[d] == '>' && s[d+1] == '|' || s[d] == '<' && s[d+1] == '>') {
			return d + 2, false
		}
		if d > 0 && s[d] == '<' {
			return d + 1, false
		}
		if d > 0 && s[d] == '>' { // \d+>>?
			if d+1 < len(s) && s[d+1] == '>' {
				return d + 2, false
			}
			return d + 1, false
		}
	}
	switch c := s[0]; c {
	case '&':
		if has("&>>") {
			return 3, false
		}
		if has("&>") || has("&&") {
			return 2, false
		}
		return 1, false
	case '\n', ';', '(', ')', '<':
		return 1, false
	case '|':
		if has("||") {
			return 2, false
		}
		return 1, false
	case '>':
		if has(">>") {
			return 2, false
		}
		return 1, false
	case '"', '\'':
		if i := strings.IndexByte(s[1:], c); i >= 0 {
			return i + 2, true
		}
	}
	n := 0
	for n < len(s) && !isBreak(s[n]) {
		n++
	}
	return n, true
}

// isBreak reports whether c ends a bare word: [\s;|&<>()].
func isBreak(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f', ';', '|', '&', '<', '>', '(', ')':
		return true
	}
	return false
}

// delimiter consumes the word after a << and returns it after bash's quote
// removal, reading the source directly rather than tokens: a quote may hold
// blanks and a backslash may escape one (`<<E"O F"`, `<<E\ OF`), which the
// bare-word token splits, and trimming only a word's outer quotes left
// delimiters that never matched, hiding every later command (audit I1).
// The word runs to the first unquoted, unescaped blank or operator byte (the
// scanner's isBreak). Quote removal follows bash 5 for a heredoc word, each
// form checked against bash:
//   - unquoted: `\` keeps the next byte, `\` + newline is removed (a line
//     continuation), and `$` before a quote is dropped;
//   - '...' keeps everything;
//   - "..." and $"..." : `\` escapes only $, `, " and \, and `\` + newline
//     is removed;
//   - $'...' decodes ANSI-C escapes (see ansiEscape).
//
// A quote left open is a syntax error in bash (nothing runs), so it is not
// read as a heredoc: the words after the << are then tokenised as usual
// and nothing is hidden. No word at all (a newline or operator follows) is
// not a heredoc either.
func (sc *scanner) delimiter() (string, bool) {
	s, i := sc.s, sc.pos
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\f') {
		i++
	}
	if i >= len(s) || isBreak(s[i]) {
		return "", false
	}
	var b strings.Builder
	for i < len(s) && !isBreak(s[i]) {
		switch c := s[i]; {
		case c == '\\':
			switch {
			case i+1 >= len(s):
				b.WriteByte(c)
			case s[i+1] != '\n':
				b.WriteByte(s[i+1])
			}
			i += 2
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return "", false
			}
			b.WriteString(s[i+1 : i+1+j])
			i += j + 2
		case c == '"' || c == '$' && i+1 < len(s) && s[i+1] == '"':
			if c == '$' {
				i++
			}
			end, ok := doubleQuoted(&b, s, i+1)
			if !ok {
				return "", false
			}
			i = end
		case c == '$' && i+1 < len(s) && s[i+1] == '\'':
			end, ok := ansiQuoted(&b, s, i+2)
			if !ok {
				return "", false
			}
			i = end
		default:
			b.WriteByte(c)
			i++
		}
	}
	sc.pos = min(i, len(s))
	return b.String(), true
}

// doubleQuoted decodes a "..." body starting at s[i] into b and returns the
// index after the closing quote.
func doubleQuoted(b *strings.Builder, s string, i int) (int, bool) {
	for ; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			return i + 1, true
		case c == '\\' && i+1 < len(s) && s[i+1] == '\n':
			i++
		case c == '\\' && i+1 < len(s) && strings.IndexByte("$`\"\\", s[i+1]) >= 0:
			i++
			b.WriteByte(s[i])
		default:
			b.WriteByte(c)
		}
	}
	return i, false
}

// ansiQuoted decodes a $'...' body starting at s[i] into b and returns the
// index after the closing quote. A decoded NUL ends the string's content, as
// in bash; the rest up to the quote is dropped.
func ansiQuoted(b *strings.Builder, s string, i int) (int, bool) {
	nul := false
	for i < len(s) {
		c := s[i]
		if c == '\'' {
			return i + 1, true
		}
		if c != '\\' || i+1 >= len(s) {
			if !nul {
				b.WriteByte(c)
			}
			i++
			continue
		}
		r, n, raw := ansiEscape(s[i+1:])
		switch {
		case nul:
		case raw:
			b.WriteByte(byte(r))
		case r == 0:
			nul = true
		default:
			b.WriteRune(r)
		}
		i += 1 + n
	}
	return i, false
}

// ansiEscape decodes the escape after a backslash in $'...': the byte count
// it spans, and the value, which is a raw byte (octal and \x forms, which
// bash emits as bytes) or a rune (\u, \U). An unknown escape keeps its
// backslash, as bash does; it is returned as the backslash alone, spanning
// nothing, so the next byte is read on its own.
func ansiEscape(s string) (r rune, n int, raw bool) {
	c := s[0]
	if v, ok := ansiSimple[c]; ok {
		return v, 1, false
	}
	digits := func(max int, base int) (int, int) {
		v, k := 0, 0
		for k < max && k < len(s)-1 {
			d := strings.IndexByte("0123456789abcdef"[:base], lower(s[1+k]))
			if d < 0 {
				break
			}
			v, k = v*base+d, k+1
		}
		return v, k
	}
	switch c {
	case '0', '1', '2', '3', '4', '5', '6', '7':
		v, k := 0, 0
		for k < 3 && k < len(s) && s[k] >= '0' && s[k] <= '7' {
			v, k = v*8+int(s[k]-'0'), k+1
		}
		return rune(v & 0xff), k, v&0xff != 0
	case 'x':
		if v, k := digits(2, 16); k > 0 {
			return rune(v), 1 + k, v != 0
		}
	case 'u', 'U':
		max := 4
		if c == 'U' {
			max = 8
		}
		if v, k := digits(max, 16); k > 0 {
			if v > utf8.MaxRune {
				v = utf8.RuneError
			}
			return rune(v), 1 + k, false
		}
	case 'c':
		if len(s) > 1 {
			return rune(s[1] & 0x1f), 2, true
		}
	}
	return '\\', 0, true
}

var ansiSimple = map[byte]rune{'a': 7, 'b': 8, 'e': 27, 'E': 27, 'f': 12, 'n': 10, 'r': 13, 't': 9, 'v': 11, '\\': '\\', '\'': '\'', '"': '"', '?': '?'}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// skipBodies cuts the pending heredocs' bodies out of the source, in order,
// starting after the current newline, and returns them with their lines.
// Each ends on the first line equal to its delimiter, compared as a whole
// line (so an indented `  EOF` does not end it, as in bash), with a trailing
// \r dropped and, for <<-, leading tabs stripped (from body lines too). The
// scanner resumes at the newline after the last terminator. Every line is
// looked at once and at most MaxHeredocBodyBytes of each body is kept, so
// the pass stays linear.
func (sc *scanner) skipBodies(docs []heredoc) []heredoc {
	s, p := sc.s, sc.end
	resume := len(s) // an unterminated body runs to the end
	for i := range docs {
		d := &docs[i]
		budget := MaxHeredocBodyBytes
		resume = len(s)
		for p < len(s) {
			e := strings.IndexByte(s[p:], '\n')
			if e < 0 {
				e = len(s)
			} else {
				e += p
			}
			line := strings.TrimSuffix(s[p:e], "\r")
			if d.tabs {
				line = strings.TrimLeft(line, "\t")
			}
			p = e + 1
			if line == d.delim {
				resume = e
				break
			}
			if d.cut {
				continue // still looking for the terminator
			}
			// Each line is encoded once. One that does not fit is cut to
			// the raw prefix as long as the room left, or, if that still
			// encodes too long, a quarter of it: no substitution or escape
			// more than quadruples its bytes (< is <lt>, \r is <cr>), so
			// that prefix fits. At most two more encodings of at most
			// MaxHeredocBodyBytes each, so the pass stays linear.
			enc := escapeLiterals(line)
			if cost := len(litNL) + len(enc); cost <= budget {
				d.lines = append(d.lines, enc)
				budget -= cost
				continue
			}
			if room := budget - len(litNL); room >= 0 {
				// The line may be shorter than the room (it is its
				// escapes that do not fit): clamp before cutting.
				enc = escapeLiterals(line[:runeCut(line, min(room, len(line)))])
				if len(enc) > room {
					enc = escapeLiterals(line[:runeCut(line, min(room/4, len(line)))])
				}
				d.lines = append(d.lines, enc)
			}
			d.cut = true
		}
	}
	sc.pos = resume // the newline ending the last terminator, or the end
	return docs
}

// group appends the rest of a redirection target's $(...) group (see
// groupEnd) after the target word just emitted, normalising each word.
func (sc *scanner) group(out []string) []string {
	save := *sc
	sc.next()
	if !sc.ok() || sc.tok != "(" {
		*sc = save
		return out
	}
	depth := 0
	for ; sc.ok(); sc.next() {
		switch t := sc.tok; {
		case t == "\n" || isHeredoc(t) || operators[t]:
			*sc = save
			return out
		case t == "(":
			depth++
		case t == ")":
			depth--
		}
		out = append(out, normalizeToken(sc.tok))
		save = *sc
		if depth == 0 {
			return out
		}
	}
	return out
}

// wrapSpec describes a wrapper's command line ahead of its program.
type wrapSpec struct {
	flags    string          // short options without a value
	valued   string          // short options taking a value, attached or the next word
	long     map[string]bool // long options; true = takes a value (next word unless --opt=v)
	operands int             // words before the program (timeout's DURATION)
	numeric  bool            // nice's historic -N form
}

type wrapRole int

const (
	wrapOwn     wrapRole = iota // the wrapper's own option, value or operand
	wrapProgram                 // the program the wrapper runs
	wrapStop                    // an unknown option: stop treating words as the wrapper's
)

type wrapState struct {
	name     string
	spec     *wrapSpec
	value    bool // the next word is an option's value
	operands int
	endOpts  bool // after "--"
}

// next classifies the next (normalised) word after a wrapper.
func (w *wrapState) next(n string) wrapRole {
	switch {
	case operators[n] || n == "(" || n == ")" || n == "<" || n == ">" || n == ">>" || isHeredoc(n) || strings.HasPrefix(n, heredocTok) || redirRe.MatchString(n):
		// Shell syntax is never a wrapper's word: `sudo -u ; id` must not
		// swallow the ";" as the -u value and run on into the next command.
		return wrapProgram
	case w.value:
		w.value = false
		return wrapOwn
	case !w.endOpts && n == "--":
		w.endOpts = true
		return wrapOwn
	case !w.endOpts && len(n) > 1 && n[0] == '-':
		return w.option(n)
	case w.operands > 0:
		w.operands--
		return wrapOwn
	}
	return wrapProgram
}

func (w *wrapState) option(n string) wrapRole {
	if long, ok := strings.CutPrefix(n, "--"); ok {
		name, _, inline := strings.Cut(long, "=")
		valued, known := w.spec.long[name]
		if !known {
			return wrapStop
		}
		w.value = valued && !inline
		return wrapOwn
	}
	if w.spec.numeric && numRe.MatchString(n[1:]) {
		return wrapOwn
	}
	for i := 1; i < len(n); i++ {
		switch c := n[i]; {
		case strings.IndexByte(w.spec.valued, c) >= 0:
			w.value = i == len(n)-1 // otherwise the value is attached (-oL)
			return wrapOwn
		case strings.IndexByte(w.spec.flags, c) < 0:
			return wrapStop
		}
	}
	return wrapOwn
}

// isHeredoc reports whether t is a heredoc operator, <<, <<- or either
// with an fd (0<<); hereString, whether it is <<< with an optional fd.
func isHeredoc(t string) bool {
	op := strings.TrimLeft(t, "0123456789")
	return op == "<<" || op == "<<-"
}

func hereString(t string) bool { return strings.TrimLeft(t, "0123456789") == "<<<" }

// quotedBare reports whether t is a quoted word whose text is a bare
// program name.
func quotedBare(t string) bool {
	return len(t) >= 2 && (t[0] == '"' || t[0] == '\'') && t[len(t)-1] == t[0] && bareRe.MatchString(t[1:len(t)-1])
}

func isAssignment(t string) bool {
	eq := strings.IndexByte(t, '=')
	return eq > 0 && !strings.HasPrefix(t, "-") && bareRe.MatchString(strings.ToLower(t[:eq]))
}

func normalizeToken(t string) string {
	quote, inner := "", t
	if len(t) >= 2 && (t[0] == '"' || t[0] == '\'') && t[len(t)-1] == t[0] {
		quote, inner = t[:1], t[1:len(t)-1]
	}
	switch {
	case redirRe.MatchString(t):
		return t
	case operators[t] || t == ">" || t == ">>" || t == "<" || t == "(" || t == ")":
		return t
	case quote != "" && markerRe.MatchString(inner):
		return "<tok>"
	case quote == "":
		if keyTypes.MatchString(inner) {
			return inner
		}
		if r, ok := wholeToken(inner); ok {
			return r
		}
	}
	if strings.ContainsAny(inner, "<>") {
		return quote + escapeLiterals(inner) + quote
	}
	return quote + substitute(inner) + quote
}

// escapeLiterals encodes an attacker's own < and > as <lt> and <gt>, which
// no substitution produces, so every <...> left in a word is either the
// normaliser's placeholder or this escape: a typed `"<url>"` can neither
// count as a URL toward Distinctive nor share a fingerprint with a real one.
// A backslash escape (\<) would collide with a real placeholder after an
// attacker's backslash (`"\http://x"` gives \<url>). Only quoted words can
// hold < or >, the tokenizer splits them out elsewhere.
//
// The pieces between the literals are substituted independently, which is
// exactly equivalent to substituting the whole word: no pattern can match
// across a < or >, and one reads as a word boundary either way.
func escapeLiterals(inner string) string {
	var b strings.Builder
	b.Grow(len(inner) + len(inner)/4)
	for {
		i := strings.IndexAny(inner, "<>")
		if i < 0 {
			b.WriteString(substitute(inner))
			return b.String()
		}
		if i > 0 {
			b.WriteString(substitute(inner[:i]))
		}
		if inner[i] == '<' {
			b.WriteString(litLT)
		} else {
			b.WriteString(litGT)
		}
		inner = inner[i+1:]
	}
}

// substitute replaces the randomised parts inside a word (or a piece of one
// free of < and >) with placeholders.
func substitute(inner string) string {
	inner = keyBody.ReplaceAllStringFunc(inner, func(b string) string {
		if isKeyBlob(b) {
			return "<key>"
		}
		return b
	})
	inner = urlRe.ReplaceAllString(inner, "<url>")
	inner = ipRe.ReplaceAllString(inner, "<ip>")
	inner = tmpRe.ReplaceAllString(inner, "/tmp/<f>")
	inner = randomInside(inner)
	return escapeNL.Replace(inner) // one command per encoded line
}

// isKeyBlob reports whether b decodes to an SSH wire blob (length-prefixed
// key type), so a base64 payload that merely contains "AAAA" is not a key.
// Only whole quanta are decoded: captured keys are often truncated in logs.
func isKeyBlob(b string) bool {
	b = strings.TrimRight(b, "=")
	raw, err := base64.RawStdEncoding.DecodeString(b[:len(b)/4*4])
	if err != nil || len(raw) < 4 {
		return false
	}
	n := binary.BigEndian.Uint32(raw[:4])
	return n > 0 && int64(n) <= int64(len(raw)-4) && keyTypes.Match(raw[4:4+n])
}

func wholeToken(t string) (string, bool) {
	switch {
	case t == "":
		return "", false
	case keyBody.FindString(t) == t && isKeyBlob(t):
		return "<key>", true
	case urlRe.FindString(t) == t:
		return "<url>", true
	case ipRe.FindString(t) == t:
		return "<ip>", true
	case tmpRe.FindString(t) == t:
		return "/tmp/<f>", true
	case hexRe.MatchString(t):
		return "<hex>", true
	case numRe.MatchString(t):
		return "<n>", true
	case b64Re.MatchString(t) && strings.ContainsAny(t, "0123456789") && strings.ToLower(t) != t && strings.ToUpper(t) != t:
		return "<b64>", true
	}
	return "", false
}

// randomInside replaces hex runs of >= 16 chars, numbers of >= 6 digits and
// mixed letter+digit words of >= 6 chars (random passwords, file names)
// inside a larger token, keeping `\n` escapes: whole tokens get the same
// treatment in wholeToken, and quoted text used to keep per-victim numbers
// (`"root:123456789"`, audit M4).
func randomInside(s string) string {
	parts := strings.Split(s, `\n`)
	for i, p := range parts {
		p = hexIn.ReplaceAllString(p, "<hex>")
		p = numIn.ReplaceAllString(p, "<n>")
		parts[i] = randRe.ReplaceAllStringFunc(p, func(w string) string {
			if len(w) >= 6 && !keyTypeWords[w] {
				return "<tok>"
			}
			return w
		})
	}
	return strings.Join(parts, `\n`)
}

// EncodeLine is one command event's normalised tokens, joined by tokSep.
func EncodeLine(cmd string) string { return strings.Join(NormalizeCommand(cmd), tokSep) }

// Join encodes a session script from its encoded lines.
func Join(lines []string) string { return strings.Join(lines, lineSep) }

// Split decodes a Join-encoded script into per-line token lists.
func Split(enc string) [][]string {
	if enc == "" {
		return nil
	}
	lines := strings.Split(enc, lineSep)
	out := make([][]string, len(lines))
	for i, l := range lines {
		if l == "" {
			out[i] = []string{}
			continue
		}
		out[i] = strings.Split(l, tokSep)
	}
	return out
}

// displayer renders the encoding for people: separators become spaces and
// newlines, and escaped literals read shell-style as \< and \>.
// A heredoc body's line breaks read as \n, so the body stays inside its
// command's line: `cat << <heredoc>\nwget <url>\nsh x > /tmp/<f>`.
var displayer = strings.NewReplacer(tokSep, " ", lineSep, "\n", litLT, `\<`, litGT, `\>`, litNL, `\n`, litCR, `\r`)

const ellipsis = "…"

// Display renders an encoded script for people, capped at max bytes
// including the ellipsis that marks a cut (a cap too small for the
// ellipsis gets a bare prefix); max <= 0 means no cap. The cut never
// splits a rune.
func Display(enc string, max int) string {
	s := displayer.Replace(enc)
	if max <= 0 || len(s) <= max {
		return s
	}
	if max < len(ellipsis) {
		return s[:runeCut(s, max)]
	}
	return s[:runeCut(s, max-len(ellipsis))] + ellipsis
}

// runeCut returns the largest n' <= n where s[:n'] ends on a rune boundary.
// Only a valid multi-byte rune straddling n moves the cut back (by at most
// UTFMax-1 bytes); an invalid byte is its own "rune", so a run of stray
// continuation bytes cannot drag the cut back to the start.
func runeCut(s string, n int) int {
	if n >= len(s) || utf8.RuneStart(s[n]) {
		return n
	}
	for j := n - 1; j >= 0 && j > n-utf8.UTFMax; j-- {
		if utf8.RuneStart(s[j]) {
			if r, size := utf8.DecodeRuneInString(s[j:]); !(r == utf8.RuneError && size == 1) && j+size > n {
				return j
			}
			break
		}
	}
	return n
}

// Fingerprint is the lower-hex SHA-256 of a Join-encoded script.
func Fingerprint(enc string) string {
	sum := sha256.Sum256([]byte(enc))
	return hex.EncodeToString(sum[:])
}

func segments(cmds [][]string) [][]string {
	var out [][]string
	for _, c := range cmds {
		var cur []string
		for _, t := range c {
			if operators[t] {
				if len(cur) > 0 {
					out = append(out, cur)
				}
				cur = nil
				continue
			}
			cur = append(cur, t)
		}
		if len(cur) > 0 {
			out = append(out, cur)
		}
	}
	return out
}

// CommandCount counts simple commands, not input lines: bots often send a
// whole script on one line.
func CommandCount(cmds [][]string) int { return len(segments(cmds)) }

// Reserved words that are syntax in the program slot, never a program:
// program() skips them and the word after them is still the program (`if
// id`, `then wget`, `! grep`, `{ id`), so NormalizeCommand keeps the slot
// open after them. In a segment led by one of noProgram (`for i in ...`,
// `case $x in`, `[[ -f x ]]`, `function f`) no word runs as a program.
// Reading them as programs made recon-only scripts Distinctive (audit M1).
var (
	reserved = map[string]bool{
		"if": true, "then": true, "else": true, "elif": true, "fi": true, "do": true, "done": true,
		"while": true, "until": true, "esac": true, "{": true, "}": true, "!": true, "]]": true,
	}
	noProgram = map[string]bool{"for": true, "case": true, "select": true, "[[": true, "function": true}
)

var recon = map[string]bool{
	"uname": true, "whoami": true, "id": true, "hostname": true, "uptime": true, "nproc": true,
	"free": true, "pwd": true, "ls": true, "w": true, "cat": true, "lscpu": true, "ifconfig": true,
	"ip": true, "ps": true, "top": true, "df": true, "which": true, "history": true, "exit": true,
	"cd": true, "unset": true, "echo": true, "export": true, "grep": true, "head": true, "tail": true,
	"wc": true, "awk": true, "sort": true, "uniq": true, "cut": true, "tr": true, "crontab": true,
	"find": true, "locate": true, "lspci": true, "dmidecode": true,
	// Tool probes: `command -v wget` reports the wrapper itself (-v does not
	// run its operand), and type/hash only look programs up.
	"command": true, "type": true, "hash": true,
}

// takesTarget reports whether redirection t is followed by a target word.
// fd duplications and closes (2>&1, <&3, 2>&-) carry theirs inside the
// token; a bare >& or <& (`>& f`, bash's redirect-both form) and every other
// redirection (>, <, 2>, &>, <<<) take the next word.
func takesTarget(t string) bool {
	i := strings.LastIndexByte(t, '&')
	return i <= 0 || i == len(t)-1
}

// groupEnd returns the index of the last word of a redirection target that
// starts at toks[i]. The tokenizer splits an unquoted `$(evil)` at "(", so a
// "(" right after the target opens a group that belongs to it, up to the
// matching ")": `> $(evil) python3` runs python3, not evil. The group also
// ends before a newline, an operator or a heredoc, which end the command or
// need the main loop, so an unterminated group never swallows later
// commands. Only shell syntax decides it, and parens and those stops are the
// same before and after normalisation, so NormalizeCommand (raw words, in
// scanner.group, which applies these rules) and program() (normalised
// words) agree. It never drops a word: callers emit
// or skip every index up to the one returned.
func groupEnd(toks []string, i int) int {
	if i+1 >= len(toks) || toks[i+1] != "(" {
		return i
	}
	depth := 0
	for j := i + 1; j < len(toks); j++ {
		switch toks[j] {
		case "\n":
			return j - 1
		case "(":
			depth++
		case ")":
			if depth--; depth == 0 {
				return j
			}
		default:
			if operators[toks[j]] || isHeredoc(toks[j]) {
				return j - 1
			}
		}
	}
	return len(toks) - 1
}

// program returns a simple command's program, skipping subshell parens,
// variable assignments, redirections with their targets and wrappers with
// their own options.
// A wrapper followed by an option it does not know reports the wrapper
// itself: guessing which later word is the program could name an argument.
func program(seg []string) string {
	var wrap *wrapState
	target := false // the previous word was a redirection awaiting its target
	for i := 0; i < len(seg); i++ {
		t := seg[i]
		if target {
			target = false
			i = groupEnd(seg, i)
			continue
		}
		// A redirection and its target are neither the program nor a
		// wrapper's word, wherever they sit: `2>/dev/null id` runs id.
		// fd duplications (2>&1) hold their target inside the token.
		if t == ">" || t == ">>" || t == "<" || isHeredoc(t) || redirRe.MatchString(t) {
			target = takesTarget(t)
			continue
		}
		if wrap != nil {
			switch wrap.next(t) {
			case wrapOwn:
				continue
			case wrapStop:
				return wrap.name
			}
			wrap = nil
		}
		if t == "(" || t == ")" || strings.HasPrefix(t, heredocTok) ||
			(strings.Contains(t, "=") && !strings.HasPrefix(t, "-")) || strings.HasSuffix(t, "$") {
			continue
		}
		if reserved[t] {
			continue
		}
		if noProgram[t] {
			return ""
		}
		if spec := wrappers[t]; spec != nil {
			wrap = &wrapState{name: t, spec: spec, operands: spec.operands}
			continue
		}
		return path.Base(strings.Trim(t, `"'`))
	}
	return ""
}

// Distinctive reports whether a script is specific enough to link sessions:
// at least 5 simple commands (Shamsi et al. 2022) and not generic recon.
func Distinctive(cmds [][]string) bool {
	segs := segments(cmds)
	if len(segs) < 5 {
		return false
	}
	for _, s := range segs {
		for _, t := range s {
			if strings.Contains(t, "<key>") || strings.Contains(t, "<url>") {
				return true
			}
		}
		if p := program(s); p != "" && !recon[p] {
			return true
		}
	}
	return false
}

// Common reports whether a value is shared too widely to identify an
// operator. The 5-actor minimum keeps a small honeypot, where two actors are
// already several percent, from treating every shared value as common.
func Common(actors, population int) (bool, string) {
	if actors > MaxLinkActors {
		return true, fmt.Sprintf("common: used by %d actors", actors)
	}
	if actors >= MinCommonActors && population > 0 {
		if p := float64(actors) * 100 / float64(population); p > MaxLinkPercent {
			return true, fmt.Sprintf("common: used by %.1f%% of actors", p)
		}
	}
	return false, ""
}

// LinkDecision is the only place the script link rule lives; the grouping and
// the Scripts panel both call it, so they cannot disagree.
func LinkDecision(distinctive bool, actors, population int) (bool, string) {
	if !distinctive {
		return false, "not distinctive: fewer than 5 commands or recon only"
	}
	if common, why := Common(actors, population); common {
		return false, why
	}
	return true, fmt.Sprintf("distinctive, used by %d actors", actors)
}
