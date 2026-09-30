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
// Tokens and its cap, the family constants, and MaxCommands and
// MaxNormalizedBytes, with which the store cuts a session's true capped
// prefix; not a pure refactor or a comment): the campaign worker compares it with the version stored in the
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
// digits) and encodes a real line break as <nl>/<cr>; 5 = words, comments
// and escapes follow bash (final audit I1): an unquoted # at a word start
// begins a comment, which yields no token (a shebang line is no program), a
// backslash escapes the next byte and a backslash-newline is a line
// continuation everywhere outside quotes (inside operators too), a "..."
// ends only at an unescaped quote, a quote may start mid-word, and `...`,
// ${...} and a $(...) inside "..." are read whole; an unquoted heredoc body
// joins backslash-continued lines before looking for its terminator; a
// delimiter keeps $(...), `...` and ${...} literally (M1) and decodes $'...'
// as bash 5.2 does (\c?, \c\\, a NUL, bash's UTF-8 for \u and \U; M2); \r,
// \f and the separator bytes are word bytes (these two encode as <us> and
// <rs>) and only an all-CRLF event has its line endings read as LF (M7); an
// arithmetic (( )) runs no program and [, test, :, true, false and sleep are
// recon (M4); a quoted delimiter's placeholder is <heredoc-q> (M5);
// ExtractKeys follows OpenSSH's mpint and RSA modulus rules and hashes the
// key as ssh-keygen re-encodes it (M6: its ssh_key evidence is rebuilt by
// the same reset); the pin covers MaxCommands and MaxNormalizedBytes (M3).
const Version = 5

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

	// A heredoc's placeholder (heredocQTok for a quoted delimiter); its
	// body follows inside the same token, one litNL per body line, and
	// litMore marks a body cut at MaxHeredocBodyBytes.
	heredocTok  = "<heredoc>"
	heredocQTok = "<heredoc-q>"
	litNL       = "<nl>"
	litCR       = "<cr>"
	litMore     = "<more>"
	// An attacker's own separator bytes inside a word: ordinary bytes to
	// bash, so they are kept (as these) rather than read as blanks.
	litUS = "<us>"
	litRS = "<rs>"

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
	// A real line break inside a word encodes as a placeholder, not as \n:
	// a typed backslash-n and a real newline used to encode alike (audit M4).
	// The separator bytes get placeholders too, so the encoding stays
	// exactly reversible: they used to be stripped to blanks, which split
	// `echo a\x1fb` into the words of `echo a b` (final audit M7).
	escapeNL = strings.NewReplacer("\r", litCR, "\n", litNL, tokSep, litUS, lineSep, litRS)
)

// NormalizeCommand splits cmd into shell tokens and replaces the parts bots
// randomise with placeholders, including inside quoted strings.
func NormalizeCommand(cmd string) []string {
	cmd = crlfToLF(cmd)
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
			if d, quoted, ok := sc.delimiter(); ok {
				pending = append(pending, heredoc{delim: d, tabs: strings.HasSuffix(t, "-"), quoted: quoted, slot: len(out)})
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

// crlfToLF drops the \r of every line ending when the whole event uses CRLF
// (every \n follows a \r, and a last line ends with \r if there is no \n):
// a CRLF client's script then encodes like the same script sent with LF.
// Anywhere else a \r is an ordinary byte of its word, as it is to bash:
// `wget\rhttp://x/y` is one word (bash reports the command not found) and
// no longer encodes like `wget http://x/y`, and an `EOF\r` line does not
// end a heredoc an LF line opened (bash keeps reading the body; audit M7).
func crlfToLF(s string) string {
	if !strings.Contains(s, "\r") {
		return s
	}
	n := strings.Count(s, "\n")
	if n != strings.Count(s, "\r\n") || (n == 0 && !strings.HasSuffix(s, "\r")) {
		return s
	}
	return strings.TrimSuffix(strings.ReplaceAll(s, "\r\n", "\n"), "\r")
}

// heredoc is a << awaiting its body: the delimiter after quote removal,
// whether <<- strips leading tabs, whether any part of the delimiter was
// quoted (bash then expands nothing in the body and keeps its backslash
// line continuations), and the index of its placeholder token. skipBodies
// fills in the body's lines.
type heredoc struct {
	delim  string
	tabs   bool
	quoted bool
	slot   int
	lines  []string // encoded, with their litNLs at most MaxHeredocBodyBytes
	cut    bool     // the body had more than that
}

// token is the heredoc's placeholder followed by its body, each line
// normalised like a quoted word's text and introduced by litNL, so the body
// is data inside one token: it never adds commands or a program (the
// program slot sees the placeholder prefix), but two droppers that write
// different scripts through the same wrapper no longer share a fingerprint
// (audit I2; the echo "..." > f form always kept its content). An empty
// body leaves the bare placeholder. A quoted delimiter gives heredocQTok:
// bash runs the $(...) in an unquoted body and not in a quoted one, so the
// two must not share an encoding (final audit M5).
func (h heredoc) token() string {
	var b strings.Builder
	if h.quoted {
		b.WriteString(heredocQTok)
	} else {
		b.WriteString(heredocTok)
	}
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
// out of the source by lines and tokenising resumes after it. It reads
// bash's word syntax (POSIX token recognition plus bash's $'...', $"..."
// and ${...}):
//   - blanks are space and tab; a backslash-newline outside quotes is a
//     line continuation and is removed wherever it appears, between tokens,
//     inside a word and inside an operator (`>\<newline>>` is >>);
//   - an unquoted `#` at the start of a word begins a comment that runs to
//     the end of the line and yields no token (a shebang line is one);
//   - a word runs to the first unquoted blank or operator byte. Inside it a
//     backslash escapes the next byte, '...' is literal, "..." ends only at
//     a `"` no backslash escapes, and `...`, $'...', $"..." and ${...} are
//     read whole, each by bash's rules for it (see span). A quote may start
//     mid-word (x'a b'y is one word);
//   - an operator or redirection is what tokenRe (normalize_test.go)
//     lists, plus `((` when it opens an arithmetic command.
//
// A word token's text is its source with the continuations outside quotes
// removed; the quotes and escapes themselves are kept, so the encoding
// stays exactly as specific as the source (`echo "\"   x"` and `echo "\"
// x"` used to encode alike). An opener that never closes is a bash syntax
// error; the scanner then reads it as an ordinary byte, so a stray quote can
// never hide the commands after it. $(...) outside double quotes is not read
// whole: it tokenises as $ ( ... ), which groupEnd relies on.
//
// Every construct's end is computed once per opening position (spans), and
// every step moves forward, so a pass is linear on everything measured
// (final audit I1, see the timing notes in version_test.go).
type scanner struct {
	s          string
	pos        int
	tok        string
	start, end int         // tok's source span
	spans      map[int]int // span's memo: kind | open<<3 -> end, or -1
	// strict is set inside a command substitution (parenEnd): there a
	// construct that never closes leaves the substitution unclosed too
	// (failed), as it does in bash, instead of being read as ordinary
	// bytes. Reading on would rescan the rest of the input once per
	// nesting level, which made `"$("$(...` quadratic.
	strict, failed bool
}

func (sc *scanner) ok() bool { return sc.start >= 0 }

// next advances to the next token; ok() is false at the end.
func (sc *scanner) next() {
	s, p := sc.s, sc.pos
	for {
		p = skipBlanks(s, p)
		if p < len(s) && s[p] == '#' {
			if e := strings.IndexByte(s[p:], '\n'); e >= 0 {
				p += e
			} else {
				p = len(s)
			}
			continue
		}
		break
	}
	if p >= len(s) {
		sc.start, sc.end, sc.tok, sc.pos = -1, len(s), "", len(s)
		return
	}
	tok, e := sc.operator(p)
	if e == p {
		e, tok = sc.word(p)
	}
	sc.start, sc.end, sc.tok, sc.pos = p, e, tok, e
}

// skipBlanks skips spaces, tabs and line continuations.
func skipBlanks(s string, p int) int {
	for p < len(s) {
		switch {
		case s[p] == ' ' || s[p] == '\t':
			p++
		case s[p] == '\\' && p+1 < len(s) && s[p+1] == '\n':
			p += 2
		default:
			return p
		}
	}
	return p
}

// skipConts skips line continuations only.
func skipConts(s string, p int) int {
	for p+1 < len(s) && s[p] == '\\' && s[p+1] == '\n' {
		p += 2
	}
	return p
}

// operator reads the operator or redirection at s[p] (never a blank) and
// returns it with continuations removed, and the index after it; e == p
// means s[p] starts a word. The forms are tokenRe's: \d*<<<, \d*<<-?,
// \d*(?:>>?|<)&(?:\d+|-)?, &>>?, \d*>|, \d*<>, \d+>>?, \d+<, and the
// single operators, where an fd number counts only when a redirection
// follows it (`12abc` is a word).
func (sc *scanner) operator(p int) (string, int) {
	s := sc.s
	at := func(q int) (byte, int) {
		q = skipConts(s, q)
		if q >= len(s) {
			return 0, q
		}
		return s[q], q + 1
	}
	var r []byte
	c, n := at(p)
	for c >= '0' && c <= '9' {
		r = append(r, c)
		c, n = at(n)
	}
	d := len(r)
	if c == '<' {
		if c2, n2 := at(n); c2 == '<' {
			if c3, n3 := at(n2); c3 == '<' || c3 == '-' {
				return string(append(r, '<', '<', c3)), n3
			}
			return string(append(r, '<', '<')), n2
		}
	}
	if c == '>' || c == '<' {
		r = append(r, c)
		e := n
		c2, n2 := at(e)
		if c == '>' && c2 == '>' {
			if c3, n3 := at(n2); c3 == '&' {
				r, e = append(r, '>'), n2
				c2, n2 = c3, n3
			}
		}
		switch {
		case c2 == '&':
			r, e = append(r, '&'), n2
			c3, n3 := at(e)
			if c3 == '-' {
				return string(append(r, '-')), n3
			}
			for c3 >= '0' && c3 <= '9' {
				r, e = append(r, c3), n3
				c3, n3 = at(e)
			}
			return string(r), e
		case c == '>' && c2 == '|' || c == '<' && c2 == '>':
			return string(append(r, c2)), n2
		case d > 0 && c2 == '>':
			return string(append(r, '>')), n2
		case d > 0:
			return string(r), e
		}
	}
	if d > 0 {
		return "", p
	}
	c2, n2 := at(n)
	switch c {
	case '&':
		if c2 == '>' {
			if c3, n3 := at(n2); c3 == '>' {
				return "&>>", n3
			}
			return "&>", n2
		}
		if c2 == '&' {
			return "&&", n2
		}
		return "&", n
	case '|':
		if c2 == '|' {
			return "||", n2
		}
		return "|", n
	case '>':
		if c2 == '>' {
			return ">>", n2
		}
		return ">", n
	case '(':
		// (( opens an arithmetic command only if its inner ( closes on a )
		// that another ) follows, as bash decides it: `((i++))` runs no
		// program, `((id); w)` is two subshells running id and w.
		if c2 == '(' {
			e := sc.span(kParen, n2)
			if e >= 0 {
				if c3, _ := at(e); c3 == ')' {
					return "((", n2
				}
			}
			sc.failed = sc.failed || sc.strict && e < 0
		}
		return "(", n
	case '\n', ';', ')', '<':
		return string(c), n
	}
	return "", p
}

// word reads the word at s[p] and returns the index after it and its text
// with the continuations outside quotes removed.
func (sc *scanner) word(p int) (int, string) {
	s := sc.s
	i := p
	var conts []int
	for i < len(s) && !isBreak(s[i]) {
		c := s[i]
		var next byte
		if i+1 < len(s) {
			next = s[i+1]
		}
		switch {
		case c == '\\':
			if next == '\n' {
				conts = append(conts, i)
			}
			i += 2
		case c == '\'':
			i = sc.whole(i, kSQ, i+1)
		case c == '"':
			i = sc.whole(i, kDQ, i+1)
		case c == '`':
			i = sc.whole(i, kBQ, i+1)
		case c == '$' && next == '\'':
			i = sc.whole(i, kANSI, i+2)
		case c == '$' && next == '"':
			i = sc.whole(i, kDQ, i+2)
		case c == '$' && next == '{':
			i = sc.whole(i, kBrace, i+2)
		default:
			i++
		}
	}
	i = min(i, len(s))
	if len(conts) == 0 {
		return i, s[p:i]
	}
	var b strings.Builder
	from := p
	for _, c := range conts {
		b.WriteString(s[from:c])
		from = c + 2
	}
	b.WriteString(s[from:i])
	return i, b.String()
}

// whole returns the index after the construct opened at s[i] whose content
// starts at content, or i+1 when it never closes: the opener is then an
// ordinary byte of the word.
func (sc *scanner) whole(i, kind, content int) int {
	if e := sc.span(kind, content); e >= 0 {
		return e
	}
	if sc.strict {
		sc.failed = true
		return len(sc.s)
	}
	return i + 1
}

// Constructs span can read whole.
const (
	kSQ    = iota // '...'
	kDQ           // "..." and $"..."
	kBQ           // `...`
	kANSI         // $'...'
	kBrace        // ${...}
	kParen        // $(...) inside double quotes or ${...}, and (( lookahead
)

// span returns the index after the closing byte of the construct whose
// content starts at s[p], or -1 if it never closes. The rules are bash's,
// each checked against bash 5.2:
//   - '...': to the next ', nothing is special;
//   - $'...' and `...`: to the next unescaped ' or `;
//   - "...": to the next unescaped ", reading `...`, $(...) and ${...}
//     inside it whole, so a quote in a command substitution does not end
//     the string (`"$(echo ')"')"` is one word);
//   - ${...}: to the first } outside quotes and nested constructs (a bare {
//     does not nest), where '...' quotes even inside double quotes;
//   - $(...): tokenised like the top level, heredoc bodies and comments
//     included, to the ) that closes it; a case pattern's ) does not.
//
// A construct inside another that never closes leaves the outer one
// unclosed too. Each (kind, p) is computed once.
func (sc *scanner) span(kind, p int) int {
	if sc.spans == nil {
		sc.spans = map[int]int{}
	}
	key := p<<3 | kind
	if e, ok := sc.spans[key]; ok {
		return e
	}
	e := -1
	switch kind {
	case kSQ:
		if j := strings.IndexByte(sc.s[p:], '\''); j >= 0 {
			e = p + j + 1
		}
	case kANSI:
		e = escapedEnd(sc.s, p, '\'')
	case kBQ:
		e = escapedEnd(sc.s, p, '`')
	case kDQ, kBrace:
		e = sc.quotedEnd(kind, p)
	case kParen:
		e = sc.parenEnd(p)
	}
	sc.spans[key] = e
	return e
}

// escapedEnd returns the index after the first q at or after s[p] that no
// backslash escapes, or -1.
func escapedEnd(s string, p int, q byte) int {
	for i := p; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case q:
			return i + 1
		}
	}
	return -1
}

// quotedEnd reads a "..." (kDQ) or ${...} (kBrace) body starting at s[p].
func (sc *scanner) quotedEnd(kind, p int) int {
	s := sc.s
	for i := p; i < len(s); {
		c := s[i]
		var next byte
		if i+1 < len(s) {
			next = s[i+1]
		}
		nested := -2 // the construct's end, if c opens one
		switch {
		case kind == kDQ && c == '"', kind == kBrace && c == '}':
			return i + 1
		case c == '\\':
			i += 2
			continue
		case c == '`':
			nested = sc.span(kBQ, i+1)
		case c == '$' && next == '(':
			nested = sc.span(kParen, i+2)
		case c == '$' && next == '{':
			nested = sc.span(kBrace, i+2)
		case kind == kBrace && c == '\'':
			nested = sc.span(kSQ, i+1)
		case kind == kBrace && c == '$' && next == '\'':
			nested = sc.span(kANSI, i+2)
		case kind == kBrace && c == '"':
			nested = sc.span(kDQ, i+1)
		case kind == kBrace && c == '$' && next == '"':
			nested = sc.span(kDQ, i+2)
		default:
			i++
			continue
		}
		if nested < 0 {
			return -1
		}
		i = nested
	}
	return -1
}

// parenEnd finds the ) closing a command substitution whose content starts
// at s[p] by tokenising the content as the top level is tokenised: a
// nested ( ... ) or (( ... )) is skipped whole (its own span, computed
// once, so nesting stays linear), and a heredoc body, a comment and a
// quoted ) do not count. A case pattern's ) (`$(case $x in a) id;; esac)`)
// is not the closing one either: inside a case, at this level, an unmatched
// ) ends a pattern.
func (sc *scanner) parenEnd(p int) int {
	sub := scanner{s: sc.s, pos: p, spans: sc.spans, strict: true}
	cases := 0
	start := true
	var pending []heredoc
	for sub.next(); sub.ok(); sub.next() {
		if sub.failed {
			return -1
		}
		t := sub.tok
		switch {
		case t == "\n" && len(pending) > 0:
			sub.skipBodies(pending)
			pending = pending[:0]
		case isHeredoc(t):
			if d, quoted, ok := sub.delimiter(); ok {
				pending = append(pending, heredoc{delim: d, tabs: strings.HasSuffix(t, "-"), quoted: quoted})
			}
		case t == "(" || t == "((":
			// The subshell's content, or the arithmetic's inner (, closes
			// at e; operator() has checked the arithmetic's second ).
			e := sub.span(kParen, sub.end)
			if e < 0 {
				return -1
			}
			if t == "((" {
				e = skipConts(sub.s, e) + 1
			}
			sub.pos = e
		case t == ")" && cases > 0:
			t = ";" // a pattern's ), a command follows
		case t == ")":
			return sub.end
		case start && t == "case":
			cases++
		case start && t == "esac" && cases > 0:
			cases--
		}
		start = t == "\n" || operators[t] || t == "(" || reserved[t]
	}
	return -1
}

// isBreak reports whether c ends a bare word: a blank or an operator byte.
// \r and \f are ordinary bytes to bash (final audit M7).
func isBreak(c byte) bool {
	switch c {
	case ' ', '\t', '\n', ';', '|', '&', '<', '>', '(', ')':
		return true
	}
	return false
}

// delimiter consumes the word after a << and returns it after bash's quote
// removal, reading the source directly rather than tokens: a quote may hold
// blanks and a backslash may escape one (`<<E"O F"`, `<<E\ OF`), and
// trimming only a word's outer quotes left delimiters that never matched,
// hiding every later command (audit I1). The word ends where the scanner's
// word ends. Quote removal follows bash 5 for a heredoc word, each form
// checked against bash:
//   - unquoted: `\` keeps the next byte, `\` + newline is removed (a line
//     continuation), and `$` before a quote is dropped;
//   - '...' keeps everything;
//   - "..." and $"..." : `\` escapes only $, `, " and \, and `\` + newline
//     is removed;
//   - $'...' decodes ANSI-C escapes (see ansiDecode);
//   - `...`, $(...), $((...)) and ${...} are kept literally, quotes inside
//     included (`<<$(x)` ends on a `$(x)` line; its paren used to end the
//     word, so no line ever matched; final audit M1).
//
// quoted reports whether a quote or escape took part (a continuation or
// substitution does not), which keeps bash from expanding the body. A
// construct left open is a syntax error in bash (nothing runs), so it is not
// read as a heredoc: the words after the << are then tokenised as usual
// and nothing is hidden. No word at all (a newline, an operator or a
// comment follows) is not a heredoc either.
func (sc *scanner) delimiter() (delim string, quoted, ok bool) {
	s := sc.s
	i := skipBlanks(s, sc.pos)
	if i >= len(s) || isBreak(s[i]) || s[i] == '#' {
		return "", false, false
	}
	var b strings.Builder
	for i < len(s) && !isBreak(s[i]) {
		c := s[i]
		var next byte
		if i+1 < len(s) {
			next = s[i+1]
		}
		kind, content := -1, 0
		switch {
		case c == '\\':
			switch {
			case i+1 >= len(s):
				b.WriteByte(c)
				quoted = true
			case next != '\n':
				b.WriteByte(next)
				quoted = true
			}
			i += 2
			continue
		case c == '\'':
			kind, content = kSQ, i+1
		case c == '"':
			kind, content = kDQ, i+1
		case c == '$' && next == '"':
			kind, content = kDQ, i+2
		case c == '$' && next == '\'':
			kind, content = kANSI, i+2
		case c == '`':
			kind, content = kBQ, i+1
		case c == '$' && next == '(':
			kind, content = kParen, i+2
		case c == '$' && next == '{':
			kind, content = kBrace, i+2
		default:
			b.WriteByte(c)
			i++
			continue
		}
		e := sc.span(kind, content)
		if e < 0 {
			return "", false, false
		}
		switch kind {
		case kSQ:
			b.WriteString(s[content : e-1])
		case kDQ:
			doubleQuoted(&b, s[content:e-1])
		case kANSI:
			ansiDecode(&b, s[content:e-1])
		default:
			b.WriteString(s[i:e])
		}
		quoted = quoted || kind == kSQ || kind == kDQ || kind == kANSI
		i = e
	}
	sc.pos = min(i, len(s))
	return b.String(), quoted, true
}

// doubleQuoted writes the value of a "..." body (without its quotes).
func doubleQuoted(b *strings.Builder, s string) {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s) && s[i+1] == '\n':
			i++
		case c == '\\' && i+1 < len(s) && strings.IndexByte("$`\"\\", s[i+1]) >= 0:
			i++
			b.WriteByte(s[i])
		default:
			b.WriteByte(c)
		}
	}
}

// ansiDecode writes the value of a $'...' body (without its quotes), as
// bash 5.2 decodes it: a decoded NUL ends the string's content, and a \u or
// \U value is written in bash's own UTF-8, which also encodes surrogates
// and values above U+10FFFF (up to 6 bytes; above 0x7fffffff nothing).
func ansiDecode(b *strings.Builder, s string) {
	for i := 0; i < len(s); {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			i++
			continue
		}
		v, n, k := ansiEscape(s[i+1:])
		switch k {
		case escNUL:
			return
		case escByte:
			b.WriteByte(byte(v))
		case escRune:
			writeBashUTF8(b, v)
		}
		i += 1 + n
	}
}

const (
	escByte = iota // a raw byte
	escRune        // a \u or \U code point
	escNUL         // a NUL, which ends the string
	escNone        // nothing (a \U value above 0x7fffffff)
)

// ansiEscape decodes the escape after a backslash in $'...' (s is the rest
// of the body, never empty): its value, the bytes it spans and its kind. An
// unknown escape keeps its backslash, as bash does; it is returned as the
// backslash alone, spanning nothing, so the next byte is read on its own.
func ansiEscape(s string) (v uint32, n, kind int) {
	c := s[0]
	if r, ok := ansiSimple[c]; ok {
		return uint32(r), 1, escByte
	}
	digits := func(max int, base int) (uint32, int) {
		var v uint32
		k := 0
		for k < max && k < len(s)-1 {
			d := strings.IndexByte("0123456789abcdef"[:base], lower(s[1+k]))
			if d < 0 {
				break
			}
			v, k = v*uint32(base)+uint32(d), k+1
		}
		return v, k
	}
	nul := func(v uint32, n, kind int) (uint32, int, int) {
		if v == 0 {
			return 0, n, escNUL
		}
		return v, n, kind
	}
	switch c {
	case '0', '1', '2', '3', '4', '5', '6', '7':
		var v uint32
		k := 0
		for k < 3 && k < len(s) && s[k] >= '0' && s[k] <= '7' {
			v, k = v*8+uint32(s[k]-'0'), k+1
		}
		return nul(v&0xff, k, escByte)
	case 'x':
		if v, k := digits(2, 16); k > 0 {
			return nul(v, 1+k, escByte)
		}
	case 'u', 'U':
		max := 4
		if c == 'U' {
			max = 8
		}
		if v, k := digits(max, 16); k > 0 {
			if v > 0x7fffffff {
				return 0, 1 + k, escNone
			}
			return nul(v, 1+k, escRune)
		}
	case 'c':
		// \cX is X's control character, \c? is DEL, and \c\\ spans both
		// backslashes; a \c at the end of the body is kept literally.
		if len(s) > 1 {
			x, k := s[1], 2
			if x == '\\' && len(s) > 2 && s[2] == '\\' {
				k = 3
			}
			if x == '?' {
				return 0x7f, k, escByte
			}
			return nul(uint32(upper(x)&0x1f), k, escByte)
		}
	}
	return '\\', 0, escByte
}

var ansiSimple = map[byte]rune{'a': 7, 'b': 8, 'e': 27, 'E': 27, 'f': 12, 'n': 10, 'r': 13, 't': 9, 'v': 11, '\\': '\\', '\'': '\'', '"': '"', '?': '?'}

// writeBashUTF8 writes v (at most 0x7fffffff) in the original, up to 6-byte
// UTF-8 form bash uses, without Go's substitution of surrogates and values
// above U+10FFFF.
func writeBashUTF8(b *strings.Builder, v uint32) {
	switch {
	case v < 0x80:
		b.WriteByte(byte(v))
		return
	case v < 0x800:
		b.WriteByte(0xc0 | byte(v>>6))
	case v < 0x10000:
		b.WriteByte(0xe0 | byte(v>>12))
		b.WriteByte(0x80 | byte(v>>6)&0x3f)
	case v < 0x200000:
		b.WriteByte(0xf0 | byte(v>>18))
		b.WriteByte(0x80 | byte(v>>12)&0x3f)
		b.WriteByte(0x80 | byte(v>>6)&0x3f)
	case v < 0x4000000:
		b.WriteByte(0xf8 | byte(v>>24))
		b.WriteByte(0x80 | byte(v>>18)&0x3f)
		b.WriteByte(0x80 | byte(v>>12)&0x3f)
		b.WriteByte(0x80 | byte(v>>6)&0x3f)
	default:
		b.WriteByte(0xfc | byte(v>>30))
		b.WriteByte(0x80 | byte(v>>24)&0x3f)
		b.WriteByte(0x80 | byte(v>>18)&0x3f)
		b.WriteByte(0x80 | byte(v>>12)&0x3f)
		b.WriteByte(0x80 | byte(v>>6)&0x3f)
	}
	b.WriteByte(0x80 | byte(v)&0x3f)
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func upper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}

// skipBodies cuts the pending heredocs' bodies out of the source, in order,
// starting after the current newline, and returns them with their lines.
// Each ends on the first line equal to its delimiter, compared as a whole
// line (so an indented `  EOF` does not end it, as in bash), with leading
// tabs stripped for <<- (from body lines too). In the body of an unquoted
// delimiter a line ending in an unescaped backslash continues on the next
// one (bash joins them before comparing: `E\` + `OF` is a terminator,
// `x\` + `EOF` is not). The scanner resumes at the newline after the last
// terminator. Every line is looked at once and at most MaxHeredocBodyBytes
// of each body is kept, so the pass stays linear.
func (sc *scanner) skipBodies(docs []heredoc) []heredoc {
	s, p := sc.s, sc.end
	resume := len(s) // an unterminated body runs to the end
	for i := range docs {
		d := &docs[i]
		budget := MaxHeredocBodyBytes
		resume = len(s)
		for p < len(s) {
			var line string
			line, p = bodyLine(s, p, !d.quoted)
			if d.tabs {
				line = strings.TrimLeft(line, "\t")
			}
			if line == d.delim {
				resume = p - 1
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
	sc.pos = min(resume, len(s)) // the newline ending the last terminator, or the end
	return docs
}

// bodyLine returns the heredoc body line starting at s[p] and the index
// after its newline (len(s)+1 when it has none). With joins, a line ending
// in an odd run of backslashes loses that backslash and continues on the
// next line.
func bodyLine(s string, p int, joins bool) (string, int) {
	var b strings.Builder
	for {
		e := strings.IndexByte(s[p:], '\n')
		if e < 0 {
			e = len(s)
		} else {
			e += p
		}
		line := s[p:e]
		k := len(line) - len(strings.TrimRight(line, `\`))
		if !joins || k%2 == 0 || e >= len(s) {
			if b.Len() == 0 {
				return line, e + 1
			}
			b.WriteString(line)
			return b.String(), e + 1
		}
		b.WriteString(line[:len(line)-1])
		p = e + 1
	}
}

// group appends the rest of a redirection target's $(...) group (see
// groupEnd) after the target word just emitted, normalising each word.
func (sc *scanner) group(out []string) []string {
	save := *sc
	sc.next()
	if !sc.ok() || (sc.tok != "(" && sc.tok != "((") {
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
		case t == "((":
			depth += 2
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
	case operators[n] || n == "(" || n == ")" || n == "<" || n == ">" || n == ">>" || isHeredoc(n) || isHeredocTok(n) || redirRe.MatchString(n) || n == "((":
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

// isHeredocTok reports whether t is a heredoc placeholder with its body.
func isHeredocTok(t string) bool {
	return strings.HasPrefix(t, heredocTok) || strings.HasPrefix(t, heredocQTok)
}

// dequote applies bash's quote removal to a program word (`\id`, 'id',
// "i"d all run id): a backslash outside quotes keeps the next byte, '...'
// is literal, and inside "..." a backslash escapes only $, `, ", \ and a
// newline (removed). A quote left open keeps its opener.
func dequote(t string) string {
	if !strings.ContainsAny(t, `\'"`) {
		return t
	}
	var b strings.Builder
	for i := 0; i < len(t); i++ {
		switch c := t[i]; c {
		case '\\':
			if i+1 < len(t) {
				i++
				c = t[i]
			}
			b.WriteByte(c)
		case '\'':
			j := strings.IndexByte(t[i+1:], '\'')
			if j < 0 {
				b.WriteByte(c)
				continue
			}
			b.WriteString(t[i+1 : i+1+j])
			i += j + 1
		case '"':
			e := escapedEnd(t, i+1, '"')
			if e < 0 {
				b.WriteByte(c)
				continue
			}
			doubleQuoted(&b, t[i+1:e-1])
			i = e - 1
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

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
	case operators[t] || t == ">" || t == ">>" || t == "<" || t == "(" || t == "((" || t == ")":
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
	return escapeNL.Replace(inner) // one command per encoded line, no separator
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
	noProgram = map[string]bool{"for": true, "case": true, "select": true, "[[": true, "((": true, "function": true}
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
	// Tests and no-ops: `[ -d /tmp ] && cd /tmp`, `:`, `sleep 1` (final
	// audit M4).
	"[": true, "test": true, ":": true, "true": true, "false": true, "sleep": true,
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
		if t == "(" || t == ")" || isHeredocTok(t) ||
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
		return path.Base(dequote(t))
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
