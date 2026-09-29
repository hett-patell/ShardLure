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
)

var (
	tokenRe  = regexp.MustCompile(`<<<|<<-?|\d*>>?&\d+|&>>?|\d+>>?|\n|\|\||&&|>>|[;|&<>()]|"[^"]*"|'[^']*'|[^\s;|&<>()]+`)
	redirRe  = regexp.MustCompile(`^(?:<<<|\d*>>?&\d+|&>>?|\d+>>?)$`)
	bareRe   = regexp.MustCompile(`^[a-z_][a-z0-9_.+-]*$`)
	keyTypes = regexp.MustCompile(`^(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-\S+|sk-\S+@openssh\.com)$`)
	keyBody  = regexp.MustCompile(`AAAA[0-9A-Za-z+/]{36,}={0,3}`)
	urlRe    = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s"'|;&<>()]+`)
	ipRe     = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/[^\s"'|;&<>()]*)?`)
	hexRe    = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	b64Re    = regexp.MustCompile(`^[0-9A-Za-z+/=]{24,}$`)
	numRe    = regexp.MustCompile(`^\d+$`)
	randRe   = regexp.MustCompile(`\b(?:[A-Za-z]*\d[A-Za-z0-9]*[A-Za-z]|[A-Za-z]+\d)[A-Za-z0-9]*\b`)
	tmpRe    = regexp.MustCompile(`/tmp/[^\s/"'|;&<>()]+`)
	markerRe = regexp.MustCompile(`^[A-Za-z0-9]{1,4}$`)
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
	escapeNL     = strings.NewReplacer("\r", `\r`, "\n", `\n`)
)

// NormalizeCommand splits cmd into shell tokens and replaces the parts bots
// randomise with placeholders, including inside quoted strings.
func NormalizeCommand(cmd string) []string {
	cmd = stripSeps.Replace(cmd)
	raw := tokenRe.FindAllString(cmd, -1)
	out := make([]string, 0, len(raw))
	start := true
	var wrap *wrapState // non-nil while a wrapper's own words precede its program
	heredoc, inBody := "", false
	for i := 0; i < len(raw); i++ {
		t := raw[i]
		// A heredoc body is data, not commands: drop it up to the delimiter
		// line, so `cat <<EOF\nid\nw\nEOF` stays one command. The newline that
		// opens the body is also the first possible terminator line, so it
		// falls through to the check below instead of being consumed:
		// consuming it made `cat <<EOF\nEOF\nid` swallow every later command,
		// and any dropper prefixed with an empty heredoc collapsed to one
		// non-distinctive command with a shared fingerprint (review I1).
		if heredoc != "" && t == "\n" {
			inBody = true
		}
		if inBody {
			// The terminator is the delimiter word exactly, alone on its line
			// (followed by a newline or the end). Quotes are not trimmed: bash
			// compares the raw line, so a quoted `"EOF"` line does not end the
			// body. Known limitation: the tokenizer discards whitespace, so an
			// indented `  EOF` line terminates here where bash would not
			// (except `<<-` with tabs). That is unreachable at the token level
			// and fails safe: it can only surface commands, never hide them,
			// and the fingerprint stays deterministic per script.
			if t == "\n" && i+1 < len(raw) && raw[i+1] == heredoc {
				if i+2 >= len(raw) || raw[i+2] == "\n" {
					i++
					heredoc, inBody = "", false
				}
			}
			continue
		}
		if t == "<<<" {
			out = append(out, t)
			start = false
			continue
		}
		if t == "<<" || t == "<<-" {
			out = append(out, "<<")
			if i+1 < len(raw) && raw[i+1] != "\n" {
				i++
				heredoc = strings.Trim(raw[i], `"'`)
				out = append(out, "<heredoc>")
			}
			start = false
			continue
		}
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
		case start && bareRe.MatchString(t):
			// A program resolved through PATH (base64, python3) is never
			// per-victim random; paths such as /tmp/x or ./x still are.
		default:
			t = normalizeToken(t)
		}
		out = append(out, t)
		if start && wrappers[t] != nil {
			wrap = &wrapState{name: t, spec: wrappers[t], operands: wrappers[t].operands}
		}
		start = operators[t] || t == "(" || (start && (wrap != nil || isAssignment(t)))
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
	case operators[n] || n == "(" || n == ")" || n == "<" || n == ">" || n == ">>" || n == "<<" || n == "<heredoc>" || redirRe.MatchString(n):
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

// randomInside replaces mixed letter+digit words of >= 6 chars (random
// passwords, file names) inside a larger token, keeping `\n` escapes.
func randomInside(s string) string {
	parts := strings.Split(s, `\n`)
	for i, p := range parts {
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
var displayer = strings.NewReplacer(tokSep, " ", lineSep, "\n", litLT, `\<`, litGT, `\>`)

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

var recon = map[string]bool{
	"uname": true, "whoami": true, "id": true, "hostname": true, "uptime": true, "nproc": true,
	"free": true, "pwd": true, "ls": true, "w": true, "cat": true, "lscpu": true, "ifconfig": true,
	"ip": true, "ps": true, "top": true, "df": true, "which": true, "history": true, "exit": true,
	"cd": true, "unset": true, "echo": true, "export": true, "grep": true, "head": true, "tail": true,
	"wc": true, "awk": true, "sort": true, "uniq": true, "cut": true, "tr": true, "crontab": true,
	"find": true, "locate": true, "lspci": true, "dmidecode": true,
}

// program returns a simple command's program, skipping subshell parens,
// variable assignments, redirections and wrappers with their own options.
// A wrapper followed by an option it does not know reports the wrapper
// itself: guessing which later word is the program could name an argument.
func program(seg []string) string {
	var wrap *wrapState
	for _, t := range seg {
		if wrap != nil {
			switch wrap.next(t) {
			case wrapOwn:
				continue
			case wrapStop:
				return wrap.name
			}
			wrap = nil
		}
		if t == "(" || t == ")" || t == ">" || t == ">>" || t == "<" || t == "<<" || t == "<heredoc>" || redirRe.MatchString(t) ||
			(strings.Contains(t, "=") && !strings.HasPrefix(t, "-")) || strings.HasSuffix(t, "$") {
			continue
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
