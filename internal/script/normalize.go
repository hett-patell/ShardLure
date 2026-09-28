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
	// wrappers run the next word as the program (sudo wget, nohup ./x).
	wrappers     = map[string]bool{"sudo": true, "nohup": true, "env": true, "exec": true, "command": true, "time": true, "nice": true, "busybox": true}
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
		start = operators[t] || t == "(" || (start && (wrappers[t] || isAssignment(t)))
	}
	return out
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
	inner = escapeNL.Replace(inner) // one command per encoded line
	return quote + inner + quote
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

// Display renders an encoded script for people, capped at max bytes.
func Display(enc string, max int) string {
	s := strings.ReplaceAll(strings.ReplaceAll(enc, tokSep, " "), lineSep, "\n")
	if max > 0 && len(s) > max {
		cut := max
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
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
// variable assignments and redirections.
func program(seg []string) string {
	for _, t := range seg {
		if t == "(" || t == ")" || t == ">" || t == ">>" || t == "<" || t == "<<" || t == "<heredoc>" || wrappers[t] || redirRe.MatchString(t) ||
			(strings.Contains(t, "=") && !strings.HasPrefix(t, "-")) || strings.HasSuffix(t, "$") {
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
