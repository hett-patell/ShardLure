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

// ExtractURLs finds remote URLs and /dev/tcp targets in shell commands.
func ExtractURLs(command string) []string {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(u string) {
		u = strings.TrimRight(u, `"'`,)
		u = strings.TrimRight(u, `;|&`)
		if u == "" {
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
