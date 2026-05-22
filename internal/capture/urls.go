package capture

import (
	"net"
	"regexp"
	"strings"
)

var (
	reHTTP = regexp.MustCompile(`https?://[^\s"'<>]+`)
	// curl ... <url>  — leading flags chunk matches non-greedy because curl
	// commonly has -o/--output flags before the URL. We don't actually need
	// to capture the local file path: reHTTP picks the URL up regardless,
	// and the URL-prefix gate below filters anything that's not a URL.
	reCurl = regexp.MustCompile(`(?i)curl\s+[^\s;|&]*\s+(https?://\S+)`)
	reWget = regexp.MustCompile(`(?i)wget\s+(?:[^\s;|&]*\s+)*?(https?://\S+)`)
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
	for _, m := range reWget.FindAllStringSubmatch(command, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}
	for _, m := range reCurl.FindAllStringSubmatch(command, -1) {
		for i := 1; i < len(m); i++ {
			if strings.HasPrefix(m[i], "http://") || strings.HasPrefix(m[i], "https://") {
				add(m[i])
			}
		}
	}
	for _, m := range reDevTCP.FindAllStringSubmatch(command, -1) {
		if len(m) >= 3 {
			host, port := m[1], m[2]
			add("http://" + net.JoinHostPort(host, port) + "/")
		}
	}
	return out
}
