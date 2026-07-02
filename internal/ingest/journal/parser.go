package journal

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

var (
	reInvalid   = regexp.MustCompile(`^(?P<ts>\S+)\s+\S+\s+sshd\[\d+\]:\s+Invalid user (?P<user>\S+) from (?P<ip>\S+)`)
	reFailed    = regexp.MustCompile(`^(?P<ts>\S+)\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+).*?from (?P<ip>\S+)`)
	reFailedKey = regexp.MustCompile(`^(?P<ts>\S+)\s+\S+\s+sshd\[\d+\]:\s+Failed publickey for (?P<user>\S+).*?from (?P<ip>\S+)`)
	reAccepted  = regexp.MustCompile(`^(?P<ts>\S+)\s+\S+\s+sshd\[\d+\]:\s+Accepted publickey for (?P<user>\S+) from (?P<ip>\S+)`)
	rePort      = regexp.MustCompile(`port (\d+)`)
)

type match struct {
	ts, user, ip string
	kind         models.EventKind
}

func SanitizeUser(u string) string {
	if u == "" {
		return "?"
	}
	var b strings.Builder
	for _, r := range u {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('?')
		}
		if b.Len() >= 32 {
			break
		}
	}
	s := b.String()
	if s == "" {
		return "?"
	}
	return s
}

func ParseLine(line string) (*models.Event, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, false
	}

	var m match

	switch {
	case reInvalid.MatchString(line):
		m = matchFromRegex(reInvalid, line, models.KindInvalidUser)
	case reFailed.MatchString(line):
		m = matchFromRegex(reFailed, line, models.KindFailedPass)
	case reFailedKey.MatchString(line):
		m = matchFromRegex(reFailedKey, line, models.KindFailedKey)
	case reAccepted.MatchString(line):
		m = matchFromRegex(reAccepted, line, models.KindAccepted)
	default:
		return nil, false
	}
	if m.ts == "" || m.user == "" || net.ParseIP(m.ip) == nil {
		return nil, false
	}

	ts, err := time.Parse(time.RFC3339, m.ts)
	if err != nil {
		// journalctl -o short-iso emits the numeric zone WITHOUT a colon
		// ("2026-07-02T15:04:05+0530"), which RFC3339 rejects. (The old
		// fallback here used "-07:00" — a strict subset of RFC3339's
		// "Z07:00" — so it could never succeed and every short-iso line
		// with a no-colon offset was silently dropped.)
		ts, err = time.Parse("2006-01-02T15:04:05-0700", m.ts)
		if err != nil {
			return nil, false
		}
	}

	e := &models.Event{
		TS:       ts.UTC(),
		Source:   models.SourceJournal,
		Kind:     m.kind,
		SrcIP:    m.ip,
		Username: SanitizeUser(m.user),
		Raw:      line,
	}
	if p := rePort.FindStringSubmatch(line); len(p) > 1 {
		e.SrcPort, _ = strconv.Atoi(p[1])
	}
	return e, true
}

func matchFromRegex(re *regexp.Regexp, line string, kind models.EventKind) match {
	g := re.FindStringSubmatch(line)
	if len(g) == 0 {
		return match{kind: kind}
	}
	get := func(name string) string {
		idx := re.SubexpIndex(name)
		if idx < 0 || idx >= len(g) {
			return ""
		}
		return g[idx]
	}
	return match{
		ts:   get("ts"),
		user: get("user"),
		ip:   get("ip"),
		kind: kind,
	}
}
