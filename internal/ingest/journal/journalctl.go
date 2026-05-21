package journal

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/networkshard/shardlure/internal/store"
)

func IngestJournalctl(st *store.Store, unit string, since string, adminIPs []string, replace bool) (*Result, error) {
	if unit == "" {
		unit = "ssh"
	}
	if since == "" {
		since = "30 days ago"
	}
	cmd := exec.Command("journalctl", "-u", unit, "-S", since, "-o", "short-iso", "--no-pager")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("journalctl: %w", err)
	}
	events, err := ParseReader(strings.NewReader(string(out)))
	if err != nil {
		return nil, err
	}

	return persistJournalEvents(st, events, adminIPs, replace)
}

func IngestJournalctlToFile(path string, unit string, since string) error {
	if unit == "" {
		unit = "ssh"
	}
	if since == "" {
		since = "30 days ago"
	}
	cmd := exec.Command("journalctl", "-u", unit, "-S", since, "-o", "short-iso", "--no-pager")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("journalctl: %w", err)
	}
	filtered := filterSSHLines(string(out))
	return os.WriteFile(path, []byte(filtered), 0o644)
}

func filterSSHLines(raw string) string {
	var b strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		if strings.Contains(line, "sshd[") &&
			(strings.Contains(line, "Invalid user") ||
				strings.Contains(line, "Failed password") ||
				strings.Contains(line, "Failed publickey") ||
				strings.Contains(line, "Accepted ")) {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
