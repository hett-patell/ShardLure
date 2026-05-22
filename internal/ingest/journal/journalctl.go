package journal

import (
	"fmt"
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
	events, skipped, err := parseReaderCounting(strings.NewReader(string(out)))
	if err != nil {
		return nil, err
	}

	res, err := persistJournalEvents(st, events, adminIPs, replace)
	if res != nil {
		res.SkippedLines = skipped
	}
	return res, err
}
