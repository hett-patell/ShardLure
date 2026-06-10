package journal

import (
	"fmt"
	"os/exec"

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
	// Stream stdout through the parser rather than cmd.Output(), which buffers
	// the entire (potentially hundreds-of-MB) journal into memory and then
	// string()-copies it — a real OOM risk on a busy honeypot's 30-day log.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("journalctl pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("journalctl: %w", err)
	}
	events, skipped, parseErr := parseReaderCounting(stdout)
	// Always reap the child to avoid leaking it, even on a parse error.
	waitErr := cmd.Wait()
	if parseErr != nil {
		return nil, parseErr
	}
	if waitErr != nil {
		return nil, fmt.Errorf("journalctl: %w", waitErr)
	}

	res, err := persistJournalEvents(st, events, adminIPs, replace)
	if res != nil {
		res.SkippedLines = skipped
	}
	return res, err
}
