package journal

import (
	"fmt"
	"io"
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
	if parseErr != nil {
		// parseReaderCounting stopped early, so journalctl may still be trying
		// to write a large backlog into the now-unread pipe — Wait() would
		// block on the full pipe forever (hanging the whole startup seed).
		// Drain the pipe in the background and kill the child so Wait returns.
		go io.Copy(io.Discard, stdout)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, parseErr
	}
	// Always reap the child to avoid leaking it.
	waitErr := cmd.Wait()
	if waitErr != nil {
		return nil, fmt.Errorf("journalctl: %w", waitErr)
	}

	res, err := persistJournalEvents(st, events, adminIPs, replace)
	if res != nil {
		res.SkippedLines = skipped
	}
	return res, err
}
