package journal

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func TailFollow(ctx context.Context, st *store.Store, unit string, adminIPs []string) error {
	if unit == "" {
		unit = "ssh"
	}
	admin := actor.AdminSet(adminIPs)
	cmd := exec.CommandContext(ctx, "journalctl", "-u", unit, "-f", "-o", "short-iso", "--no-pager")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("journalctl follow: %w", err)
	}

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "sshd[") {
			continue
		}
		e, ok := ParseLine(line)
		if !ok {
			continue
		}
		if e.Kind == models.KindAccepted && admin[e.SrcIP] {
			continue
		}
		e.ActorID = "journal:" + e.SrcIP
		if err := st.InsertEvent(e); err != nil {
			continue
		}
		_ = actor.SyncJournalIP(st, e.SrcIP, admin)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return cmd.Wait()
}
