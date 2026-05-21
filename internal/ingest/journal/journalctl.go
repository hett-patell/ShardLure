package journal

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
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

	admin := actor.AdminSet(adminIPs)
	if replace {
		if err := st.ClearAll(); err != nil {
			return nil, err
		}
	}

	skipped := 0
	var attack []*models.Event
	for _, e := range events {
		if e.Kind == models.KindAccepted && admin[e.SrcIP] {
			skipped++
			continue
		}
		if e.Kind == models.KindAccepted {
			if err := st.InsertEvent(e); err != nil {
				return nil, err
			}
			continue
		}
		attack = append(attack, e)
	}

	actors, _ := actor.BuildFromJournal(attack, admin)
	for _, e := range attack {
		if err := st.InsertEvent(e); err != nil {
			return nil, fmt.Errorf("insert event: %w", err)
		}
	}
	for _, a := range actors {
		if err := st.UpsertActor(a); err != nil {
			return nil, err
		}
		ipStats := map[string]int{}
		users := map[string]int{}
		for _, e := range attack {
			if e.ActorID != a.ID {
				continue
			}
			ipStats[e.SrcIP]++
			if e.Username != "" {
				users[e.Username]++
			}
		}
		for ip, c := range ipStats {
			if err := st.UpsertActorIP(a.ID, ip, a.LastSeen, c); err != nil {
				return nil, err
			}
		}
		for u, c := range users {
			if err := st.UpsertActorUser(a.ID, u, c); err != nil {
				return nil, err
			}
		}
	}

	return &Result{
		Events:       len(attack),
		Actors:       len(actors),
		SkippedAdmin: skipped,
	}, nil
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
