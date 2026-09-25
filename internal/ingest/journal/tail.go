package journal

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/netmatch"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func journalctlFollowArgs(unit string) []string {
	return []string{"-u", unit, "-n", "0", "-f", "-o", "short-iso", "--no-pager"}
}

func TailFollow(ctx context.Context, st *store.Store, unit string, adminIPs []string) error {
	return TailFollowObserved(ctx, st, unit, adminIPs, nil)
}

func TailFollowObserved(ctx context.Context, st *store.Store, unit string, adminIPs []string, heartbeat func()) error {
	if unit == "" {
		unit = "ssh"
	}
	admin := actor.AdminSet(adminIPs)
	cmd := exec.CommandContext(ctx, "journalctl", journalctlFollowArgs(unit)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("journalctl follow: %w", err)
	}
	waiting := &atomic.Bool{}
	reader := &tailHeartbeatReader{r: stdout, waiting: waiting, heartbeat: heartbeat}
	watch, stop := context.WithCancel(ctx)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-watch.Done():
				return
			case <-tick.C:
				if waiting.Load() && heartbeat != nil {
					heartbeat()
				}
			}
		}
	}()
	defer func() { stop(); <-joined }()

	if err := consumeTail(st, reader, admin); err != nil {
		// Kill BEFORE Wait. journalctl -f never exits on its own, so a plain
		// Wait() here blocks forever on a scanner error (e.g. bufio.ErrTooLong
		// from a >1MiB line) — wedging the goroutine and silently ending
		// journal ingestion. Killing the child makes Wait() return.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	if ctx.Err() != nil {
		_ = cmd.Wait() // ctx cancellation already signalled the child via CommandContext
		return nil
	}
	return cmd.Wait()
}

func consumeTail(st *store.Store, r io.Reader, admin *netmatch.Set) error {
	sc := bufio.NewScanner(r)
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
		if e.Kind == models.KindAccepted && admin.Has(e.SrcIP) {
			continue
		}
		if e.Kind == models.KindAccepted {
			// Match batch-ingest semantics (persistJournalEvents): a
			// non-allowlisted success is stored as telemetry but gets no
			// ActorID and never forms an attacker actor. Stamping and
			// syncing it here created actor state that the next batch
			// rebuild silently reversed.
			if _, err := st.AppendJournalEventAtomic(e, nil); err != nil {
				return err
			}
			continue
		}
		if _, err := actor.SyncJournalEvent(st, e, admin); err != nil {
			return err
		}
	}
	return sc.Err()
}

type tailHeartbeatReader struct {
	r         io.Reader
	waiting   *atomic.Bool
	heartbeat func()
}

func (r *tailHeartbeatReader) Read(p []byte) (int, error) {
	r.waiting.Store(true)
	n, err := r.r.Read(p)
	r.waiting.Store(false)
	if n > 0 && r.heartbeat != nil {
		r.heartbeat()
	}
	return n, err
}
