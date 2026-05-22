// Package replay turns an observed cowrie session into a runnable
// bash script. The goal is reproducibility in a defender's lab:
// drop the script onto an isolated VM and watch the actor's exact
// command sequence play back, in order, with the same inter-command
// pacing. The output is intentionally "dumb" — we don't try to
// translate commands, just replay them verbatim with timing
// preserved via sleep statements.
package replay

import (
	"fmt"
	"strings"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// MaxSleep caps inter-command sleep duration. Real sessions
// occasionally have multi-minute idle gaps that we don't want to
// faithfully reproduce in a replay; the cap keeps scripts moving.
const MaxSleep = 5 * time.Second

// Options tunes the generated script's preamble and pacing.
type Options struct {
	// IncludeSleeps emits `sleep <n>` lines reflecting the observed
	// inter-command gaps (clamped to MaxSleep). Disable for fastest
	// possible replay.
	IncludeSleeps bool
	// DryRun comments out each command with `# ` so the script can be
	// reviewed without execution. The pacing sleeps stay live so the
	// timing remains visible.
	DryRun bool
}

// Render returns a bash script reproducing the command stream from
// the given session. Events are expected in chronological order
// (store.SessionEvents already guarantees this). Non-command events
// are skipped — replay is a command transcript, not a full session
// log.
func Render(sessionID string, events []*models.Event, opts Options) string {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n")
	b.WriteString("# ShardLure session replay\n")
	b.WriteString("# session: " + sessionID + "\n")

	// Header metadata (actor / src IP / window) - drawn from the first
	// command event we see so the script self-documents its origin.
	for _, e := range events {
		if e == nil || e.Kind != models.KindCommand {
			continue
		}
		b.WriteString("# actor:  " + safeComment(e.ActorID) + "\n")
		b.WriteString("# src_ip: " + safeComment(e.SrcIP) + "\n")
		b.WriteString("# user:   " + safeComment(e.Username) + "\n")
		b.WriteString("# first:  " + e.TS.UTC().Format(time.RFC3339) + "\n")
		break
	}
	b.WriteString("# generated: " + time.Now().UTC().Format(time.RFC3339) + "\n")
	b.WriteString("#\n")
	b.WriteString("# WARNING: replay only inside a disposable, network-isolated VM.\n")
	b.WriteString("# Commands below are verbatim attacker input and may be hostile.\n\n")
	b.WriteString("set +e  # honour attacker's failure tolerance\n\n")

	var prev, anchor time.Time
	first := true
	emitted := 0
	for _, e := range events {
		if e == nil || e.Kind != models.KindCommand {
			continue
		}
		cmd := strings.TrimSpace(e.Command)
		if cmd == "" {
			continue
		}
		if opts.IncludeSleeps && !first {
			gap := e.TS.Sub(prev)
			if gap > MaxSleep {
				gap = MaxSleep
			}
			if gap >= time.Second {
				fmt.Fprintf(&b, "sleep %.1f\n", gap.Seconds())
			}
		}
		// "# T+12s" offset comments give the reader a sense of pacing
		// even when sleeps are disabled. Anchor is the first command,
		// not the first session event (which is often a login probe).
		if first {
			anchor = e.TS
		} else {
			off := e.TS.Sub(anchor)
			fmt.Fprintf(&b, "# T+%s\n", formatOffset(off))
		}
		if opts.DryRun {
			b.WriteString("# ")
		}
		b.WriteString(cmd)
		b.WriteByte('\n')
		prev = e.TS
		first = false
		emitted++
	}

	if emitted == 0 {
		b.WriteString("# (no command events captured for this session)\n")
	}
	return b.String()
}

func formatOffset(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}

// safeComment strips characters that could break a bash comment line.
// We only really need to guard against newlines; everything else is
// already inside a `#` prefix.
func safeComment(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ")
}
