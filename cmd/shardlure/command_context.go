package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// newCommandContext gives one-shot CLI operations the same shutdown contract
// as the live and web commands. A caller can supply a narrower parent in tests
// or embedding code; process signals and parent cancellation both stop reads,
// network requests, and rate-limit timers.
func newCommandContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}
