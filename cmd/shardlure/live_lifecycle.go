package main

import (
	"context"
	"errors"
	"github.com/networkshard/shardlure/internal/observability"
	"sync"
	"sync/atomic"
)

type liveHooks struct {
	Seed    func(context.Context) error
	Serve   func(context.Context) error
	Workers func(context.Context) error
	Close   func() error
}

// runLiveLifecycle owns the cancellation tree and closes shared resources only
// after both the HTTP owner and every producer have joined. Production adapters
// arrange for Seed to wait for successful listener binding before doing work.
func runLiveLifecycle(parent context.Context, m *observability.Monitor, h liveHooks) error {
	if m == nil || h.Seed == nil || h.Serve == nil || h.Workers == nil || h.Close == nil {
		return errors.New("live lifecycle: missing owner")
	}
	if err := m.SetPhase(observability.Starting); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if err := ctx.Err(); err != nil {
		_ = m.SetPhase(observability.Draining)
		return shutdownResult(parent, err, h.Close())
	}
	var group sync.WaitGroup
	var first sync.Once
	var workErr error
	var serving atomic.Bool
	start := func(fn func() error) {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := fn(); err != nil {
				first.Do(func() { workErr = err; cancel() })
			}
		}()
	}
	start(func() error {
		err := h.Serve(ctx)
		if err == nil && ctx.Err() == nil {
			return errors.New("live lifecycle: server stopped unexpectedly")
		}
		return err
	})
	start(func() error {
		if err := h.Seed(ctx); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := m.SetPhase(observability.Serving); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		serving.Store(true)
		err := h.Workers(ctx)
		if err == nil && ctx.Err() == nil {
			return errors.New("live lifecycle: workers stopped unexpectedly")
		}
		return err
	})
	<-ctx.Done()
	_ = m.SetPhase(observability.Draining)
	group.Wait()
	if !serving.Load() && workErr == nil {
		workErr = ctx.Err()
	}
	return shutdownResult(parent, workErr, h.Close())
}

// shutdownResult is the process's verdict once every owner has joined.
//
// When parent ended (SIGTERM/SIGINT via signal.NotifyContext: systemd stop, a
// reboot), the operator asked for the shutdown, so the cancellation it caused
// in whatever was in flight is the requested outcome and the daemon must exit
// 0. The old rule only forgave a cancellation once the Serving phase had been
// reached, so a SIGTERM that landed while Seed was still running (listener
// bound, cowrie/capture backfill or cache warm-up in flight) exited 1 with
// "error: context canceled" and systemd marked the stop a failure
// (shardlure-live on the ARM box, reboot of 2026-09-29).
//
// The forgiveness is deliberately narrow: an error is dropped only when every
// leaf of its chain is a cancellation (see onlyCancellation). A genuine
// failure, including one joined beside a cancellation, still exits non-zero,
// as does anything at all when parent is still live (a hook failed on its own).
func shutdownResult(parent context.Context, workErr, closeErr error) error {
	if parent.Err() != nil {
		if onlyCancellation(workErr) {
			workErr = nil
		}
		if onlyCancellation(closeErr) {
			closeErr = nil
		}
	}
	return errors.Join(workErr, closeErr)
}

// onlyCancellation reports whether err is non-nil and nothing but
// context.Canceled/DeadlineExceeded, following the whole chain: %w wrappers
// are unwrapped, and a multi-error (errors.Join, fmt.Errorf with several %w)
// counts only when every branch does. A plain errors.Is would also match
// errors.Join(realFailure, context.Canceled) and swallow the real failure.
// An error that claims a cancellation through its own Is method without
// exposing Unwrap (capture.captureError hides upstream text that way) counts
// as one. Text is never compared: a %v-flattened "context canceled" is not a
// cancellation the chain can prove, so it stays an error.
func onlyCancellation(err error) bool {
	if err == nil {
		return false
	}
	if err == context.Canceled || err == context.DeadlineExceeded {
		return true
	}
	if multi, ok := err.(interface{ Unwrap() []error }); ok {
		seen := false
		for _, branch := range multi.Unwrap() {
			if branch == nil {
				continue
			}
			if !onlyCancellation(branch) {
				return false
			}
			seen = true
		}
		return seen
	}
	if next := errors.Unwrap(err); next != nil {
		return onlyCancellation(next)
	}
	if claim, ok := err.(interface{ Is(error) bool }); ok {
		return claim.Is(context.Canceled) || claim.Is(context.DeadlineExceeded)
	}
	return false
}
