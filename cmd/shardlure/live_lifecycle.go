package main

import (
	"context"
	"errors"
	"fmt"
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
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	if err := ctx.Err(); err != nil {
		_ = m.SetPhase(observability.Draining)
		return shutdownResult(signalled(parent, ctx), err, h.Close())
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
				// The cause records that an owner failed on its own. A later
				// SIGTERM during the drain must not turn that into a clean stop.
				first.Do(func() { workErr = err; cancel(fmt.Errorf("%w: %w", errOwnerFailed, err)) })
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
	return shutdownResult(signalled(parent, ctx), workErr, h.Close())
}

// errOwnerFailed marks ctx's cancellation cause when a hook failed first.
var errOwnerFailed = errors.New("live lifecycle: an owner failed")

// signalled reports whether the shutdown was requested from outside (parent
// ended: SIGTERM/SIGINT via signal.NotifyContext) rather than started by a
// hook failing on its own. It must be judged from ctx's cancellation cause,
// not from parent.Err() after the join: a hook that fails with a
// cancellation-only error of its own (an internal timeout's
// DeadlineExceeded) followed by a SIGTERM during the drain would otherwise
// read as signalled, and the failure would be forgiven. Whichever cancel came
// first owns the cause: a hook's cancel stamps errOwnerFailed, while a parent
// cancel propagates the parent's cause, and a later cancel never overwrites it.
func signalled(parent, ctx context.Context) bool {
	return parent.Err() != nil && !errors.Is(context.Cause(ctx), errOwnerFailed)
}

// shutdownResult is the process's verdict once every owner has joined.
//
// When the shutdown was signalled (parent ended first — SIGTERM/SIGINT via
// signal.NotifyContext: systemd stop, a reboot; see signalled), the operator asked for the shutdown, so the cancellation it caused
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
// as does anything at all when a hook failed on its own first.
func shutdownResult(signalled bool, workErr, closeErr error) error {
	if signalled {
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
//
// The walk is bounded: Unwrap is attacker-free but arbitrary code, and a cyclic
// chain (an error whose Unwrap returns itself or an ancestor) used to recurse
// until the stack overflowed. Past cancellationWalkDepth levels, or after
// cancellationWalkNodes errors in total (a multi-error DAG that shares
// branches fans out exponentially without ever getting deep), the error counts
// as real: an unprovable cancellation is never forgiven.
func onlyCancellation(err error) bool {
	budget := cancellationWalkNodes
	return onlyCancellationWalk(err, 0, &budget)
}

const (
	cancellationWalkDepth = 64
	cancellationWalkNodes = 1024
)

func onlyCancellationWalk(err error, depth int, budget *int) bool {
	if err == nil {
		return false
	}
	*budget--
	if depth >= cancellationWalkDepth || *budget < 0 {
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
			if !onlyCancellationWalk(branch, depth+1, budget) {
				return false
			}
			seen = true
		}
		return seen
	}
	if next := errors.Unwrap(err); next != nil {
		return onlyCancellationWalk(next, depth+1, budget)
	}
	// A leaf whose own Is method claims a cancellation counts as one (net
	// timeout errors do this for DeadlineExceeded), matching errors.Is.
	if claim, ok := err.(interface{ Is(error) bool }); ok {
		return claim.Is(context.Canceled) || claim.Is(context.DeadlineExceeded)
	}
	return false
}
