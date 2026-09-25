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
		return errors.Join(err, h.Close())
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
	if serving.Load() && parent.Err() != nil && (errors.Is(workErr, context.Canceled) || errors.Is(workErr, context.DeadlineExceeded)) {
		workErr = nil
	}
	return errors.Join(workErr, h.Close())
}
