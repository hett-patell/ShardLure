package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/networkshard/shardlure/internal/observability"
	"sync/atomic"
	"testing"
	"time"
)

func TestStartupCancellationNeverServesAndJoinsBeforeClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := observability.New(time.Now, 0)
	seedStarted, serveStarted := make(chan struct{}), make(chan struct{})
	var seedDone, serveDone, workersStarted, closed atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- runLiveLifecycle(ctx, m, liveHooks{
			Seed: func(ctx context.Context) error {
				close(seedStarted)
				<-ctx.Done()
				seedDone.Store(true)
				return ctx.Err()
			},
			Serve:   func(ctx context.Context) error { close(serveStarted); <-ctx.Done(); serveDone.Store(true); return nil },
			Workers: func(ctx context.Context) error { workersStarted.Store(true); <-ctx.Done(); return nil },
			Close: func() error {
				if !seedDone.Load() || !serveDone.Load() {
					t.Error("resources closed before owners joined")
				}
				closed.Store(true)
				return nil
			},
		})
	}()
	<-seedStarted
	<-serveStarted
	cancel()
	select {
	case err := <-done:
		// The parent (the signal context) ended: an operator-requested stop
		// during startup is a clean exit, not a failure.
		if err != nil {
			t.Fatalf("signal during startup reported failure: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("startup did not join")
	}
	if workersStarted.Load() || !closed.Load() || m.Snapshot().Phase != observability.Draining {
		t.Fatal("invalid startup/shutdown state")
	}
}

func TestLifecycleWaitsForHandlersAndWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := observability.New(time.Now, 0)
	started, release := make(chan struct{}), make(chan struct{})
	var served, worked, closed atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- runLiveLifecycle(ctx, m, liveHooks{Seed: func(context.Context) error { return nil }, Serve: func(ctx context.Context) error { <-ctx.Done(); <-release; served.Store(true); return nil }, Workers: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			<-release
			worked.Store(true)
			return nil
		}, Close: func() error {
			if !served.Load() || !worked.Load() {
				t.Error("premature resource close")
			}
			closed.Store(true)
			return nil
		}})
	}()
	<-started
	cancel()
	if closed.Load() {
		t.Fatal("resources closed with work in flight")
	}
	close(release)
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not join")
	}
	if !closed.Load() {
		t.Fatal("resources not closed")
	}
}

func TestLifecycleServerFailureCancelsSeeding(t *testing.T) {
	m := observability.New(time.Now, 0)
	sentinel := errors.New("inert listen failure")
	var closed atomic.Bool
	err := runLiveLifecycle(context.Background(), m, liveHooks{Seed: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }, Serve: func(context.Context) error { return sentinel }, Workers: func(context.Context) error { t.Error("workers started after bind failure"); return nil }, Close: func() error { closed.Store(true); return nil }})
	if !errors.Is(err, sentinel) || !closed.Load() || m.Snapshot().Phase != observability.Draining {
		t.Fatalf("failure ownership lost: %v", err)
	}
}

// testCaptureStyleErr claims a cancellation through Is without Unwrap, the
// shape capture.captureError uses to hide upstream error text.
type testCaptureStyleErr struct{}

func (testCaptureStyleErr) Error() string        { return "capture failed" }
func (testCaptureStyleErr) Is(target error) bool { return target == context.Canceled }

// A SIGTERM must exit 0 whatever was in flight, and must never hide a genuine
// failure. Regression for shardlure-live exiting 1 "error: context canceled"
// when systemd stopped it during a reboot (2026-09-29).
func TestSignalShutdownExitsZeroWhateverWasInFlight(t *testing.T) {
	realErr := errors.New("disk I/O error")
	type hookErr func(ctx context.Context) error
	cases := []struct {
		name string
		// inSeed: the hook runs as Seed (never reaches Serving); otherwise as
		// Workers after Serving.
		inSeed  bool
		hook    hookErr
		closeFn func() error
		wantErr error // nil: must exit 0
	}{
		{name: "seed returns ctx.Err", inSeed: true, hook: func(ctx context.Context) error { return ctx.Err() }},
		{name: "seed wraps with %w", inSeed: true, hook: func(ctx context.Context) error { return fmt.Errorf("backfill rotated logs: %w", ctx.Err()) }},
		{name: "seed joins two cancellations", inSeed: true, hook: func(ctx context.Context) error {
			return errors.Join(fmt.Errorf("ingest: %w", ctx.Err()), context.DeadlineExceeded)
		}},
		{name: "seed capture-style Is-only cancellation", inSeed: true, hook: func(ctx context.Context) error { return fmt.Errorf("capture: %w", testCaptureStyleErr{}) }},
		{name: "worker wrapped cancellation", hook: func(ctx context.Context) error { return fmt.Errorf("tick: %w", ctx.Err()) }},
		{name: "close returns wrapped cancellation", hook: func(ctx context.Context) error { return nil },
			closeFn: func() error { return fmt.Errorf("release lease: %w", context.Canceled) }},
		// Genuine failures must survive a signal-initiated stop.
		{name: "seed genuine failure", inSeed: true, hook: func(ctx context.Context) error { return realErr }, wantErr: realErr},
		{name: "worker genuine failure joined with cancellation", hook: func(ctx context.Context) error {
			return errors.Join(realErr, ctx.Err())
		}, wantErr: realErr},
		{name: "close genuine failure", hook: func(ctx context.Context) error { return nil },
			closeFn: func() error { return realErr }, wantErr: realErr},
		{name: "%v-flattened cancellation is not provably one", inSeed: true, hook: func(ctx context.Context) error {
			return fmt.Errorf("seed: %v", ctx.Err())
		}, wantErr: errFlattened},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent, signal := context.WithCancel(context.Background())
			defer signal()
			m := observability.New(time.Now, 0)
			running := make(chan struct{})
			var once atomic.Bool
			block := func(ctx context.Context) error {
				if once.CompareAndSwap(false, true) {
					close(running)
				}
				<-ctx.Done()
				return tc.hook(ctx)
			}
			h := liveHooks{
				Seed:    func(ctx context.Context) error { return nil },
				Serve:   func(ctx context.Context) error { <-ctx.Done(); return nil },
				Workers: func(ctx context.Context) error { <-ctx.Done(); return nil },
				Close:   func() error { return nil },
			}
			if tc.inSeed {
				h.Seed = block
			} else {
				h.Workers = block
			}
			if tc.closeFn != nil {
				h.Close = tc.closeFn
			}
			done := make(chan error, 1)
			go func() { done <- runLiveLifecycle(parent, m, h) }()
			<-running
			signal()
			var err error
			select {
			case err = <-done:
			case <-time.After(time.Second):
				t.Fatal("shutdown did not join")
			}
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("signal-initiated shutdown failed: %v", err)
			case tc.wantErr == errFlattened && (err == nil || err.Error() != "seed: context canceled"):
				t.Fatalf("flattened error lost: %v", err)
			case tc.wantErr != nil && tc.wantErr != errFlattened && !errors.Is(err, tc.wantErr):
				t.Fatalf("genuine failure swallowed: got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

var errFlattened = errors.New("sentinel: expect the flattened text")

// A signal that arrives before the lifecycle even starts is still a clean stop.
func TestSignalBeforeStartExitsZero(t *testing.T) {
	parent, signal := context.WithCancel(context.Background())
	signal()
	var closed atomic.Bool
	err := runLiveLifecycle(parent, observability.New(time.Now, 0), liveHooks{
		Seed:    func(context.Context) error { t.Error("seeded after signal"); return nil },
		Serve:   func(context.Context) error { t.Error("served after signal"); return nil },
		Workers: func(context.Context) error { return nil },
		Close:   func() error { closed.Store(true); return nil },
	})
	if err != nil || !closed.Load() {
		t.Fatalf("pre-start signal: err=%v closed=%v", err, closed.Load())
	}
}

func TestOnlyCancellation(t *testing.T) {
	real := errors.New("real")
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{context.Canceled, true},
		{context.DeadlineExceeded, true},
		{fmt.Errorf("a: %w", fmt.Errorf("b: %w", context.Canceled)), true},
		{errors.Join(context.Canceled, nil, context.DeadlineExceeded), true},
		{fmt.Errorf("x: %w, %w", context.Canceled, context.Canceled), true},
		{testCaptureStyleErr{}, true},
		{errors.Join(real, context.Canceled), false},
		{fmt.Errorf("x: %w, %w", context.Canceled, real), false},
		{fmt.Errorf("wrap: %w", errors.Join(context.Canceled, real)), false},
		{errors.New("context canceled"), false},
		{fmt.Errorf("x: %v", context.Canceled), false},
		{real, false},
	} {
		if got := onlyCancellation(tc.err); got != tc.want {
			t.Errorf("onlyCancellation(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
