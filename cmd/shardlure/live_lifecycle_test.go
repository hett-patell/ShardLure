package main

import (
	"context"
	"errors"
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
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("aborted startup reported success: %v", err)
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
