package main

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/campaign"
	"github.com/networkshard/shardlure/internal/capture"
	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/ingest/cowrie"
	"github.com/networkshard/shardlure/internal/ingest/journal"
	"github.com/networkshard/shardlure/internal/observability"
	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/internal/web"
	"github.com/networkshard/shardlure/pkg/models"
)

type runtimeOptions struct {
	Addr, CowriePath         string
	Live, Journal, Tailscale bool
	Interval                 time.Duration
	OnListening              func(net.Addr)
}

func workerCycle(m *observability.Monitor, id observability.Worker, budget time.Duration) func(bool, error) {
	return workerCycleWith(m, id, budget, true)
}

// workerCycleWith reports a worker's cycles to the monitor. A worker that is
// not required still shows its failures in /metrics but never gates /readyz.
func workerCycleWith(m *observability.Monitor, id observability.Worker, budget time.Duration, required bool) func(bool, error) {
	return func(begin bool, err error) {
		now := time.Now().UTC()
		state := m.Snapshot().Workers[id]
		state.Enabled = true
		state.Required = required
		state.Running = true
		state.Completed = false
		state.LastProgress = now
		if begin {
			state.OperationDeadline = now.Add(budget)
		} else {
			state.OperationDeadline = time.Time{}
			if err == nil {
				state.LastSuccess = now
				state.Failure = observability.FailureNone
			} else {
				state.Failure = observability.FailureIO
			}
		}
		_ = m.SetWorker(id, state)
	}
}
func workerStopped(m *observability.Monitor, id observability.Worker, completed bool) {
	state := m.Snapshot().Workers[id]
	state.Running = false
	state.Completed = completed
	state.OperationDeadline = time.Time{}
	_ = m.SetWorker(id, state)
}

func runPeriodicWorker(ctx context.Context, m *observability.Monitor, id observability.Worker, gap, budget time.Duration, fn func(context.Context) error) {
	notify := workerCycle(m, id, budget)
	defer workerStopped(m, id, false)
	for ctx.Err() == nil {
		notify(true, nil)
		work, cancel := context.WithTimeout(ctx, budget)
		err := fn(work)
		if err == nil && work.Err() != nil {
			err = work.Err()
		}
		cancel()
		notify(false, err)
		if !waitGap(ctx, m, id, gap) {
			return
		}
	}
}

// waitGap sleeps gap between cycles, refreshing the worker's LastProgress
// every 5 s so a long gap never reads as a stalled worker. It reports false
// when ctx ends first. Shared by runPeriodicWorker and runOptionalWorker so a
// fix to the wait or heartbeat semantics reaches both (audit M4).
func waitGap(ctx context.Context, m *observability.Monitor, id observability.Worker, gap time.Duration) bool {
	timer := time.NewTimer(gap)
	defer timer.Stop()
	heartbeat := time.NewTicker(5 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		case <-heartbeat.C:
			state := m.Snapshot().Workers[id]
			state.LastProgress = time.Now().UTC()
			_ = m.SetWorker(id, state)
		}
	}
}

// runOptionalWorker is runPeriodicWorker for auxiliary analysis: failures are
// reported in /metrics but never make the daemon not-ready.
//
// It also logs them, because /metrics is not read on every deployment: the
// first failure of a streak and each change of the error text, then the
// recovery. Not every cycle, since a worker in backoff returns the same
// retained error on each 5 s tick (campaign.Worker.Tick) and a permanent
// failure would otherwise fill the journal; the failing tick before this
// logged nothing at all, which is how a worker dead from its first tick went
// unnoticed on the upgrade rehearsal (fix-all review I1).
func runOptionalWorker(ctx context.Context, m *observability.Monitor, id observability.Worker, gap, budget time.Duration, fn func(context.Context) error) {
	notify := workerCycleWith(m, id, budget, false)
	defer workerStopped(m, id, false)
	logged := "" // text of the failure last logged; "" while healthy
	for ctx.Err() == nil {
		notify(true, nil)
		work, cancel := context.WithTimeout(ctx, budget)
		err := fn(work)
		if err == nil && work.Err() != nil {
			err = work.Err()
		}
		cancel()
		notify(false, err)
		switch {
		case err != nil && ctx.Err() != nil:
			// Shutdown cancelled the cycle: not a worker failure.
		case err != nil && err.Error() != logged:
			logged = err.Error()
			log.Printf("%s worker failed (reported in /metrics until it succeeds): %v", id, err)
		case err == nil && logged != "":
			logged = ""
			log.Printf("%s worker recovered", id)
		}
		if !waitGap(ctx, m, id, gap) {
			return
		}
	}
}

func runRuntime(ctx context.Context, st *store.Store, keys *settings.Keystore, cfg config.Config, opts runtimeOptions) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if opts.Interval <= 0 {
		opts.Interval = 5 * time.Second
	}
	if opts.CowriePath == "" {
		opts.CowriePath = cfg.Cowrie.JSONLog
	}
	cfg.Cowrie.JSONLog = opts.CowriePath
	m := observability.New(time.Now, uint64(cfg.Observability.MinFreeBytes))
	for _, worker := range []observability.Worker{observability.Backfills, observability.JournalSummaries} {
		_ = m.SetWorker(worker, observability.WorkerState{Enabled: true, Required: true})
	}
	if opts.Live {
		_ = m.SetWorker(observability.CowrieIngest, observability.WorkerState{Enabled: true, Required: true})
		if opts.Journal {
			_ = m.SetWorker(observability.JournalTail, observability.WorkerState{Enabled: true, Required: true})
		}
		if cfg.Capture.Enabled {
			_ = m.SetWorker(observability.CaptureFiles, observability.WorkerState{Enabled: true, Required: true})
			if cfg.Capture.QuarantineFetch {
				_ = m.SetWorker(observability.CaptureURL, observability.WorkerState{Enabled: true, Required: true})
				if cfg.Capture.Refetch {
					// Optional: see newRefetchWorker.
					_ = m.SetWorker(observability.CaptureRefetch, observability.WorkerState{Enabled: true})
				}
			}
		}
	}
	st.SetIngestObserver(func(source models.Source, n int, err error) {
		var kind observability.Source
		switch source {
		case models.SourceCowrie:
			kind = observability.Cowrie
		case models.SourceJournal:
			kind = observability.Journal
		default:
			return
		}
		if err != nil {
			_ = m.ObserveIngest(kind, observability.StorageError, 1)
		} else {
			_ = m.ObserveIngest(kind, observability.Success, uint64(n))
		}
	})
	var runner *capture.Runner
	if opts.Live {
		runner = capture.NewRunner(st, cfg)
		// Before seed and every worker: all of them reach runner.Run, which
		// consults the gate (see wireCapturePause).
		wireCapturePause(runner, m)
	}
	bound := make(chan struct{})
	var announce sync.Once
	options := webOptionsWithTailscale(cfg, opts.Tailscale)
	options.Monitor = m
	options.OnListening = func(addr net.Addr) {
		announce.Do(func() { close(bound) })
		if opts.OnListening != nil {
			opts.OnListening(addr)
		}
	}
	campaigns := campaign.NewWorker(st, cfg.RetentionDays, cfg.CaptureEvidenceDir())
	options.OnCampaignEdit = campaigns.Wake
	server := web.New(st, keys, opts.Addr, options)
	probe := observability.NewFilesystemProbe(st.Probe, cfg.DataDir, cfg.CaptureEvidenceDir(), opts.Live && cfg.Capture.Enabled)
	serve := func(parent context.Context) error {
		sampled, cancel := context.WithCancel(parent)
		var group sync.WaitGroup
		group.Add(2)
		go func() { defer group.Done(); observability.RunSampler(sampled, m, probe) }()
		go func() {
			defer group.Done()
			observability.RunAggregateSampler(sampled, m, func(ctx context.Context) (observability.AggregateSample, error) {
				s, err := st.OperationalSnapshot(ctx)
				return observability.AggregateSample{At: s.At, FilePending: s.FilePending, FileRetry: s.FileRetry, FileLeased: s.FileLeased, URLPending: s.URLPending, URLRetry: s.URLRetry, URLLeased: s.URLLeased, FileDiscoveryLag: s.FileDiscoveryLag, CommandDiscoveryLag: s.CommandDiscoveryLag, ProtectedFileJobs: s.ProtectedFileJobs, PoolOpen: s.PoolOpen, PoolInUse: s.PoolInUse, PoolWaits: s.PoolWaits}, err
			})
		}()
		err := server.RunContext(sampled)
		cancel()
		group.Wait()
		return err
	}
	seed := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-bound:
		}
		if opts.Live {
			if opts.Journal {
				if _, err := journal.IngestJournalctlContext(ctx, st, cfg.Journal.Unit, "30 days ago", cfg.AdminIPs, false); err != nil {
					return err
				}
			}
			if err := cowrie.BackfillRotatedLogsContext(ctx, st, opts.CowriePath, cfg.AdminIPs); err != nil {
				return err
			}
			if _, err := cowrie.IngestFileAppendContext(ctx, st, opts.CowriePath, cfg.AdminIPs); err != nil {
				return err
			}
			if _, err := runner.Run(ctx); err != nil {
				return err
			}
		}
		// Fill the dashboard caches before reporting ready: filling them on the
		// first request after a restart took 8-90 s on a 1.75M-event database.
		if err := server.WarmCaches(ctx); err != nil {
			return err
		}
		sample, err := probe(ctx)
		if err != nil {
			return err
		}
		m.RecordSample(sample)
		return ctx.Err()
	}
	workers := func(ctx context.Context) error {
		var group sync.WaitGroup
		start := func(fn func()) { group.Add(1); go func() { defer group.Done(); fn() }() }
		start(func() { runRuntimeBackfills(ctx, m, st) })
		start(func() {
			cursor := "" // owned by this worker goroutine only
			runPeriodicWorker(ctx, m, observability.JournalSummaries, time.Second, 20*time.Second, func(ctx context.Context) error {
				next, err := actor.AdvancePendingJournalSummaries(ctx, st, cursor, 16)
				cursor = next
				return err
			})
		})
		start(func() {
			runOptionalWorker(ctx, m, observability.Campaigns, 5*time.Second, 2*time.Minute, campaigns.Tick)
		})
		start(func() {
			// Started here, after seed and cache warm-up, not in serve: a first
			// sample taken mid-seed competes with cold start, pins a WAL
			// snapshot under heavy writes, and reports an undercount as valid
			// for 5 minutes. Runs in web mode too: /metrics is served there
			// and the windows slide and the share ledgers change on a static DB.
			// 5-minute cadence, 30 s budget: a 7-day window costs seconds on
			// the ARM sensor (see RunFunnelSampler).
			observability.RunFunnelSampler(ctx, m, 5*time.Minute, 30*time.Second, funnelCollector(st))
		})
		if opts.Live {
			start(func() {
				runPeriodicWorker(ctx, m, observability.CowrieIngest, opts.Interval, 2*time.Minute, func(ctx context.Context) error {
					_, ingestErr := cowrie.IngestFileAppendContext(ctx, st, opts.CowriePath, cfg.AdminIPs)
					_, captureErr := runner.Run(ctx)
					return errors.Join(ingestErr, captureErr)
				})
			})
			if cfg.Capture.Enabled {
				fileWorker := runner.FileWorker()
				fileWorker.OnCycle = workerCycle(m, observability.CaptureFiles, 2*time.Minute)
				start(func() { defer workerStopped(m, observability.CaptureFiles, false); fileWorker.Run(ctx) })
				if cfg.Capture.QuarantineFetch {
					urlWorker := newURLWorker(st, runner, m)
					start(func() { defer workerStopped(m, observability.CaptureURL, false); urlWorker.Run(ctx) })
					if cfg.Capture.Refetch {
						refetchWorker := newRefetchWorker(st, runner, m)
						start(func() { defer workerStopped(m, observability.CaptureRefetch, false); refetchWorker.Run(ctx) })
					}
				}
			}
			if opts.Journal {
				start(func() {
					notify := workerCycle(m, observability.JournalTail, 2*time.Minute)
					defer workerStopped(m, observability.JournalTail, false)
					for ctx.Err() == nil {
						notify(false, nil)
						err := journal.TailFollowObserved(ctx, st, cfg.Journal.Unit, cfg.AdminIPs, func() { notify(false, nil) })
						if ctx.Err() != nil {
							return
						}
						if err == nil {
							err = errors.New("journal stopped")
						}
						notify(false, err)
						if !waitForBackfill(ctx, time.Second) {
							return
						}
						if _, err := journal.IngestJournalctlContext(ctx, st, cfg.Journal.Unit, "5 minutes ago", cfg.AdminIPs, false); err != nil {
							notify(false, err)
						}
					}
				})
			}
			start(func() {
				for ctx.Err() == nil {
					if err := st.MaintenancePurgeContext(ctx, cfg.RetentionDays); err != nil && ctx.Err() == nil {
						log.Print("maintenance purge failed")
					}
					if _, err := runner.PurgeOldSourceFilesContext(ctx, cfg.RetentionDays); err != nil && ctx.Err() == nil {
						log.Print("source retention failed")
					}
					if !waitForBackfill(ctx, 24*time.Hour) {
						return
					}
				}
			})
		}
		<-ctx.Done()
		group.Wait()
		// Only the campaign goroutine ticks the worker, and it has returned:
		// release the evidence-root descriptor familyOf pinned.
		campaigns.Close()
		return nil
	}
	return runLiveLifecycle(ctx, m, liveHooks{Seed: seed, Serve: serve, Workers: workers, Close: st.Close})
}

func runRuntimeBackfills(ctx context.Context, m *observability.Monitor, st *store.Store) {
	notify := workerCycle(m, observability.Backfills, time.Minute)
	completed := false
	defer func() { workerStopped(m, observability.Backfills, completed) }()
	steps := []func(context.Context) (bool, error){
		func(ctx context.Context) (bool, error) { r, e := st.BackfillArtifactTimes(ctx, 1000); return r.Done, e },
		func(ctx context.Context) (bool, error) { r, e := st.BackfillEventTimes(ctx, 1000); return r.Done, e },
		func(ctx context.Context) (bool, error) { r, e := st.BackfillLedgerTimes(ctx, 1000); return r.Done, e },
	}
	for _, step := range steps {
		for ctx.Err() == nil {
			notify(true, nil)
			work, cancel := context.WithTimeout(ctx, time.Minute)
			done, err := step(work)
			if err == nil && work.Err() != nil {
				err = work.Err()
			}
			cancel()
			notify(false, err)
			if err == nil && done {
				break
			}
			gap := 250 * time.Millisecond
			if err != nil {
				gap = 5 * time.Second
			}
			if !waitForBackfill(ctx, gap) {
				return
			}
		}
		if ctx.Err() != nil {
			return
		}
	}
	completed = true
}
