package main

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/networkshard/shardlure/internal/actor"
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
	return func(begin bool, err error) {
		now := time.Now().UTC()
		state := m.Snapshot().Workers[id]
		state.Enabled = true
		state.Required = true
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
		timer := time.NewTimer(gap)
		heartbeat := time.NewTicker(5 * time.Second)
	wait:
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				heartbeat.Stop()
				return
			case <-timer.C:
				break wait
			case <-heartbeat.C:
				state := m.Snapshot().Workers[id]
				state.LastProgress = time.Now().UTC()
				_ = m.SetWorker(id, state)
			}
		}
		heartbeat.Stop()
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
					urlWorker := capture.NewArtifactWorker(st, runner.Fetch(), 5, 2*time.Minute)
					urlWorker.OnCycle = workerCycle(m, observability.CaptureURL, 2*time.Minute)
					start(func() { defer workerStopped(m, observability.CaptureURL, false); urlWorker.Run(ctx) })
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
					if err := st.MaintenancePurge(cfg.RetentionDays); err != nil {
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
