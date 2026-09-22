package observability

import (
	"context"
	"time"
)

type Probe func(context.Context) (Sample, error)
type AggregateProbe func(context.Context) (AggregateSample, error)
type AggregateSample struct {
	At, AttemptedAt                                                     time.Time
	Valid                                                               bool
	FilePending, FileRetry, FileLeased, URLPending, URLRetry, URLLeased int64
	FileDiscoveryLag, CommandDiscoveryLag, ProtectedFileJobs            int64
	PoolOpen, PoolInUse, PoolWaits                                      int64
}

func (m *Monitor) RecordAggregates(sample AggregateSample) {
	sample.At = sample.At.UTC()
	sample.AttemptedAt = sample.AttemptedAt.UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	if !sample.Valid {
		m.state.Aggregates.Valid = false
		m.state.Aggregates.AttemptedAt = sample.AttemptedAt
		return
	}
	m.state.Aggregates = sample
}

func RunSampler(ctx context.Context, m *Monitor, probe Probe) {
	runSampler(ctx, m, probe, 5*time.Second, time.Second)
}
func runSampler(ctx context.Context, m *Monitor, probe Probe, interval, budget time.Duration) {
	if m == nil || probe == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		at := m.clockNow().UTC()
		cycle, cancel := context.WithTimeout(ctx, budget)
		sample, err := probe(cycle)
		expired := cycle.Err() != nil
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil || expired {
			sample = Sample{At: at}
		}
		if err != nil || expired || !sample.DatabaseUp || !sample.DataAccessible || (sample.CaptureRequired && !sample.EvidenceAccessible) {
			m.mu.Lock()
			addCounter(&m.state.ProbeFailures, 1)
			m.mu.Unlock()
		}
		if sample.At.IsZero() {
			sample.At = at
		}
		m.RecordSample(sample)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Aggregates have their own owner/cadence. Scrapes never invoke this callback,
// and a slow/cancelled aggregate cannot overlap the following attempt.
func RunAggregateSampler(ctx context.Context, m *Monitor, probe AggregateProbe) {
	if m == nil || probe == nil {
		return
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for ctx.Err() == nil {
		at := m.clockNow().UTC()
		cycle, cancel := context.WithTimeout(ctx, time.Second)
		sample, err := probe(cycle)
		expired := cycle.Err() != nil
		cancel()
		if ctx.Err() != nil {
			return
		}
		sample.AttemptedAt = at
		sample.Valid = err == nil && !expired
		if sample.Valid && sample.At.IsZero() {
			sample.At = at
		}
		m.RecordAggregates(sample)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
