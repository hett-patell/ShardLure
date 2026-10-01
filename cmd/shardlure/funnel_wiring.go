package main

import (
	"context"
	"time"

	"github.com/networkshard/shardlure/internal/intel/bazaar"
	"github.com/networkshard/shardlure/internal/observability"
	"github.com/networkshard/shardlure/internal/store"
)

// funnelWindow copies a store window into the observability type field by
// field; observability may not import store.
func funnelWindow(c store.FunnelCounts) observability.FunnelWindow {
	return observability.FunnelWindow{
		Connected: c.Connected, LoggedIn: c.LoggedIn, RanCommands: c.RanCommands, DownloadAttempt: c.DownloadAttempt,
		Captured: c.Captured, NewPayloads: c.NewPayloads,
		SharedBazaar: c.SharedBazaar, SharedURLhaus: c.SharedURLhaus, SharedThreatFox: c.SharedThreatFox,
	}
}

// funnelCollector is the collector the runtime's workers hook starts. It is a
// variable only so a test can observe when the first collection happens.
var funnelCollector = collectFunnel

// collectFunnel computes the 24h and 7d funnels. The payload stages use
// MalwareBazaar's own Vet thresholds so "captured" means "would be eligible
// to share", never a looser private definition (CLAUDE.md: candidate
// selection must never be tighter or looser than Vet).
func collectFunnel(st *store.Store) func(context.Context) (observability.FunnelSample, error) {
	return func(ctx context.Context) (observability.FunnelSample, error) {
		now := time.Now()
		pol := store.SharePolicy{MinBytes: bazaar.MinSampleBytes, Origins: bazaar.ShareableOrigins()}
		day, err := st.PayloadFunnel(ctx, now.Add(-24*time.Hour), pol)
		if err != nil {
			return observability.FunnelSample{}, err
		}
		week, err := st.PayloadFunnel(ctx, now.Add(-7*24*time.Hour), pol)
		if err != nil {
			return observability.FunnelSample{}, err
		}
		// At stays zero: RunFunnelSampler stamps it with the monitor clock, so
		// the staleness check compares like with like. now is only the window
		// cutoff, which must be wall-clock to match the stored timestamps.
		return observability.FunnelSample{Day: funnelWindow(day), Week: funnelWindow(week)}, nil
	}
}
