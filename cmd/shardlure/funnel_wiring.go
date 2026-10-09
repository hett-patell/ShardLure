package main

import (
	"context"
	"log"
	"time"

	"github.com/networkshard/shardlure/internal/capture"
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

// capturePauseNotifier reports SpaceGate transitions: one log line per
// transition (not per cycle) and the monitor flag behind
// shardlure_capture_paused and the Settings strip.
func capturePauseNotifier(m *observability.Monitor) func(bool, uint64) {
	return func(paused bool, free uint64) {
		m.SetCapturePaused(paused)
		if paused {
			log.Printf("capture: paused, evidence filesystem has %d bytes free (below capture.min_free_bytes)", free)
		} else {
			log.Print("capture: resumed, evidence filesystem is above capture.min_free_bytes")
		}
	}
}

// wireCapturePause connects the runner's gate to the monitor. Call it right
// after NewRunner, before seed or any worker can call runner.Run: Allow reads
// OnChange under the gate's lock, but this write is unlocked, so assigning it
// once a goroutine may be inside Allow is a data race.
func wireCapturePause(runner *capture.Runner, m *observability.Monitor) {
	runner.SpaceGate().OnChange = capturePauseNotifier(m)
}

// newURLWorker builds the quarantine-fetch retry worker. It shares the
// runner's SpaceGate, so a pause stops URL fetches as well as file copies.
func newURLWorker(st *store.Store, runner *capture.Runner, m *observability.Monitor) *capture.ArtifactWorker {
	w := capture.NewArtifactWorker(st, runner.Fetch(), 5, 2*time.Minute)
	w.Space = runner.SpaceGate()
	w.Hosts = runner.HostGate()
	w.OnCycle = workerCycle(m, observability.CaptureURL, 2*time.Minute)
	return w
}

// newRefetchWorker builds the Phase C re-fetch worker. It shares the runner's
// fetcher (one evidence directory), SpaceGate (a pause stops re-fetches too)
// and HostGate (never two fetches from one attacker server at once). Space
// and OnCycle are set here, before the caller starts Run: both are read
// unlocked by every tick.
//
// It reports as an optional worker (never gates /readyz): its 30 s tick is
// longer than readiness's 15 s idle-progress limit, so a required worker
// would read stalled between ticks, and re-fetching is extra yield on top of
// first capture, not something collection depends on. Failures still show
// in /metrics as worker_error{worker="capture_refetch"}.
func newRefetchWorker(st *store.Store, runner *capture.Runner, m *observability.Monitor) *capture.RefetchWorker {
	w := capture.NewRefetchWorker(st, runner.Fetch(), runner.HostGate())
	w.Space = runner.SpaceGate()
	w.OnCycle = workerCycleWith(m, observability.CaptureRefetch, 2*time.Minute, false)
	return w
}
