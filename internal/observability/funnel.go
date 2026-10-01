package observability

import (
	"context"
	"time"
)

// FunnelWindow is one window of the payload funnel, copied from the store by
// the caller (this package must not depend on store).
type FunnelWindow struct {
	Connected, LoggedIn, RanCommands, DownloadAttempt int64
	Captured, NewPayloads                             int64
	SharedBazaar, SharedURLhaus, SharedThreatFox      int64
}

// FunnelStage is one fixed, ordered stage name and its count. Names are
// literals so the metric's label set stays closed.
type FunnelStage struct {
	Name string
	N    int64
}

// Stages returns the stages in funnel order.
func (w FunnelWindow) Stages() []FunnelStage {
	return []FunnelStage{
		{"connected", w.Connected}, {"logged_in", w.LoggedIn}, {"ran_commands", w.RanCommands},
		{"download_attempt", w.DownloadAttempt}, {"captured", w.Captured}, {"new_payloads", w.NewPayloads},
		{"shared_bazaar", w.SharedBazaar}, {"shared_urlhaus", w.SharedURLhaus}, {"shared_threatfox", w.SharedThreatFox},
	}
}

// FunnelSample is the last computed funnel for the 24h and 7d windows.
type FunnelSample struct {
	At        time.Time
	Valid     bool
	Day, Week FunnelWindow
}

// funnelMaxAge bounds how stale a funnel may be before /metrics calls it
// unavailable: three missed 5-minute refreshes.
const funnelMaxAge = 15 * time.Minute

// RecordFunnel stores a sample. An invalid sample (a failed refresh) keeps
// the last good values and only clears Valid, like RecordAggregates, so one
// slow query does not zero the operator's dashboards.
func (m *Monitor) RecordFunnel(sample FunnelSample) {
	sample.At = sample.At.UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	if !sample.Valid {
		m.state.Funnel.Valid = false
		return
	}
	m.state.Funnel = sample
}

// RunFunnelSampler refreshes the funnel every period with its own budget. It
// is separate from RunAggregateSampler because that sampler has a 1 s budget
// sized for queue counts, while a 7-day funnel over ~2M events takes seconds
// on the ARM sensor.
func RunFunnelSampler(ctx context.Context, m *Monitor, every, budget time.Duration, collect func(context.Context) (FunnelSample, error)) {
	// A non-positive period would panic in time.NewTicker, and a non-positive
	// budget expires every cycle before collect can answer. Both are caller
	// misconfiguration, so the sampler returns without running rather than
	// panicking the daemon or recording a stream of invalid samples. The gap
	// stays visible: shardlure_payload_funnel_available reads 0.
	if m == nil || collect == nil || every <= 0 || budget <= 0 {
		return
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for ctx.Err() == nil {
		at := m.clockNow().UTC()
		cycle, cancel := context.WithTimeout(ctx, budget)
		sample, err := collect(cycle)
		expired := cycle.Err() != nil
		cancel()
		if err == nil && !expired {
			sample.Valid = true
			if sample.At.IsZero() {
				sample.At = at
			}
			m.RecordFunnel(sample)
		} else if ctx.Err() == nil {
			m.RecordFunnel(FunnelSample{Valid: false})
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// SetCapturePaused records whether capture writes are paused for lack of
// free space. It is deliberately not a worker Failure: a pause is the guard
// working, and marking it a failure would fail /readyz.
func (m *Monitor) SetCapturePaused(paused bool) {
	m.mu.Lock()
	m.state.CapturePaused = paused
	m.mu.Unlock()
}
