package observability

import (
	"bytes"
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFunnelExpositionUsesFixedLabels(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	m := New(func() time.Time { return now }, 0)
	m.RecordFunnel(FunnelSample{At: now.Add(-time.Minute), Valid: true,
		Day:  FunnelWindow{Connected: 10, LoggedIn: 4, RanCommands: 3, DownloadAttempt: 2, Captured: 1, NewPayloads: 1, SharedBazaar: 1},
		Week: FunnelWindow{Connected: 70, Captured: 5}})
	var buf bytes.Buffer
	if err := WritePrometheus(&buf, m.Snapshot()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"shardlure_payload_funnel_available 1\n",
		`shardlure_payload_funnel{window="24h",stage="connected"} 10` + "\n",
		`shardlure_payload_funnel{window="24h",stage="download_attempt"} 2` + "\n",
		`shardlure_payload_funnel{window="7d",stage="captured"} 5` + "\n",
		`shardlure_payload_funnel{window="7d",stage="shared_threatfox"} 0` + "\n",
		"shardlure_capture_paused 0\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in exposition:\n%s", want, out)
		}
	}
}

func TestFunnelUnavailableWhenStaleOrInvalid(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	m := New(func() time.Time { return now }, 0)
	m.RecordFunnel(FunnelSample{At: now.Add(-16 * time.Minute), Valid: true, Day: FunnelWindow{Connected: 1}})
	var buf bytes.Buffer
	_ = WritePrometheus(&buf, m.Snapshot())
	if !strings.Contains(buf.String(), "shardlure_payload_funnel_available 0\n") {
		t.Fatal("a funnel older than 15 minutes must report unavailable")
	}
	m.RecordFunnel(FunnelSample{At: now, Valid: true, Day: FunnelWindow{Connected: 7}})
	m.RecordFunnel(FunnelSample{Valid: false})
	s := m.Snapshot()
	if s.Funnel.Valid || s.Funnel.Day.Connected != 7 {
		t.Fatalf("a failed refresh must mark invalid but keep the last values, got %+v", s.Funnel)
	}
}

func TestStagesAreFixedAndOrdered(t *testing.T) {
	w := FunnelWindow{Connected: 1, LoggedIn: 2, RanCommands: 3, DownloadAttempt: 4, Captured: 5,
		NewPayloads: 6, SharedBazaar: 7, SharedURLhaus: 8, SharedThreatFox: 9}
	want := []FunnelStage{{"connected", 1}, {"logged_in", 2}, {"ran_commands", 3}, {"download_attempt", 4},
		{"captured", 5}, {"new_payloads", 6}, {"shared_bazaar", 7}, {"shared_urlhaus", 8}, {"shared_threatfox", 9}}
	got := w.Stages()
	if len(got) != len(want) {
		t.Fatalf("stages = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("stage %d = %+v, want %+v (all: %v)", i, got[i], want[i], got)
		}
	}
}

// waitFunnel polls the snapshot until cond holds or the deadline passes.
func waitFunnel(t *testing.T, m *Monitor, cond func(FunnelSample) bool) FunnelSample {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f := m.Snapshot().Funnel
		if cond(f) {
			return f
		}
		if time.Now().After(deadline) {
			t.Fatalf("funnel condition not reached, last %+v", f)
		}
		time.Sleep(time.Millisecond)
	}
}

func runSamplerAsync(ctx context.Context, m *Monitor, every, budget time.Duration, collect func(context.Context) (FunnelSample, error)) chan struct{} {
	done := make(chan struct{})
	go func() {
		RunFunnelSampler(ctx, m, every, budget, collect)
		close(done)
	}()
	return done
}

func waitDone(t *testing.T, done chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sampler did not stop")
	}
}

func TestRunFunnelSamplerRecordsAndStops(t *testing.T) {
	m := New(time.Now, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	done := runSamplerAsync(ctx, m, time.Hour, time.Second, func(context.Context) (FunnelSample, error) {
		calls.Add(1)
		return FunnelSample{Day: FunnelWindow{Connected: 3}}, nil
	})
	f := waitFunnel(t, m, func(f FunnelSample) bool { return f.Valid })
	if f.Day.Connected != 3 || f.At.IsZero() || f.At.Location() != time.UTC {
		t.Fatalf("recorded funnel = %+v", f)
	}
	cancel()
	waitDone(t, done)
	if n := calls.Load(); n != 1 {
		t.Fatalf("collect calls = %d, want 1 (period is an hour)", n)
	}
}

func TestRunFunnelSamplerOverrunIsInvalidAndKeepsValues(t *testing.T) {
	m := New(time.Now, 0)
	m.RecordFunnel(FunnelSample{At: time.Now(), Valid: true, Day: FunnelWindow{Connected: 7}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runSamplerAsync(ctx, m, time.Hour, 20*time.Millisecond, func(cycle context.Context) (FunnelSample, error) {
		<-cycle.Done()
		// A collect that answers late with no error must still be dropped:
		// only the budget marks it expired.
		return FunnelSample{Day: FunnelWindow{Connected: 99}}, nil
	})
	f := waitFunnel(t, m, func(f FunnelSample) bool { return !f.Valid })
	if f.Day.Connected != 7 {
		t.Fatalf("an overrun must keep the last values, got %+v", f)
	}
	cancel()
	waitDone(t, done)
}

func TestRunFunnelSamplerRejectsNonPositiveDurations(t *testing.T) {
	for _, d := range []struct{ every, budget time.Duration }{{0, time.Second}, {-time.Second, time.Second}, {time.Hour, 0}, {time.Hour, -1}} {
		m := New(time.Now, 0)
		var calls atomic.Int32
		done := runSamplerAsync(context.Background(), m, d.every, d.budget, func(context.Context) (FunnelSample, error) {
			calls.Add(1)
			return FunnelSample{}, nil
		})
		waitDone(t, done)
		if n := calls.Load(); n != 0 {
			t.Fatalf("every=%v budget=%v: collect calls = %d, want 0", d.every, d.budget, n)
		}
	}
}

func TestCapturePausedGauge(t *testing.T) {
	m := New(time.Now, 0)
	m.SetCapturePaused(true)
	var buf bytes.Buffer
	_ = WritePrometheus(&buf, m.Snapshot())
	if !strings.Contains(buf.String(), "shardlure_capture_paused 1\n") {
		t.Fatal("paused capture must export 1")
	}
}

func TestFunnelSampleAvailable(t *testing.T) {
	at := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	good := FunnelSample{At: at, Valid: true}
	for _, tc := range []struct {
		name string
		f    FunnelSample
		now  time.Time
		want bool
	}{
		{"fresh", good, at.Add(time.Minute), true},
		{"at the bound", good, at.Add(funnelMaxAge), true},
		{"past the bound", good, at.Add(funnelMaxAge + time.Second), false},
		{"from the future", good, at.Add(-time.Second), false},
		{"invalid", FunnelSample{At: at}, at, false},
		{"never sampled", FunnelSample{Valid: true}, at, false},
	} {
		if got := tc.f.Available(tc.now); got != tc.want {
			t.Errorf("%s: Available = %v, want %v", tc.name, got, tc.want)
		}
	}
}
