package observability

import (
	"bytes"
	"context"
	"errors"
	"strings"
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
	names := []string{}
	for _, st := range (FunnelWindow{}).Stages() {
		names = append(names, st.Name)
	}
	want := "connected,logged_in,ran_commands,download_attempt,captured,new_payloads,shared_bazaar,shared_urlhaus,shared_threatfox"
	if strings.Join(names, ",") != want {
		t.Fatalf("stages = %v", names)
	}
}

func TestRunFunnelSamplerRecordsAndStops(t *testing.T) {
	m := New(time.Now, 0)
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	done := make(chan struct{})
	go func() {
		RunFunnelSampler(ctx, m, time.Hour, time.Second, func(context.Context) (FunnelSample, error) {
			calls++
			if calls == 1 {
				cancel()
				return FunnelSample{Day: FunnelWindow{Connected: 3}}, nil
			}
			return FunnelSample{}, errors.New("unreachable")
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sampler did not stop after cancel")
	}
	if calls != 1 {
		t.Fatalf("collect calls = %d, want 1", calls)
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
