package observability

import (
	"context"
	"errors"
	"github.com/networkshard/shardlure/internal/safefile"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSamplerBudgetCancellationAndNoOverlappingCycles(t *testing.T) {
	m := New(time.Now, 0)
	m.SetPhase(Serving)
	m.RecordSample(Sample{At: time.Now(), DatabaseUp: true, DataAccessible: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var active, maxActive, calls atomic.Int32
	probe := func(ctx context.Context) (Sample, error) {
		n := active.Add(1)
		defer active.Add(-1)
		maxActive.Store(max(maxActive.Load(), n))
		calls.Add(1)
		<-ctx.Done()
		return Sample{}, ctx.Err()
	}
	done := make(chan struct{})
	go func() { defer close(done); runSampler(ctx, m, probe, 5*time.Millisecond, 10*time.Millisecond) }()
	deadline := time.After(time.Second)
	for m.Snapshot().Sample.DatabaseUp {
		select {
		case <-deadline:
			t.Fatal("probe budget did not fail readiness")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sampler ignored cancellation")
	}
	if calls.Load() == 0 || maxActive.Load() != 1 {
		t.Fatalf("overlapping probes: calls=%d active=%d", calls.Load(), maxActive.Load())
	}
	if ready, _ := m.Ready(); ready {
		t.Fatal("failed probe remained ready")
	}
}

func TestFilesystemProbeDistinguishesUnavailableAndDisabledVolumes(t *testing.T) {
	data, evidence := t.TempDir(), t.TempDir()
	probe := NewFilesystemProbe(func(context.Context) error { return nil }, data, evidence, true)
	sample, err := probe(context.Background())
	if err != nil || !sample.DatabaseUp || !sample.DataAccessible || !sample.EvidenceAccessible || sample.DataFreeBytes == 0 {
		root, openErr := safefile.OpenRoot(data)
		if openErr != nil {
			t.Logf("root access: %v", openErr)
		} else {
			t.Logf("write access: %v", root.CheckWritable())
			root.Close()
		}
		info, _ := os.Stat(filepath.Dir(data))
		if info != nil {
			t.Logf("fixture parent mode=%v", info.Mode())
		}
		leaf, _ := os.Stat(data)
		if leaf != nil {
			t.Logf("fixture leaf mode=%v", leaf.Mode())
		}
		t.Fatalf("healthy volumes %+v %v", sample, err)
	}
	if err := os.Chmod(evidence, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(evidence, 0700)
	sample, err = probe(context.Background())
	if err != nil || sample.EvidenceAccessible {
		t.Fatalf("read-only volume looks writable: %+v %v", sample, err)
	}
	probe = NewFilesystemProbe(func(context.Context) error { return nil }, data, filepath.Join(data, "missing"), false)
	sample, err = probe(context.Background())
	if err != nil || sample.CaptureRequired || !sample.DataAccessible {
		t.Fatalf("disabled capture requires evidence: %+v %v", sample, err)
	}
	probe = NewFilesystemProbe(func(context.Context) error { return errors.New("private DB error") }, data, evidence, true)
	sample, err = probe(context.Background())
	if err != nil || sample.DatabaseUp {
		t.Fatalf("unavailable DB looks healthy: %+v %v", sample, err)
	}
}

func TestAggregateSamplerHasIndependentBoundedCadence(t *testing.T) {
	m := New(time.Now, 0)
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunAggregateSampler(ctx, m, func(context.Context) (AggregateSample, error) {
			calls.Add(1)
			return AggregateSample{}, errors.New("inert failure")
		})
	}()
	deadline := time.After(time.Second)
	for calls.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("no initial aggregate attempt")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	for i := 0; i < 1000; i++ {
		_ = m.Snapshot()
	}
	cancel()
	<-done
	if calls.Load() != 1 || m.Snapshot().Aggregates.Valid {
		t.Fatal("scrapes drove aggregates or failed values looked valid")
	}
}

func TestSamplerStampsItsMonitorClock(t *testing.T) {
	now := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	m := New(func() time.Time { return now }, 0)
	m.SetPhase(Serving)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunSampler(ctx, m, func(context.Context) (Sample, error) { return Sample{DatabaseUp: true, DataAccessible: true}, nil })
	}()
	deadline := time.After(time.Second)
	for m.Snapshot().Sample.At.IsZero() {
		select {
		case <-deadline:
			t.Fatal("sample never recorded")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	<-done
	if !m.Snapshot().Sample.At.Equal(now) {
		t.Fatal("sampler ignored injected monitor clock")
	}
}
