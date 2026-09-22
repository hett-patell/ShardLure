package observability

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReadinessClockSpaceAndWorkerContract(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	m := New(func() time.Time { return now }, 256<<20)
	if ready, _ := m.Ready(); ready {
		t.Fatal("starting process ready")
	}
	m.SetPhase(Serving)
	good := Sample{At: now, DatabaseUp: true, DataAccessible: true, DataFreeBytes: 1 << 30}
	m.RecordSample(good)
	if ready, why := m.Ready(); !ready {
		t.Fatalf("healthy sample rejected: %v", why)
	}
	now = now.Add(16 * time.Second)
	if ready, _ := m.Ready(); ready {
		t.Fatal("stale sample ready")
	}
	now = good.At.Add(-time.Second)
	if ready, _ := m.Ready(); ready {
		t.Fatal("future sample ready")
	}
	now = good.At
	low := good
	low.DataFreeBytes = 1
	m.RecordSample(low)
	if ready, _ := m.Ready(); ready {
		t.Fatal("low-space ready")
	}
	low = good
	low.CaptureRequired = true
	low.EvidenceAccessible = false
	m.RecordSample(low)
	if ready, _ := m.Ready(); ready {
		t.Fatal("missing required evidence ready")
	}
	m.RecordSample(good)
	if err := m.SetWorker(CowrieIngest, WorkerState{Enabled: true, Required: true, Running: true, LastProgress: now}); err != nil {
		t.Fatal(err)
	}
	if ready, _ := m.Ready(); !ready {
		t.Fatal("quiet live worker rejected for no attacks")
	}
	m.SetWorker(CowrieIngest, WorkerState{Enabled: true, Required: true, Running: false, LastProgress: now})
	if ready, _ := m.Ready(); ready {
		t.Fatal("dead worker ready")
	}
	m.SetWorker(CowrieIngest, WorkerState{Enabled: true, Required: true, Running: true, LastProgress: now.Add(-time.Minute), OperationDeadline: now.Add(30 * time.Second)})
	if ready, _ := m.Ready(); !ready {
		t.Fatal("normal operation budget mistaken for dead worker")
	}
	m.SetWorker(CowrieIngest, WorkerState{Enabled: true, Required: true, Running: true, LastProgress: now.Add(time.Second)})
	if ready, _ := m.Ready(); ready {
		t.Fatal("future heartbeat ready")
	}
	m.SetWorker(CowrieIngest, WorkerState{})
	m.SetWorker(Backfills, WorkerState{Enabled: true, Required: true, Completed: true, LastProgress: now})
	if ready, _ := m.Ready(); !ready {
		t.Fatal("completed finite backfill considered dead")
	}
	m.SetPhase(Draining)
	m.SetPhase(Serving)
	if ready, _ := m.Ready(); ready {
		t.Fatal("serving replaced draining")
	}
	disabled := New(func() time.Time { return now }, 0)
	disabled.SetPhase(Serving)
	good.DataFreeBytes = 0
	disabled.RecordSample(good)
	if ready, _ := disabled.Ready(); !ready {
		t.Fatal("zero threshold did not disable only free-space threshold")
	}
	good.DatabaseUp = false
	disabled.RecordSample(good)
	if ready, _ := disabled.Ready(); ready {
		t.Fatal("zero threshold disabled DB health")
	}
}

func TestMetricsClosedCardinalityAndSeparateDurableAccounting(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	m := New(func() time.Time { return now }, 0)
	var before, after bytes.Buffer
	if err := WritePrometheus(&before, m.Snapshot()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10000; i++ {
		if err := m.ObserveProvider(Provider(i+100), Submit, Success); err == nil {
			t.Fatal("unknown provider accepted")
		}
		if err := m.ObserveIngest(Cowrie, Outcome(i+100), 1); err == nil {
			t.Fatal("unknown outcome accepted")
		}
	}
	if err := WritePrometheus(&after, m.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Fatal("invalid input retained state or labels")
	}
	if n := testing.AllocsPerRun(1000, func() { _ = m.ObserveProvider(Provider(1000), Submit, Success) }); n != 0 {
		t.Fatalf("invalid input allocated retained state: %f", n)
	}
	m.ObserveProvider(URLhaus, Submit, Success)
	m.ObserveDurableShare(URLhaus, StorageError, 1)
	s := m.Snapshot()
	if s.ProviderRequests[URLhaus][Submit][Success] != 1 || s.DurableShares[URLhaus][Success] != 0 || s.DurableShares[URLhaus][StorageError] != 1 {
		t.Fatal("upstream acceptance confused with durable success")
	}
	other := New(func() time.Time { return now }, 0)
	if other.Snapshot().ProviderRequests[URLhaus][Submit][Success] != 0 {
		t.Fatal("counters leaked across process monitors")
	}
	after.Reset()
	WritePrometheus(&after, s)
	if strings.Contains(after.String(), "path=") || strings.Contains(after.String(), "url=") {
		t.Fatal("private labels exported")
	}
}

func TestMonitorConcurrentUpdatesAndSnapshots(t *testing.T) {
	m := New(time.Now, 0)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				m.ObserveIngest(Cowrie, Success, 1)
				m.ObserveProvider(VirusTotal, HashLookup, Success)
				m.RecordSample(Sample{At: time.Now(), DatabaseUp: true, DataAccessible: true})
				var out bytes.Buffer
				if err := WritePrometheus(&out, m.Snapshot()); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	workers.Wait()
	s := m.Snapshot()
	if s.Ingest[Cowrie][Success] != 800 || s.ProviderRequests[VirusTotal][HashLookup][Success] != 800 {
		t.Fatal("concurrent observations lost")
	}
	s.Ingest[Cowrie][Success] = 0
	if m.Snapshot().Ingest[Cowrie][Success] != 800 {
		t.Fatal("snapshot mutates live state")
	}
}
