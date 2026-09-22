package observability

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

type brokenMetricWriter struct{ err error }

func (w brokenMetricWriter) Write([]byte) (int, error) { return 0, w.err }

func TestMetricsHonorCaptureWorkerRequirementsAndWriterErrors(t *testing.T) {
	now := time.Now()
	m := New(func() time.Time { return now }, 0)
	m.SetPhase(Serving)
	m.SetWorker(CaptureFiles, WorkerState{Enabled: true, Required: true, Running: true, LastProgress: now})
	m.RecordSample(Sample{At: now, DatabaseUp: true, DataAccessible: true, EvidenceAccessible: true, EvidenceFreeBytes: 123})
	var output bytes.Buffer
	if err := WritePrometheus(&output, m.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "shardlure_volume_enabled{role=\"evidence\"} 1\n") || !strings.Contains(output.String(), "shardlure_volume_available{role=\"evidence\"} 1\n") {
		t.Fatal("metrics contradict readiness about required evidence volume")
	}
	sentinel := errors.New("closed writer")
	if err := WritePrometheus(brokenMetricWriter{sentinel}, m.Snapshot()); !errors.Is(err, sentinel) {
		t.Fatalf("writer failure swallowed: %v", err)
	}
	if err := m.ObserveProvider(URLhaus, Submit, StorageError); err == nil {
		t.Fatal("storage failure counted as a second upstream request")
	}
}
