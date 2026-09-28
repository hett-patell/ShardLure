package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/observability"
)

// A failing campaign worker must never mark the daemon not-ready: readiness
// skips workers whose Required flag is false (state.go readiness loop).
func TestOptionalWorkerFailureIsNotRequired(t *testing.T) {
	m := observability.New(time.Now, 0)
	notify := workerCycleWith(m, observability.Campaigns, time.Minute, false)
	notify(true, nil)
	notify(false, errors.New("boom"))
	st := m.Snapshot().Workers[observability.Campaigns]
	if st.Required || st.Failure == observability.FailureNone {
		t.Fatalf("state %+v", st)
	}
	// And the daemon stays ready with the failed optional worker reported.
	if err := m.SetPhase(observability.Serving); err != nil {
		t.Fatal(err)
	}
	m.RecordSample(observability.Sample{At: time.Now().UTC(), DatabaseUp: true, DataAccessible: true})
	if ready, why := m.Ready(); !ready {
		t.Fatalf("optional worker failure gated readiness: %v", why)
	}
	var out strings.Builder
	if err := observability.WritePrometheus(&out, m.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `shardlure_worker_error{worker="campaigns"} 1`) {
		t.Fatal("campaign worker failure is not visible in /metrics")
	}
}
