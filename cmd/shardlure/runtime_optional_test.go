package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"sync/atomic"
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

// A persistently failing optional worker must keep reading as failed for the
// whole streak, not just for the seconds between a real attempt and the next
// cycle: the campaign worker returns its retained error while it backs off,
// and the loop must neither clear the flag nor advance the last success on
// those cycles. The failure is logged once per streak (on the first cycle and
// on a change of text), never on every 5 s tick, and the recovery once.
func TestOptionalWorkerPersistentFailureStaysReportedAndLogsOnce(t *testing.T) {
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prev)

	m := observability.New(time.Now, 0)
	var cycles atomic.Int32
	var healthy atomic.Bool
	boom := errors.New("no such table: script_version_carry")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runOptionalWorker(ctx, m, observability.Campaigns, time.Millisecond, time.Second, func(context.Context) error {
			cycles.Add(1)
			if healthy.Load() {
				return nil
			}
			return boom // the retained error, identical on every cycle
		})
	}()
	waitFor := func(cond func() bool, what string) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
			if cond() {
				return
			}
		}
		t.Fatalf("timed out waiting for %s", what)
	}
	waitFor(func() bool { return cycles.Load() >= 20 }, "twenty failing cycles")
	st := m.Snapshot().Workers[observability.Campaigns]
	if st.Failure == observability.FailureNone || !st.LastSuccess.IsZero() {
		t.Fatalf("after %d failing cycles the worker reads healthy: %+v", cycles.Load(), st)
	}
	var out strings.Builder
	if err := observability.WritePrometheus(&out, m.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `shardlure_worker_error{worker="campaigns"} 1`) || !strings.Contains(out.String(), `shardlure_worker_last_success_timestamp_seconds{worker="campaigns"} 0`) {
		t.Fatalf("metrics do not show the streak:\n%s", out.String())
	}
	if n := strings.Count(logs.String(), "script_version_carry"); n != 1 {
		t.Fatalf("failure logged %d times over %d cycles, want exactly once per streak:\n%s", n, cycles.Load(), logs.String())
	}

	healthy.Store(true)
	waitFor(func() bool { return m.Snapshot().Workers[observability.Campaigns].Failure == observability.FailureNone }, "recovery")
	waitFor(func() bool { return strings.Contains(logs.String(), "campaigns worker recovered") }, "recovery log line")
	if st := m.Snapshot().Workers[observability.Campaigns]; st.LastSuccess.IsZero() {
		t.Fatalf("recovered worker has no last success: %+v", st)
	}
	cancel()
	<-done
	if n := strings.Count(logs.String(), "recovered"); n != 1 {
		t.Fatalf("recovery logged %d times:\n%s", n, logs.String())
	}
}
