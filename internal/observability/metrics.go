package observability

import (
	"fmt"
	"io"
	"time"
)

func flag(value bool) int {
	if value {
		return 1
	}
	return 0
}
func epoch(value time.Time) float64 {
	if value.IsZero() {
		return 0
	}
	return float64(value.UnixNano()) / 1e9
}

// WritePrometheus renders only a bounded value snapshot. It cannot query a DB,
// walk files, start probes, or turn attacker strings into names/labels.
func WritePrometheus(out io.Writer, s Snapshot) error {
	capture := captureRequired(s)
	var err error
	write := func(format string, args ...any) {
		if err == nil {
			_, err = fmt.Fprintf(out, format, args...)
		}
	}
	header := func(name, kind, help string) {
		write("# HELP shardlure_%s %s\n# TYPE shardlure_%s %s\n", name, help, name, kind)
	}
	header("ready", "gauge", "Whether required process components are ready.")
	write("shardlure_ready %d\n", flag(s.Ready))
	header("uptime_seconds", "gauge", "Process monitor uptime; resets on restart.")
	write("shardlure_uptime_seconds %g\n", s.Uptime.Seconds())
	header("phase", "gauge", "Current lifecycle phase.")
	for _, phase := range []Phase{Starting, Serving, Draining} {
		write("shardlure_phase{phase=%q} %d\n", phase.String(), flag(s.Phase == phase))
	}
	header("health_sample_available", "gauge", "Whether the health sample is recent and not future dated.")
	write("shardlure_health_sample_available %d\n", flag(s.SampleValid))
	header("health_sample_age_seconds", "gauge", "Age of the last health sample; availability is separate.")
	write("shardlure_health_sample_age_seconds %g\n", s.SampleAge.Seconds())
	header("database_up", "gauge", "Last sampled database reachability.")
	write("shardlure_database_up %d\n", flag(s.Sample.DatabaseUp && s.SampleValid))
	header("probe_failures_total", "counter", "Process-local failed health probe cycles.")
	write("shardlure_probe_failures_total %d\n", s.ProbeFailures)
	age := s.At.Sub(s.Aggregates.At)
	available := s.Aggregates.Valid && !s.Aggregates.At.IsZero() && age >= 0 && age <= 2*time.Minute
	header("aggregate_sample_available", "gauge", "Whether operational aggregates are available and recent.")
	write("shardlure_aggregate_sample_available %d\n", flag(available))
	header("aggregate_sample_age_seconds", "gauge", "Age of last successful operational aggregates; availability is separate.")
	if s.Aggregates.At.IsZero() {
		age = 0
	}
	write("shardlure_aggregate_sample_age_seconds %g\n", age.Seconds())
	header("capture_jobs", "gauge", "Persisted queued work by fixed source and state; aggregate availability is separate.")
	for _, row := range []struct {
		source, state string
		n             int64
	}{{"file", "pending", s.Aggregates.FilePending}, {"file", "retry", s.Aggregates.FileRetry}, {"file", "leased", s.Aggregates.FileLeased}, {"url", "pending", s.Aggregates.URLPending}, {"url", "retry", s.Aggregates.URLRetry}, {"url", "leased", s.Aggregates.URLLeased}} {
		write("shardlure_capture_jobs{source=%q,state=%q} %d\n", row.source, row.state, row.n)
	}
	header("capture_discovery_lag", "gauge", "Event-ID distance behind discovery, not a count of expired records.")
	write("shardlure_capture_discovery_lag{source=\"file\"} %d\nshardlure_capture_discovery_lag{source=\"command\"} %d\n", s.Aggregates.FileDiscoveryLag, s.Aggregates.CommandDiscoveryLag)
	header("capture_protected_file_jobs", "gauge", "Live jobs retaining their required source names.")
	write("shardlure_capture_protected_file_jobs %d\n", s.Aggregates.ProtectedFileJobs)
	header("database_pool_connections", "gauge", "Last sampled SQL pool pressure.")
	write("shardlure_database_pool_connections{state=\"open\"} %d\nshardlure_database_pool_connections{state=\"in_use\"} %d\n", s.Aggregates.PoolOpen, s.Aggregates.PoolInUse)
	header("database_pool_waits", "gauge", "Sampled process SQL pool wait count; aggregate availability is separate.")
	write("shardlure_database_pool_waits %d\n", s.Aggregates.PoolWaits)
	header("volume_available", "gauge", "Whether volume measurements are available.")
	write("shardlure_volume_available{role=\"data\"} %d\n", flag(s.SampleValid && s.Sample.DataAccessible))
	write("shardlure_volume_available{role=\"evidence\"} %d\n", flag(s.SampleValid && capture && s.Sample.EvidenceAccessible))
	header("volume_enabled", "gauge", "Whether a volume role is required.")
	write("shardlure_volume_enabled{role=\"data\"} 1\nshardlure_volume_enabled{role=\"evidence\"} %d\n", flag(capture))
	header("volume_free_bytes", "gauge", "Sampled free bytes; availability and enabled state are separate.")
	write("shardlure_volume_free_bytes{role=\"data\"} %d\nshardlure_volume_free_bytes{role=\"evidence\"} %d\n", s.Sample.DataFreeBytes, s.Sample.EvidenceFreeBytes)
	for _, field := range []struct {
		name, help string
		value      func(WorkerState) float64
	}{
		{"enabled", "Whether a worker is enabled.", func(w WorkerState) float64 { return float64(flag(w.Enabled)) }},
		{"running", "Whether a worker is running.", func(w WorkerState) float64 { return float64(flag(w.Running)) }},
		{"completed", "Whether a finite worker completed.", func(w WorkerState) float64 { return float64(flag(w.Completed)) }},
		{"error", "Whether a worker has an active failure.", func(w WorkerState) float64 { return float64(flag(w.Failure != FailureNone)) }},
		{"last_success_timestamp_seconds", "Last successful worker cycle, not last attacker event.", func(w WorkerState) float64 { return epoch(w.LastSuccess) }},
		{"last_progress_timestamp_seconds", "Last worker heartbeat.", func(w WorkerState) float64 { return epoch(w.LastProgress) }},
	} {
		header("worker_"+field.name, "gauge", field.help)
		for i, w := range s.Workers {
			write("shardlure_worker_%s{worker=%q} %g\n", field.name, Worker(i).String(), field.value(w))
		}
	}
	header("ingest_events_total", "counter", "Process-local committed ingest events or failed work by source and outcome.")
	for source, counts := range s.Ingest {
		for outcome, n := range counts {
			write("shardlure_ingest_events_total{source=%q,outcome=%q} %d\n", Source(source).String(), Outcome(outcome).String(), n)
		}
	}
	header("provider_requests_total", "counter", "Process-local upstream operations; excludes durable storage outcomes.")
	for provider, operations := range s.ProviderRequests {
		for operation, counts := range operations {
			for outcome, n := range counts {
				if Outcome(outcome) == StorageError {
					continue
				}
				write("shardlure_provider_requests_total{provider=%q,operation=%q,outcome=%q} %d\n", Provider(provider).String(), Operation(operation).String(), Outcome(outcome).String(), n)
			}
		}
	}
	header("durable_share_total", "counter", "Process-local durably recorded sharing outcomes, separate from upstream acceptance.")
	for provider, counts := range s.DurableShares {
		for outcome, n := range counts {
			write("shardlure_durable_share_total{provider=%q,outcome=%q} %d\n", Provider(provider).String(), Outcome(outcome).String(), n)
		}
	}
	return err
}
