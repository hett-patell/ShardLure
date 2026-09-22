// Package observability holds bounded, process-local operational state. It has
// no store/web/provider dependencies and never performs an upstream operation.
package observability

import (
	"errors"
	"sync"
	"time"
)

type Phase int

const (
	Starting Phase = iota
	Serving
	Draining
)

type Source int

const (
	Journal Source = iota
	Cowrie
	sourceCount
)

type Worker int

const (
	JournalTail Worker = iota
	CowrieIngest
	CaptureURL
	CaptureFiles
	Backfills
	workerCount
)

type Provider int

const (
	AbuseIPDB Provider = iota
	VirusTotal
	GreyNoise
	Shodan
	OTX
	IPQualityScore
	IPinfo
	MalwareBazaar
	URLhaus
	ThreatFox
	IPAPI
	providerCount
)

type Operation int

const (
	IPLookup Operation = iota
	HashLookup
	Upload
	Submit
	operationCount
)

type Outcome int

const (
	Success Outcome = iota
	Unauthorized
	RateLimited
	TransportError
	InvalidResponse
	Rejected
	Canceled
	StorageError
	outcomeCount
)

type Failure int

const (
	FailureNone Failure = iota
	FailureStorage
	FailureIO
	FailureCanceled
	FailureUnexpected
	failureCount
)

type Reason int

const (
	ReasonReady Reason = iota
	ReasonStarting
	ReasonDraining
	ReasonSampleUnavailable
	ReasonDatabase
	ReasonDataAccess
	ReasonEvidenceAccess
	ReasonLowSpace
	ReasonWorkerUnavailable
	ReasonWorkerStalled
)

var phaseNames = [...]string{"starting", "serving", "draining"}
var sourceNames = [...]string{"journal", "cowrie"}
var workerNames = [...]string{"journal_tail", "cowrie_ingest", "capture_url", "capture_files", "backfills"}
var providerNames = [...]string{"abuseipdb", "virustotal", "greynoise", "shodan", "otx", "ipqualityscore", "ipinfo", "malwarebazaar", "urlhaus", "threatfox", "ip_api"}
var operationNames = [...]string{"ip_lookup", "hash_lookup", "upload", "submit"}
var outcomeNames = [...]string{"success", "unauthorized", "rate_limited", "transport_error", "invalid_response", "rejected", "canceled", "storage_error"}
var failureNames = [...]string{"none", "storage", "io", "canceled", "unexpected"}
var reasonNames = [...]string{"ready", "starting", "draining", "sample_unavailable", "database_unavailable", "data_unavailable", "evidence_unavailable", "low_space", "worker_unavailable", "worker_stalled"}

func enumName(names []string, n int) string {
	if n < 0 || n >= len(names) {
		return "unknown"
	}
	return names[n]
}
func (p Phase) String() string     { return enumName(phaseNames[:], int(p)) }
func (s Source) String() string    { return enumName(sourceNames[:], int(s)) }
func (w Worker) String() string    { return enumName(workerNames[:], int(w)) }
func (p Provider) String() string  { return enumName(providerNames[:], int(p)) }
func (o Operation) String() string { return enumName(operationNames[:], int(o)) }
func (o Outcome) String() string   { return enumName(outcomeNames[:], int(o)) }
func (f Failure) String() string   { return enumName(failureNames[:], int(f)) }
func (r Reason) String() string    { return enumName(reasonNames[:], int(r)) }

var ErrInvalidObservation = errors.New("observability: invalid closed-enum observation")
var ErrInvalidState = errors.New("observability: invalid worker or phase transition")

type Sample struct {
	At                                                              time.Time
	DatabaseUp, DataAccessible, CaptureRequired, EvidenceAccessible bool
	DataFreeBytes, EvidenceFreeBytes                                uint64
}
type WorkerState struct {
	Enabled, Running, Completed, Required        bool
	LastProgress, LastSuccess, OperationDeadline time.Time
	Failure                                      Failure
}
type Snapshot struct {
	At, StartedAt    time.Time
	Uptime           time.Duration
	Phase            Phase
	Sample           Sample
	SampleValid      bool
	SampleAge        time.Duration
	MinFreeBytes     uint64
	Workers          [workerCount]WorkerState
	Ingest           [sourceCount][outcomeCount]uint64
	ProviderRequests [providerCount][operationCount][outcomeCount]uint64
	DurableShares    [providerCount][outcomeCount]uint64
	Ready            bool
	Reason           Reason
}
type Monitor struct {
	mu    sync.Mutex
	now   func() time.Time
	state Snapshot
}

func New(now func() time.Time, minFreeBytes uint64) *Monitor {
	if now == nil {
		now = time.Now
	}
	return &Monitor{now: now, state: Snapshot{StartedAt: now(), Phase: Starting, MinFreeBytes: minFreeBytes}}
}
func (m *Monitor) SetPhase(phase Phase) error {
	if phase < Starting || phase > Draining {
		return ErrInvalidObservation
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if phase < m.state.Phase {
		return ErrInvalidState
	}
	m.state.Phase = phase
	return nil
}
func (m *Monitor) SetWorker(worker Worker, state WorkerState) error {
	if worker < 0 || worker >= workerCount || state.Failure < 0 || state.Failure >= failureCount {
		return ErrInvalidObservation
	}
	if (!state.Enabled && (state.Running || state.Required || state.Completed)) || (state.Completed && (state.Running || worker != Backfills)) {
		return ErrInvalidState
	}
	m.mu.Lock()
	m.state.Workers[worker] = state
	m.mu.Unlock()
	return nil
}
func addCounter(value *uint64, n uint64) {
	if ^uint64(0)-*value < n {
		*value = ^uint64(0)
	} else {
		*value += n
	}
}
func (m *Monitor) ObserveIngest(source Source, outcome Outcome, n uint64) error {
	if source < 0 || source >= sourceCount || outcome < 0 || outcome >= outcomeCount {
		return ErrInvalidObservation
	}
	m.mu.Lock()
	addCounter(&m.state.Ingest[source][outcome], n)
	m.mu.Unlock()
	return nil
}
func (m *Monitor) ObserveProvider(provider Provider, operation Operation, outcome Outcome) error {
	if provider < 0 || provider >= providerCount || operation < 0 || operation >= operationCount || outcome < 0 || outcome >= outcomeCount || outcome == StorageError {
		return ErrInvalidObservation
	}
	m.mu.Lock()
	addCounter(&m.state.ProviderRequests[provider][operation][outcome], 1)
	m.mu.Unlock()
	return nil
}
func (m *Monitor) ObserveDurableShare(provider Provider, outcome Outcome, n uint64) error {
	if provider < 0 || provider >= providerCount || outcome < 0 || outcome >= outcomeCount {
		return ErrInvalidObservation
	}
	m.mu.Lock()
	addCounter(&m.state.DurableShares[provider][outcome], n)
	m.mu.Unlock()
	return nil
}
func (m *Monitor) RecordSample(sample Sample) { m.mu.Lock(); m.state.Sample = sample; m.mu.Unlock() }
func (m *Monitor) Snapshot() Snapshot {
	now := time.Now()
	if m.now != nil {
		now = m.now()
	}
	m.mu.Lock()
	s := m.state
	m.mu.Unlock()
	s.At = now
	s.Uptime = now.Sub(s.StartedAt)
	if s.StartedAt.IsZero() || s.Uptime < 0 {
		s.Uptime = 0
	}
	s.SampleAge = now.Sub(s.Sample.At)
	if s.Sample.At.IsZero() {
		s.SampleAge = 0
	}
	s.SampleValid = !s.Sample.At.IsZero() && s.SampleAge >= 0 && s.SampleAge <= 15*time.Second
	s.Ready, s.Reason = readySnapshot(s)
	return s
}
func (m *Monitor) Ready() (bool, Reason) { s := m.Snapshot(); return s.Ready, s.Reason }

func captureRequired(s Snapshot) bool {
	return s.Sample.CaptureRequired || s.Workers[CaptureURL].Enabled || s.Workers[CaptureFiles].Enabled
}

func readySnapshot(s Snapshot) (bool, Reason) {
	switch s.Phase {
	case Starting:
		return false, ReasonStarting
	case Draining:
		return false, ReasonDraining
	case Serving:
	default:
		return false, ReasonStarting
	}
	if !s.SampleValid {
		return false, ReasonSampleUnavailable
	}
	if !s.Sample.DatabaseUp {
		return false, ReasonDatabase
	}
	if !s.Sample.DataAccessible {
		return false, ReasonDataAccess
	}
	capture := captureRequired(s)
	if capture && !s.Sample.EvidenceAccessible {
		return false, ReasonEvidenceAccess
	}
	if s.MinFreeBytes != 0 && (s.Sample.DataFreeBytes < s.MinFreeBytes || (capture && s.Sample.EvidenceFreeBytes < s.MinFreeBytes)) {
		return false, ReasonLowSpace
	}
	for _, worker := range s.Workers {
		if !worker.Enabled || !worker.Required {
			continue
		}
		if worker.Failure != FailureNone {
			return false, ReasonWorkerUnavailable
		}
		if worker.Completed {
			continue
		}
		if !worker.Running {
			return false, ReasonWorkerUnavailable
		}
		age := s.At.Sub(worker.LastProgress)
		if worker.LastProgress.IsZero() || age < 0 {
			return false, ReasonWorkerStalled
		}
		if !worker.OperationDeadline.IsZero() {
			if !worker.OperationDeadline.After(s.At) {
				return false, ReasonWorkerStalled
			}
		} else if age > 15*time.Second {
			return false, ReasonWorkerStalled
		}
	}
	return true, ReasonReady
}
