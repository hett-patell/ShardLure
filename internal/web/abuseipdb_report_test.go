package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func TestAbuseIPDBReportAllRejectsConcurrentBatchBeforeScanning(t *testing.T) {
	st, keys := seedReportSources(t, false)
	s := New(st, keys, "127.0.0.1:0", Options{AbuseReportEnabled: true, AbuseMinProbe: 60})
	s.abuseReportBatchMu.Lock()
	defer s.abuseReportBatchMu.Unlock()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.handleAbuseIPDBReportAll(rec, httptest.NewRequest(http.MethodPost,
		"/api/intel/abuseipdb/report-all", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("concurrent batch status = %d, want 409 before any closed-store scan: %s", rec.Code, rec.Body.String())
	}
}

func TestAbuseIPDBReportThrottleWaitIsCancellable(t *testing.T) {
	s := &Server{lastAbuseReportAt: time.Now()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	err := s.waitForAbuseReportSlot(ctx, 2*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled throttle: %v, want context.Canceled", err)
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("cancelled throttle waited %v", elapsed)
	}
}

func TestAbuseIPDBConcurrentSingleReportsDeduplicateBeforeSlowPOST(t *testing.T) {
	var posts atomic.Int32
	var first atomic.Bool
	started := make(chan struct{})
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		if first.CompareAndSwap(false, true) {
			close(started)
			<-release
		}
		_, _ = w.Write([]byte("{\"data\":{\"ipAddress\":\"8.8.8.8\",\"abuseConfidenceScore\":70}}"))
	}))
	defer upstream.Close()

	st, keys := seedReportSources(t, false)
	s := New(st, keys, "127.0.0.1:0", Options{
		AbuseReportEnabled: true,
		AbuseEndpoint:      upstream.URL,
		AbuseMinProbe:      60,
		AbuseRewindowHours: 24,
	})

	var wg sync.WaitGroup
	responses := make([]*httptest.ResponseRecorder, 2)
	for i := range responses {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			responses[i] = httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/intel/abuseipdb/report?ip=8.8.8.8", nil)
			s.handleAbuseIPDBReport(responses[i], req)
		}(i)
	}

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first report did not reach upstream")
	}
	// The process-wide throttle is two seconds. A throttle alone therefore
	// cannot make this assertion pass: while the first request is still held
	// open, the second request gets a chance to issue a duplicate POST.
	time.Sleep(2300 * time.Millisecond)
	if got := posts.Load(); got != 1 {
		close(release)
		wg.Wait()
		t.Fatalf("got %d upstream reports while first POST was still in flight, want 1", got)
	}
	close(release)
	wg.Wait()

	if got := posts.Load(); got != 1 {
		t.Fatalf("got %d upstream reports, want one; responses: %s / %s", got,
			responses[0].Body.String(), responses[1].Body.String())
	}
	if recorded, err := st.AbuseIPDBReported("8.8.8.8", 24*time.Hour); err != nil || !recorded {
		t.Fatalf("successful report not recorded: %v, %v", recorded, err)
	}
}

func TestAbuseIPDBBatchAndSingleReportsShareTargetDedupGate(t *testing.T) {
	var posts atomic.Int32
	firstStarted := make(chan struct{})
	secondStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch posts.Add(1) {
		case 1:
			close(firstStarted)
			<-releaseFirst
		case 2:
			close(secondStarted)
		}
		_, _ = w.Write([]byte("{\"data\":{\"ipAddress\":\"8.8.8.8\",\"abuseConfidenceScore\":70}}"))
	}))
	defer upstream.Close()

	st, keys := seedReportSources(t, false)
	s := New(st, keys, "127.0.0.1:0", Options{
		AbuseReportEnabled: true,
		AbuseEndpoint:      upstream.URL,
		AbuseMinProbe:      60,
		AbuseRewindowHours: 24,
	})

	batchDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		s.handleAbuseIPDBReportAll(rec, httptest.NewRequest(http.MethodPost,
			"/api/intel/abuseipdb/report-all", nil))
		batchDone <- rec
	}()
	select {
	case <-firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("batch report did not reach upstream")
	}

	singleDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		s.handleAbuseIPDBReport(rec, httptest.NewRequest(http.MethodPost,
			"/api/intel/abuseipdb/report?ip=8.8.8.8", nil))
		singleDone <- rec
	}()

	select {
	case <-secondStarted:
		close(releaseFirst)
		<-batchDone
		<-singleDone
		t.Fatal("single report raced the in-flight batch report for the same target")
	case <-time.After(250 * time.Millisecond):
		// The single request is waiting for the target gate, not issuing a
		// duplicate public report while the batch POST is unresolved.
	}

	close(releaseFirst)
	batch := <-batchDone
	single := <-singleDone
	if batch.Code != http.StatusOK || single.Code != http.StatusOK {
		t.Fatalf("unexpected responses: batch=%d %s single=%d %s",
			batch.Code, batch.Body.String(), single.Code, single.Body.String())
	}
	if got := posts.Load(); got != 1 {
		t.Fatalf("got %d upstream reports, want one", got)
	}
}

func TestAbuseIPDBReportAllFirstRateLimitIsNotSuccess(t *testing.T) {
	var posts atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"errors":[{"detail":"Daily rate limit"}]}`))
	}))
	defer upstream.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "report-all.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatalf("settings.Load: %v", err)
	}
	if err := keys.Set(settings.KeyAbuseIPDB, "test-key"); err != nil {
		t.Fatalf("set AbuseIPDB key: %v", err)
	}

	now := time.Now().UTC()
	// UpsertJournalActorAtomic, not UpsertActor: the staleness gate reads the
	// PRIMARY IP's own last-seen from actor_ips, and an actor without that row
	// is (correctly) refused as undateable before any POST is attempted.
	if err := st.UpsertJournalActorAtomic(&models.Actor{
		ID: "journal:8.8.8.8", Source: models.SourceJournal, PrimaryIP: "8.8.8.8",
		Playbook: "dictionary_spray", ProbeScore: 90, EventCount: 400,
		UniqueUsers: 30, AttemptsPerHour: 500,
		FirstSeen: now.Add(-time.Hour), LastSeen: now,
	}, "8.8.8.8", now.Add(-time.Hour), now, 400, "root", 300); err != nil {
		t.Fatalf("UpsertJournalActorAtomic: %v", err)
	}

	// Seed first-hand observations so this still reaches the rate-limit path.
	var events []*models.Event
	for i := 0; i < 400; i++ {
		events = append(events, &models.Event{TS: now.Add(-time.Duration(i) * time.Second),
			Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: "8.8.8.8",
			Username: []string{"root", "admin", "postgres", "oracle"}[i%4], ActorID: "journal:8.8.8.8"})
	}
	if err := st.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatal(err)
	}

	s := New(st, keys, "127.0.0.1:0", Options{
		AbuseReportEnabled: true,
		AbuseEndpoint:      upstream.URL,
		AbuseMinProbe:      60,
		AbuseRewindowHours: 24,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/intel/abuseipdb/report-all", nil)
	s.handleAbuseIPDBReportAll(rec, req)

	var got reportAllResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response (%d %q): %v", rec.Code, rec.Body.String(), err)
	}
	if got.Status != "rate_limited" {
		t.Fatalf("status = %q, want rate_limited; response=%s", got.Status, rec.Body.String())
	}
	if got.Reported != 0 || got.Skipped != 0 {
		t.Fatalf("counts = (%d reported, %d skipped), want (0, 0)", got.Reported, got.Skipped)
	}
	if !strings.Contains(strings.ToLower(got.Error), "rate limit") {
		t.Fatalf("error = %q, want useful rate-limit message", got.Error)
	}
	if gotPosts := posts.Load(); gotPosts != 1 {
		t.Fatalf("upstream POSTs = %d, want 1", gotPosts)
	}
}

// The report pool is intentionally ordered by lifetime actor rate, but a
// batch submission must spend scarce provider quota on the strongest CURRENT
// target first. Source selection and final cross-IP ranking are separate: a
// per-IP chooser cannot repair the pool's lifetime ordering.
func TestAbuseIPDBReportAllRanksCurrentEvidenceBeforeSubmitting(t *testing.T) {
	var firstIP string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if firstIP == "" {
			firstIP = r.Form.Get("ip")
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer upstream.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "report-order.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Set(settings.KeyAbuseIPDB, "test-key"); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Add(-time.Second)
	var events []*models.Event
	var actors []*models.AggregatedActor
	for _, fixture := range []struct {
		ip           string
		events       int
		lifetimeRate float64
	}{
		{ip: "8.8.8.8", events: 400, lifetimeRate: 9000},
		{ip: "1.1.1.1", events: 800, lifetimeRate: 2},
	} {
		actorID := "journal:" + fixture.ip
		actors = append(actors, &models.AggregatedActor{Actor: &models.Actor{
			ID: actorID, Source: models.SourceJournal, PrimaryIP: fixture.ip,
			FirstSeen: now.Add(-time.Hour), LastSeen: now,
			Playbook: "dictionary_spray", ProbeScore: 100,
			EventCount: fixture.events, UniqueUsers: 4,
			AttemptsPerHour: fixture.lifetimeRate,
		}})
		for i := 0; i < fixture.events; i++ {
			events = append(events, &models.Event{
				TS: now.Add(-time.Duration(i) * time.Second), Source: models.SourceJournal,
				Kind: models.KindFailedPass, SrcIP: fixture.ip, ActorID: actorID,
				Username: []string{"root", "admin", "postgres", "oracle"}[i%4],
			})
		}
	}
	if err := st.AppendEventsAndUpsertActorsAgg(events, actors); err != nil {
		t.Fatal(err)
	}

	s := New(st, keys, "127.0.0.1:0", Options{
		AbuseReportEnabled: true, AbuseEndpoint: upstream.URL,
		AbuseMinProbe: 60, AbuseRewindowHours: 24,
	})
	rec := httptest.NewRecorder()
	s.handleAbuseIPDBReportAll(rec, httptest.NewRequest(http.MethodPost,
		"/api/intel/abuseipdb/report-all", nil))

	if firstIP != "1.1.1.1" {
		t.Fatalf("first submitted IP = %q, want stronger current target 1.1.1.1", firstIP)
	}
}

// A high-scoring HASSH cluster is not evidence against each of its IPs. Its
// weak target row must not mask independent, confirmed journal observations.
func TestAbuseIPDBReportSelectsTargetSourceEvidence(t *testing.T) {
	for _, batch := range []bool{false, true} {
		name := "single"
		if batch {
			name = "batch"
		}
		t.Run(name, func(t *testing.T) {
			var posts atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts.Add(1)
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				if r.Method != http.MethodPost || r.Form.Get("ip") != "8.8.8.8" {
					t.Errorf("unexpected report: %s %v", r.Method, r.Form)
				}
				_, _ = w.Write([]byte(`{"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":70}}`))
			}))
			defer upstream.Close()
			st, keys := seedReportSources(t, false)
			s := New(st, keys, "127.0.0.1:0", Options{AbuseReportEnabled: true,
				AbuseEndpoint: upstream.URL, AbuseMinProbe: 60, AbuseRewindowHours: 24})
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/intel/abuseipdb/report?ip=8.8.8.8", nil)
			if batch {
				s.handleAbuseIPDBReportAll(rec, req)
			} else {
				s.handleAbuseIPDBReport(rec, req)
			}
			if posts.Load() != 1 {
				t.Fatalf("got %d reports; journal evidence was masked: %s", posts.Load(), rec.Body.String())
			}
			if recorded, err := st.AbuseIPDBReported("8.8.8.8", 24*time.Hour); err != nil || !recorded {
				t.Fatalf("successful report not recorded: %v, %v", recorded, err)
			}
		})
	}
}

func TestAbuseIPDBSuggestionsDeduplicateTargetSources(t *testing.T) {
	st, keys := seedReportSources(t, true)
	s := New(st, keys, "127.0.0.1:0", Options{AbuseMinProbe: 60})
	rec := httptest.NewRecorder()
	s.handleAbuseIPDBSuggestions(rec, httptest.NewRequest(http.MethodGet, "/api/intel/abuseipdb/suggestions", nil))
	var got suggestionsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v: %s", err, rec.Body.String())
	}
	if got.Total != 1 || got.Returned != 1 {
		t.Fatalf("one IP must appear once, not once per source: %+v", got)
	}
	if got.Suggestions[0].EventCount != 400 || got.Suggestions[0].UniqueUsers != 4 {
		t.Fatalf("source counts combined or borrowed from cluster: %+v", got.Suggestions[0])
	}
}

func seedReportSources(t *testing.T, bothStrong bool) (*store.Store, *settings.Keystore) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "source-evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Set(settings.KeyAbuseIPDB, "test-key"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Second)
	var aggs []*models.AggregatedActor
	var events []*models.Event
	for _, source := range []models.Source{models.SourceJournal, models.SourceCowrie} {
		a := &models.Actor{ID: string(source) + ":8.8.8.8", Source: source, PrimaryIP: "8.8.8.8",
			FirstSeen: now.Add(-time.Hour), LastSeen: now, Playbook: "dictionary_spray",
			ProbeScore: 60, EventCount: 400, UniqueUsers: 4, AttemptsPerHour: 400}
		if source == models.SourceCowrie {
			a.ID = "cowrie:shared-hassh"
			a.ProbeScore, a.EventCount, a.UniqueUsers = 100, 90000, 500
		}
		aggs = append(aggs, &models.AggregatedActor{Actor: a})
		n := 400
		if source == models.SourceCowrie && !bothStrong {
			n = 1
		}
		for i := 0; i < n; i++ {
			e := &models.Event{TS: now.Add(-time.Duration(i) * time.Second), Source: source,
				ActorID: a.ID, SrcIP: a.PrimaryIP, Kind: models.KindFailedPass,
				Username: []string{"root", "admin", "postgres", "oracle"}[i%4]}
			if n == 1 {
				e.Kind, e.Username = models.KindConnect, ""
			}
			events = append(events, e)
		}
	}
	if err := st.AppendEventsAndUpsertActorsAgg(events, aggs); err != nil {
		t.Fatal(err)
	}
	return st, keys
}
