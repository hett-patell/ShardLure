package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/intel/abuseipdb"
	"github.com/networkshard/shardlure/internal/netmatch"
	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/pkg/models"
)

func TestReportEvidenceCacheExpiresAndFailsClosed(t *testing.T) {
	st, keys := seedReportSources(t, false)
	s := New(st, keys, "127.0.0.1:0", Options{AbuseMinProbe: 60})
	ctx := context.Background()
	first, err := s.reportCandidateForIPCached(ctx, "8.8.8.8")
	if err != nil || first.EventCount != 400 {
		t.Fatalf("initial evidence: %+v %v", first, err)
	}
	// Closing the DB proves a fresh scan is not repeated on the warm read.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := s.reportCandidateForIPCached(ctx, "8.8.8.8")
	if err != nil || got != first {
		t.Fatalf("warm read rescanned or changed evidence: %+v %v", got, err)
	}
	// Policy is live, not cached: tightening it changes source selection.
	s.abuseAdmin = netmatch.New([]string{"8.8.8.8"})
	if ok, _ := abuseipdb.Vet(got, s.abuseAdmin, 60, time.Now()); ok {
		t.Fatal("cache bypassed current admin exclusion")
	}
	s.reportEvidenceMu.Lock()
	entry := s.reportEvidenceCache["8.8.8.8"]
	entry.at = time.Now().Add(-2 * statsTTL)
	s.reportEvidenceCache["8.8.8.8"] = entry
	s.reportEvidenceMu.Unlock()
	got, err = s.reportCandidateForIPCached(ctx, "8.8.8.8")
	if err == nil || got.EventCount != 0 {
		t.Fatalf("failed refresh returned stale qualifying evidence: %+v %v", got, err)
	}
}

func TestReportPostDoesNotTrustCachedEvidence(t *testing.T) {
	st, keys := seedReportSources(t, false)
	var posts atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":70}}`))
	}))
	defer upstream.Close()
	s := New(st, keys, "127.0.0.1:0", Options{AbuseMinProbe: 60, AbuseReportEnabled: true, AbuseEndpoint: upstream.URL})
	rec := httptest.NewRecorder()
	s.handleAbuseIPDBSuggestions(rec, httptest.NewRequest(http.MethodGet, "/api/intel/abuseipdb/suggestions", nil))
	var initial suggestionsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &initial); err != nil || initial.Total != 1 {
		t.Fatalf("warm suggestions: %s (%v)", rec.Body.String(), err)
	}
	if err := st.ReplaceSourceEventsAndActorsAgg(models.SourceJournal, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, batch := range []bool{false, true} {
		rec = httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/intel/abuseipdb/report?ip=8.8.8.8", nil)
		if batch {
			s.handleAbuseIPDBReportAll(rec, req)
		} else {
			s.handleAbuseIPDBReport(rec, req)
		}
		if posts.Load() != 0 {
			t.Fatalf("POST trusted cached evidence after source was removed: %s", rec.Body.String())
		}
	}
}

func TestReportEvidenceCacheWaitIsCancellable(t *testing.T) {
	st, keys := seedReportSources(t, false)
	s := New(st, keys, "127.0.0.1:0", Options{AbuseMinProbe: 60})
	s.reportEvidenceFlight = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := s.reportCandidateForIPCached(ctx, "8.8.8.8")
		result <- err
	}()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled wait: %v", err)
		}
	case <-time.After(time.Second):
		close(s.reportEvidenceFlight)
		t.Fatal("cancelled request remained blocked on evidence refresh")
	}
}

func TestReportEvidenceCacheBacksOffAfterRefreshError(t *testing.T) {
	st, keys := seedReportSources(t, false)
	s := New(st, keys, "127.0.0.1:0", Options{AbuseMinProbe: 60})
	wantErr := errors.New("previous evidence refresh failed")
	s.reportEvidenceCache = map[string]reportEvidenceEntry{
		"8.8.8.8": {at: time.Now(), used: time.Now(), err: wantErr},
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := s.reportCandidateForIPCached(context.Background(), "8.8.8.8")
	if !errors.Is(err, wantErr) {
		t.Fatalf("negative cache returned %v, want prior refresh error", err)
	}
	if got.EventCount != 0 {
		t.Fatalf("negative cache returned actionable stale evidence: %+v", got)
	}
}

func TestReportEvidenceCacheBoundsEvictsAndRechecksPolicy(t *testing.T) {
	st, keys := seedReportSources(t, false)
	s := New(st, keys, "127.0.0.1:0", Options{AbuseMinProbe: 60})
	now := time.Now()
	s.reportEvidenceCache = make(map[string]reportEvidenceEntry)
	for i := 0; i < maxReportEvidenceEntries; i++ {
		s.reportEvidenceCache[fmt.Sprint(i)] = reportEvidenceEntry{at: now, used: now}
	}
	entry := s.reportEvidenceCache["0"]
	entry.used = now.Add(-time.Hour)
	s.reportEvidenceCache["0"] = entry
	if _, err := s.reportCandidateForIPCached(context.Background(), "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if len(s.reportEvidenceCache) > maxReportEvidenceEntries {
		t.Fatalf("unbounded evidence cache: %d", len(s.reportEvidenceCache))
	}
	if _, exists := s.reportEvidenceCache["0"]; exists {
		t.Fatal("least recently used evidence not evicted")
	}
	// Pin two independent sources in cache. A live policy change must select
	// the remaining allowed source without needing a refresh.
	strong := abuseipdb.ReportCandidate{SrcIP: "8.8.8.8", Playbook: "dictionary_spray",
		ProbeScore: 70, EventCount: 5000, UniqueUsers: 50, AttemptsPerHour: 500, LastSeen: now}
	strict := abuseipdb.ReportCandidate{SrcIP: "8.8.8.8", Playbook: "service_account_enum",
		ProbeScore: 90, EventCount: 20, UniqueUsers: 3, LastSeen: now}
	s.reportEvidenceCache["8.8.8.8"] = reportEvidenceEntry{at: now, used: now,
		candidates: [2]abuseipdb.ReportCandidate{strong, strict}}
	first, err := s.reportCandidateForIPCached(context.Background(), "8.8.8.8")
	if err != nil || first.ProbeScore != 70 {
		t.Fatalf("initial priority: %+v %v", first, err)
	}
	if err := keys.Set(settings.KeyAbuseMinProbe, "80"); err != nil {
		t.Fatal(err)
	}
	second, err := s.reportCandidateForIPCached(context.Background(), "8.8.8.8")
	if err != nil || second.ProbeScore != 90 {
		t.Fatalf("cached policy decision ignored current floor: %+v %v", second, err)
	}
}
