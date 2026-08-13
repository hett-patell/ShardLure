package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

// seedClusteredActor builds the production shape behind the wrongful-report
// bug: a HASSH-clustered actor whose actors.last_seen is fresh (a cluster-mate
// spoke 4 days ago) while its PRIMARY IP — the address a report would name —
// has been silent for 18 days.
func seedClusteredActor(t *testing.T, st *store.Store) {
	t.Helper()
	now := time.Now().UTC()
	agg := &models.AggregatedActor{
		Actor: &models.Actor{
			ID: "cowrie:feedfacefeedfacefeedfacefeedface", Source: models.SourceCowrie,
			PrimaryIP: "45.33.107.20", Playbook: "fast_dictionary_spray",
			ProbeScore: 95, EventCount: 5000, UniqueUsers: 200, AttemptsPerHour: 40,
			FirstSeen: now.Add(-40 * 24 * time.Hour),
			LastSeen:  now.Add(-4 * 24 * time.Hour), // cluster max — the trap
		},
		IPs: map[string]models.IPStat{
			"45.33.107.20":  {First: now.Add(-40 * 24 * time.Hour), Last: now.Add(-18 * 24 * time.Hour), Count: 4000},
			"185.220.100.9": {First: now.Add(-10 * 24 * time.Hour), Last: now.Add(-4 * 24 * time.Hour), Count: 1000},
		},
		Users: map[string]int{"root": 3000},
	}
	if err := st.AppendEventsAndUpsertActorsAgg(nil, []*models.AggregatedActor{agg}); err != nil {
		t.Fatalf("seed clustered actor: %v", err)
	}
}

// TestSuggestionsGateStalenessPerIPNotPerCluster is the regression test for the
// wrongful-report bug found live: the suggestions widget offered 163.7.1.218,
// dormant 17.7 days, because the candidate carried the actor's last_seen — the
// max across a 22-IP HASSH cluster — while the report subject was the primary
// IP. A fresh cluster-mate must not be able to vouch for a dormant address.
func TestSuggestionsGateStalenessPerIPNotPerCluster(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "staleness.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatalf("settings.Load: %v", err)
	}
	seedClusteredActor(t, st)

	s := New(st, keys, "127.0.0.1:0", Options{
		AbuseReportEnabled: true,
		AbuseMinProbe:      60,
		AbuseRewindowHours: 24,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/intel/abuseipdb/suggestions?limit=10", nil)
	s.handleAbuseIPDBSuggestions(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("suggestions status = %d", rec.Code)
	}
	var got suggestionsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, sg := range got.Suggestions {
		if sg.SrcIP == "45.33.107.20" {
			t.Fatalf("suggestions offered 45.33.107.20, whose own last activity is 18d old — "+
				"the 4d-old cluster-mate is vouching for it. Total=%d body=%s", got.Total, rec.Body.String())
		}
	}
	if got.Total != 0 {
		t.Fatalf("vetted total = %d, want 0 — the only candidate's primary IP is dormant", got.Total)
	}
}

// TestReportEndpointGatesStalenessPerIP pins the single-IP report path the
// same way: POSTing a report for the clustered actor's primary IP must be
// refused by Vet (dormant), not sent upstream.
func TestReportEndpointGatesStalenessPerIP(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":100}}`))
	}))
	defer upstream.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "staleness-report.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatalf("settings.Load: %v", err)
	}
	if err := keys.Set(settings.KeyAbuseIPDB, "test-key"); err != nil {
		t.Fatalf("set key: %v", err)
	}
	seedClusteredActor(t, st)

	s := New(st, keys, "127.0.0.1:0", Options{
		AbuseReportEnabled: true,
		AbuseEndpoint:      upstream.URL,
		AbuseMinProbe:      60,
		AbuseRewindowHours: 24,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/intel/abuseipdb/report?ip=45.33.107.20", nil)
	s.handleAbuseIPDBReport(rec, req)

	if upstreamHit {
		t.Fatal("the report endpoint POSTed upstream for an 18d-dormant primary IP — " +
			"the cluster-mate's freshness carried it through the staleness gate")
	}
	if rec.Code == http.StatusOK {
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if body["status"] == "reported" {
			t.Fatalf("report claimed success for a dormant IP: %s", rec.Body.String())
		}
	}
}
