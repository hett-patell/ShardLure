package main

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/intel/abuseipdb"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func TestCollectReportCandidatesSelectsOneSourcePerIP(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "report-sources.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC().Add(-time.Second)
	for _, fixture := range []struct {
		ip           string
		source       models.Source
		count        int
		lifetimeRate float64
	}{
		{"8.8.8.8", models.SourceCowrie, 200, 9000},
		{"8.8.8.8", models.SourceJournal, 400, 1},
		{"1.1.1.1", models.SourceJournal, 800, 2},
	} {
		a := &models.Actor{ID: fmt.Sprintf("%s:%s", fixture.source, fixture.ip), Source: fixture.source,
			PrimaryIP: fixture.ip, ProbeScore: 100, Playbook: "fast_dictionary_spray",
			FirstSeen: now.Add(-time.Hour), LastSeen: now, EventCount: 90000, AttemptsPerHour: fixture.lifetimeRate}
		var events []*models.Event
		for i := 0; i < fixture.count; i++ {
			events = append(events, &models.Event{TS: now.Add(-time.Duration(i) * time.Second),
				Source: a.Source, ActorID: a.ID, SrcIP: a.PrimaryIP, Kind: models.KindFailedPass,
				Username: []string{"root", "admin", "postgres", "oracle"}[i%4]})
		}
		if err := st.AppendEventsAndUpsertActorsAgg(events, []*models.AggregatedActor{{Actor: a}}); err != nil {
			t.Fatal(err)
		}
	}
	cands, err := collectReportCandidates(st, 60)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 2 {
		t.Fatalf("one candidate per target IP required, got %+v", cands)
	}
	if cands[0].SrcIP != "1.1.1.1" || cands[0].EventCount != 800 {
		t.Fatalf("ranking used cluster/lifetime activity instead of current target evidence: %+v", cands)
	}
	if cands[1].SrcIP != "8.8.8.8" || cands[1].EventCount != 400 || cands[1].UniqueUsers != 4 {
		t.Fatalf("must select the stronger qualifying source, never combine counts: %+v", cands[1])
	}
}

func TestCollectReportCandidatesDoesNotPrefilterClusterScore(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "report-score.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC().Add(-time.Second)
	a := &models.Actor{ID: "journal:8.8.8.8", Source: models.SourceJournal,
		PrimaryIP: "8.8.8.8", ProbeScore: 1, Playbook: "unknown",
		FirstSeen: now.Add(-time.Hour), LastSeen: now, EventCount: 400}
	var events []*models.Event
	for i := 0; i < 400; i++ {
		events = append(events, &models.Event{TS: now.Add(-time.Duration(i) * time.Second),
			Source: a.Source, ActorID: a.ID, SrcIP: a.PrimaryIP, Kind: models.KindFailedPass,
			Username: []string{"root", "admin", "postgres", "oracle"}[i%4]})
	}
	if err := st.AppendEventsAndUpsertActorsAgg(events, []*models.AggregatedActor{{Actor: a}}); err != nil {
		t.Fatal(err)
	}
	cands, err := collectReportCandidates(st, 60)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 {
		t.Fatalf("got %d candidates; recent target evidence must reach Vet despite the stored score", len(cands))
	}
	if ok, reason := abuseipdb.Vet(cands[0], nil, 60, time.Now()); !ok {
		t.Fatalf("recent brute-force evidence rejected: %s (%+v)", reason, cands[0])
	}
}

// TestCollectReportCandidatesUsesPrimaryIPLastSeen pins the CLI half of the
// wrongful-report fix. The candidate's LastSeen must be the PRIMARY IP's own
// last observation (actor_ips), not actors.last_seen — which on a
// HASSH-clustered actor is the max across every IP in the cluster, and let a
// 4-day-old cluster-mate carry an 18-day-dormant primary IP through Vet's
// staleness gate (observed live: a 22-IP actor kept a 17.7d-silent primary IP
// reportable). A behavioural test, not an AST one: this seam is a data-source
// choice, and mutation showed a source-level guard on the sibling fix could be
// dodged by renaming.
func TestCollectReportCandidatesUsesPrimaryIPLastSeen(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "cli-staleness.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	ipLast := now.Add(-18 * 24 * time.Hour)     // the primary IP's truth
	clusterLast := now.Add(-4 * 24 * time.Hour) // the fresh cluster-mate's

	agg := &models.AggregatedActor{
		Actor: &models.Actor{
			ID: "cowrie:cafebabecafebabecafebabecafebabe", Source: models.SourceCowrie,
			PrimaryIP: "45.33.107.21", Playbook: "fast_dictionary_spray",
			ProbeScore: 95, EventCount: 5000, UniqueUsers: 200, AttemptsPerHour: 40,
			FirstSeen: now.Add(-40 * 24 * time.Hour),
			LastSeen:  clusterLast,
		},
		IPs: map[string]models.IPStat{
			"45.33.107.21":  {First: now.Add(-40 * 24 * time.Hour), Last: ipLast, Count: 4000},
			"185.220.100.8": {First: now.Add(-10 * 24 * time.Hour), Last: clusterLast, Count: 1000},
		},
		Users: map[string]int{"root": 3000},
	}
	if err := st.AppendEventsAndUpsertActorsAgg(nil, []*models.AggregatedActor{agg}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cands, err := collectReportCandidates(st, 60)
	if err != nil {
		t.Fatalf("collectReportCandidates: %v", err)
	}
	var found bool
	for _, c := range cands {
		if c.SrcIP != "45.33.107.21" {
			continue
		}
		found = true
	}
	if found {
		t.Fatal("clustered actor entered the CLI candidate pool using its aggregate evidence; " +
			"the target IP has been silent for 18 days and must be excluded before report vetting")
	}
}
