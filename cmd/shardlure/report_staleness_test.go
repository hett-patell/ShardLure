package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

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
		if d := c.LastSeen.Sub(clusterLast); d > -time.Second && d < time.Second {
			t.Fatalf("candidate LastSeen is the CLUSTER max (%v) — the fresh cluster-mate is "+
				"vouching for the dormant primary IP, and Vet will pass a report for an address "+
				"silent for 18 days", c.LastSeen)
		}
		if d := c.LastSeen.Sub(ipLast); d < -time.Second || d > time.Second {
			t.Fatalf("candidate LastSeen = %v, want the primary IP's own last observation %v", c.LastSeen, ipLast)
		}
	}
	if !found {
		t.Fatal("clustered actor missing from the candidate pool entirely")
	}
}
