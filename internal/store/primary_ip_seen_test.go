package store

import (
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// seedClusterFixture reproduces the shape that made the staleness gate fail in
// production: one HASSH-clustered actor spanning several IPs, whose PRIMARY IP
// went quiet weeks ago while a cluster-mate is fresh. actors.last_seen is the
// cluster max (fresh), actor_ips carries the per-IP truth.
func seedClusterFixture(t *testing.T, st *Store) (actorID string, now time.Time) {
	t.Helper()
	now = time.Now().UTC()
	actorID = "cowrie:deadbeefdeadbeefdeadbeefdeadbeef"

	a := &models.Actor{
		ID: actorID, Source: models.SourceCowrie, PrimaryIP: "203.0.113.10",
		EventCount: 500, UniqueUsers: 40, AttemptsPerHour: 20,
		ProbeScore: 90, Playbook: "fast_dictionary_spray",
		FirstSeen: now.Add(-40 * 24 * time.Hour),
		// Cluster max: the FRESH cluster-mate's timestamp, NOT the primary IP's.
		LastSeen: now.Add(-4 * 24 * time.Hour),
	}
	agg := &models.AggregatedActor{
		Actor: a,
		IPs: map[string]models.IPStat{
			// The primary IP: dormant for 18 days.
			"203.0.113.10": {First: now.Add(-40 * 24 * time.Hour), Last: now.Add(-18 * 24 * time.Hour), Count: 400},
			// A cluster-mate seen 4 days ago — this is what actors.last_seen echoes.
			"198.51.100.7": {First: now.Add(-10 * 24 * time.Hour), Last: now.Add(-4 * 24 * time.Hour), Count: 100},
		},
		Users: map[string]int{"root": 300},
	}
	if err := st.AppendEventsAndUpsertActorsAgg(nil, []*models.AggregatedActor{agg}); err != nil {
		t.Fatalf("seed cluster: %v", err)
	}
	return actorID, now
}

// TestPrimaryIPLastSeenIsPerIPNotClusterMax is the store half of the
// wrongful-report fix: the map must answer for the PRIMARY IP, which here is
// 14 days older than the actor row's own last_seen.
func TestPrimaryIPLastSeenIsPerIPNotClusterMax(t *testing.T) {
	st := newTestStore(t, "ipseen.db")
	actorID, now := seedClusterFixture(t, st)

	m, err := st.PrimaryIPLastSeen()
	if err != nil {
		t.Fatalf("PrimaryIPLastSeen: %v", err)
	}
	got, ok := m[actorID]
	if !ok {
		t.Fatal("actor missing from PrimaryIPLastSeen map despite having an actor_ips row for its primary IP")
	}
	wantIP := now.Add(-18 * 24 * time.Hour)
	clusterMax := now.Add(-4 * 24 * time.Hour)
	if diff := got.Sub(wantIP); diff < -time.Second || diff > time.Second {
		if got.Sub(clusterMax) < time.Second && got.Sub(clusterMax) > -time.Second {
			t.Fatalf("PrimaryIPLastSeen returned the CLUSTER max (%v) — a fresh cluster-mate "+
				"is vouching for a dormant primary IP, which is the wrongful-report bug", got)
		}
		t.Fatalf("PrimaryIPLastSeen = %v, want the primary IP's own last_seen %v", got, wantIP)
	}
}

// TestPrimaryIPLastSeenOmitsUncoveredActors pins the fail-closed contract: an
// actor with no actor_ips row for its primary IP is ABSENT from the map, so a
// caller indexing it gets time.Time{}, which abuseipdb.Vet hard-rejects. The
// failure mode of missing data must be a refused report, never a wrongful one.
func TestPrimaryIPLastSeenOmitsUncoveredActors(t *testing.T) {
	st := newTestStore(t, "ipseen-missing.db")
	now := time.Now().UTC()
	// Actor row only — no actor_ips children (UpsertActor writes just actors).
	if err := st.UpsertActor(&models.Actor{
		ID: "journal:5.5.5.5", Source: models.SourceJournal, PrimaryIP: "5.5.5.5",
		EventCount: 100, UniqueUsers: 10, ProbeScore: 80, Playbook: "fast_dictionary_spray",
		FirstSeen: now.Add(-time.Hour), LastSeen: now,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	m, err := st.PrimaryIPLastSeen()
	if err != nil {
		t.Fatalf("PrimaryIPLastSeen: %v", err)
	}
	if got, ok := m["journal:5.5.5.5"]; ok {
		t.Fatalf("uncovered actor present in map with %v — where did the observation come from?", got)
	}
	if !m["journal:5.5.5.5"].IsZero() {
		t.Fatal("indexing a missing actor must yield the zero time for Vet to reject")
	}
}
