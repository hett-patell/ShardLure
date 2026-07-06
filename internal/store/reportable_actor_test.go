package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// TestGetReportableActorByIP guards the actor-duality bug: one IP can have both
// a cowrie and a journal actor row (the two ingest paths cluster
// independently). GetActorByPrimaryIP picks by last_seen and can return a
// low-signal "unknown" cowrie row while the journal row for the SAME IP is a
// confirmed brute-forcer — which made the suggestions widget (which surfaced
// the journal row) disagree with the report endpoint (which fetched the cowrie
// row and vet-rejected it). GetReportableActorByIP must pick the high-signal
// row so the two paths agree.
func TestGetReportableActorByIP(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "dual.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ip := "14.63.192.228"
	older := time.Date(2026, 7, 3, 5, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 7, 4, 6, 0, 0, 0, time.UTC)

	// journal row: confirmed brute-forcer, OLDER last_seen.
	journal := &models.AggregatedActor{
		Actor: &models.Actor{
			ID: "journal:" + ip, Source: models.SourceJournal, PrimaryIP: ip,
			Playbook: "service_account_enum", ProbeScore: 60, EventCount: 321,
			UniqueUsers: 93, AttemptsPerHour: 2, FirstSeen: older, LastSeen: older,
		},
	}
	// cowrie row: low-signal "unknown", NEWER last_seen.
	cowrie := &models.AggregatedActor{
		Actor: &models.Actor{
			ID: "cowrie:" + ip, Source: models.SourceCowrie, PrimaryIP: ip,
			Playbook: "unknown", ProbeScore: 40, EventCount: 12,
			UniqueUsers: 0, AttemptsPerHour: 0, FirstSeen: newer, LastSeen: newer,
		},
	}
	if err := st.AppendEventsAndUpsertActorsAgg(nil, []*models.AggregatedActor{journal, cowrie}); err != nil {
		t.Fatal(err)
	}

	// GetActorByPrimaryIP (last_seen order) picks the low-signal cowrie row —
	// this is the behaviour that caused the bug.
	byRecent, err := st.GetActorByPrimaryIP(ip)
	if err != nil {
		t.Fatal(err)
	}
	if byRecent.Playbook != "unknown" {
		t.Logf("note: GetActorByPrimaryIP returned %q (bug repro expects the newer 'unknown' row)", byRecent.Playbook)
	}

	// GetReportableActorByIP must pick the confirmed brute-force journal row.
	best, err := st.GetReportableActorByIP(ip)
	if err != nil {
		t.Fatal(err)
	}
	if best.Playbook != "service_account_enum" {
		t.Fatalf("GetReportableActorByIP picked %q (probe %d); want the service_account_enum row (probe 60)", best.Playbook, best.ProbeScore)
	}
	if best.ProbeScore != 60 || best.EventCount != 321 {
		t.Fatalf("wrong row: probe=%d events=%d", best.ProbeScore, best.EventCount)
	}
}
