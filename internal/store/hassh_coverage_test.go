package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// TestHASSHCoverage verifies the identity-over-IP coverage metric: how many
// actors are keyed by behavioural fingerprint vs. total actors.
func TestHASSHCoverage(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "cov.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	agg := []*models.AggregatedActor{
		{Actor: &models.Actor{ID: "cowrie:aa:bb", Source: models.SourceCowrie, PrimaryIP: "1.1.1.1", HASSH: "aa:bb", FirstSeen: now, LastSeen: now, EventCount: 3}},
		{Actor: &models.Actor{ID: "cowrie:2.2.2.2", Source: models.SourceCowrie, PrimaryIP: "2.2.2.2", FirstSeen: now, LastSeen: now, EventCount: 2}},
		{Actor: &models.Actor{ID: "journal:3.3.3.3", Source: models.SourceJournal, PrimaryIP: "3.3.3.3", FirstSeen: now, LastSeen: now, EventCount: 1}},
	}
	if err := st.AppendEventsAndUpsertActorsAgg(nil, agg); err != nil {
		t.Fatal(err)
	}

	fp, total, err := st.HASSHCoverage()
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}
	if fp != 1 {
		t.Fatalf("fingerprinted = %d, want 1 (only the hassh-keyed actor)", fp)
	}
}
