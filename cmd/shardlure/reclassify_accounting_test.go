package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

// An actor row whose events retention already purged cannot be re-derived:
// there is nothing left to re-scan. cmdReclassify put those rows on the legacy
// re-scan path, got no aggregate back, and `continue`d past them without
// touching a counter — so the printed summary silently failed to add up
// ("4 changed, 4922 unchanged, 0 without state of 5029 actors" on prod, with
// 103 actors unaccounted for and no way for an operator to know).
func TestPlanReclassifyAccountsForEveryCowrieActor(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "reclassify.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()

	// Rebuildable: flags persisted (schema v18), so its aggregate seeds from
	// the stored state without needing events.
	rebuildable := &models.Actor{
		ID: "cowrie:1.1.1.1", Source: models.SourceCowrie, PrimaryIP: "1.1.1.1",
		Playbook: "unknown", Intent: "probe", EventCount: 12, UniqueUsers: 3,
		Flags:     models.ActorFlagProbe | models.ActorFlagAuth,
		FirstSeen: now.Add(-48 * time.Hour), LastSeen: now.Add(-time.Hour),
	}
	if err := st.UpsertActor(rebuildable); err != nil {
		t.Fatalf("upsert rebuildable: %v", err)
	}

	// Orphan: pre-v18 row (flags=0) claiming events that no longer exist.
	orphan := &models.Actor{
		ID: "cowrie:2.2.2.2", Source: models.SourceCowrie, PrimaryIP: "2.2.2.2",
		Playbook: "unknown", Intent: "unknown", EventCount: 4, Flags: 0,
		FirstSeen: now.Add(-120 * 24 * time.Hour), LastSeen: now.Add(-119 * 24 * time.Hour),
	}
	if err := st.UpsertActor(orphan); err != nil {
		t.Fatalf("upsert orphan: %v", err)
	}

	// A journal actor must be ignored entirely — it carries no event-mix flags.
	if err := st.UpsertActor(&models.Actor{
		ID: "journal:3.3.3.3", Source: models.SourceJournal, PrimaryIP: "3.3.3.3",
		Playbook: "opportunistic", EventCount: 9,
		FirstSeen: now.Add(-time.Hour), LastSeen: now,
	}); err != nil {
		t.Fatalf("upsert journal: %v", err)
	}

	plan, err := planReclassify(st, actor.AdminSet(nil))
	if err != nil {
		t.Fatalf("planReclassify: %v", err)
	}

	if plan.Total != 2 {
		t.Errorf("Total = %d, want 2 cowrie actors (journal must not be counted)", plan.Total)
	}
	if plan.Unrebuildable != 1 {
		t.Errorf("Unrebuildable = %d, want 1 (the orphan whose events were purged)", plan.Unrebuildable)
	}
	sum := len(plan.Changed) + plan.Unchanged + plan.MissingState + plan.Unrebuildable
	if sum != plan.Total {
		t.Errorf("counters sum to %d but Total is %d — %d actors unaccounted for",
			sum, plan.Total, plan.Total-sum)
	}
}
