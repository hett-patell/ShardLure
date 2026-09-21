package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestJournalV23UpgradeLeavesLegacyProfilesUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-journal.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	a := &models.Actor{ID: "journal:legacy", Source: models.SourceJournal, PrimaryIP: "198.51.100.1", EventCount: 1000, UniqueUsers: 200, FirstSeen: base, LastSeen: base, Notes: "legacy operator text", Campaigns: "legacy campaign", UsernameHash: "legacy fingerprint"}
	if err := s.UpsertActor(a); err != nil {
		t.Fatal(err)
	}
	// A partial schema-only migration may already have created the table. An
	// upgrade must not enumerate and insert every old actor at startup: missing
	// state already means unknown_history and needs no eager rewrite.
	if _, err := s.db.Exec(`DELETE FROM journal_summaries;
DELETE FROM schema_migrations WHERE version>=23;
ALTER TABLE actors DROP COLUMN generated_notes;
CREATE TRIGGER forbid_legacy_summary BEFORE INSERT ON journal_summaries WHEN NEW.actor_id='journal:legacy' BEGIN SELECT RAISE(ABORT,'eager legacy summary write'); END;`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.GetActor(a.ID)
	if err != nil || got.DerivedCurrent || got.Playbook != "unknown_history" || got.EventCount != 1000 || got.UniqueUsers != 200 || got.Notes != a.Notes || got.Campaigns != a.Campaigns {
		t.Fatalf("legacy profile changed: %+v err=%v", got, err)
	}
	var rawHash string
	if err := s.db.QueryRow("SELECT username_hash FROM actors WHERE id=?", a.ID).Scan(&rawHash); err != nil || rawHash != a.UsernameHash {
		t.Fatalf("legacy evidence erased %q err=%v", rawHash, err)
	}
}

func TestJournalCounterHydrationAllocationsDoNotFollowCorpus(t *testing.T) {
	s := newTestStore(t, "bounded-counters.db")
	const id = "journal:198.51.100.11"
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if err := s.UpsertJournalActorAtomic(&models.Actor{ID: id, Source: models.SourceJournal, PrimaryIP: "198.51.100.11", FirstSeen: base, LastSeen: base, EventCount: 6000, UniqueUsers: 6000}, "198.51.100.11", base, base, 6000, "", 0); err != nil {
		t.Fatal(err)
	}
	read := func() {
		c, err := s.LoadJournalCounters(context.Background(), id, "198.51.100.11")
		if err != nil || c.Count != 6000 || c.UniqueUsers != 6000 || !c.First.Equal(base) {
			t.Fatalf("counters=%+v err=%v", c, err)
		}
	}
	small := testing.AllocsPerRun(2, read)
	if err := s.WithTx(func(tx *sql.Tx) error {
		stmt, err := tx.Prepare("INSERT INTO actor_users(actor_id,username,count) VALUES(?,?,1)")
		if err != nil {
			return err
		}
		defer stmt.Close()
		for i := 0; i < 6000; i++ {
			if _, err := stmt.Exec(id, fmt.Sprintf("name-%05d", i)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	large := testing.AllocsPerRun(2, read)
	if large > small*3+200 {
		t.Fatalf("counter hydration loads username corpus: small=%.0f large=%.0f", small, large)
	}
	t.Logf("hydration allocations: no corpus %.0f; 6000 names %.0f", small, large)
	if got, err := s.LoadJournalCounters(context.Background(), "cowrie:other", "198.51.100.11"); err != nil || got.Count != 0 {
		t.Fatalf("cross-actor hydration=%+v err=%v", got, err)
	}
}

func TestJournalUnknownHistoryDoesNotBecomeExactAfterNewNames(t *testing.T) {
	s := newTestStore(t, "unknown-history.db")
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	a := &models.Actor{ID: "journal:198.51.100.2", Source: models.SourceJournal, PrimaryIP: "198.51.100.2", FirstSeen: base, LastSeen: base, EventCount: 1000, UniqueUsers: 200, UsernameHash: "old-uncertain", Playbook: "dictionary_spray", ProbeScore: 95, Notes: "legacy annotation"}
	if err := s.UpsertActor(a); err != nil {
		t.Fatal(err)
	}
	e := &models.Event{TS: base.Add(time.Hour), ActorID: a.ID, Source: models.SourceJournal, Kind: models.KindFailedPass, Username: "new-name", SrcIP: a.PrimaryIP}
	if _, err := s.AppendJournalEventAtomic(e, &JournalActorUpdate{Actor: a, Username: e.Username}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetActor(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DerivedCurrent || got.UsernameHash != "" || got.Playbook != "unknown_history" || got.EventCount != 1001 || got.UniqueUsers != 201 || got.Notes != "legacy annotation" {
		t.Fatalf("fabricated repaired history: %+v", got)
	}
	var storedHash string
	if err := s.db.QueryRow("SELECT username_hash FROM actors WHERE id=?", a.ID).Scan(&storedHash); err != nil || storedHash != "old-uncertain" {
		t.Fatalf("unverified stored evidence erased: hash=%q err=%v", storedHash, err)
	}
	ids, err := s.PendingJournalSummaries(context.Background(), 10)
	if err != nil || len(ids) != 0 {
		t.Fatalf("unknown history must not spin pending worker: %v %v", ids, err)
	}
	labels, err := s.CountsByPlaybook()
	if err != nil || len(labels) != 1 || labels[0].Label != "unknown_history" {
		t.Fatalf("distribution still advertises stale classification: %+v err=%v", labels, err)
	}
}

func TestJournalBatchWritersPreserveAnnotations(t *testing.T) {
	for _, mode := range []string{"replace-source", "append-rebuild", "upsert"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestStore(t, "annotations.db")
			now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
			for _, id := range []string{"journal:rewritten", "journal:annotation-only"} {
				a := &models.Actor{ID: id, Source: models.SourceJournal, PrimaryIP: "198.51.100.1", FirstSeen: now, LastSeen: now, Campaigns: "operator-campaign", Notes: "operator note"}
				if err := s.UpsertActor(a); err != nil {
					t.Fatal(err)
				}
			}
			aggs := []*models.AggregatedActor{{Actor: &models.Actor{ID: "journal:rewritten", Source: models.SourceJournal, PrimaryIP: "198.51.100.1", FirstSeen: now, LastSeen: now, EventCount: 1}, Users: map[string]int{"root": 1}, IPs: map[string]models.IPStat{"198.51.100.1": {Count: 1, First: now, Last: now}}}}
			var err error
			switch mode {
			case "replace-source":
				err = s.ReplaceSourceEventsAndActorsAgg(models.SourceJournal, nil, aggs)
			case "append-rebuild":
				err = s.AppendEventsAndReplaceActorsAgg(models.SourceJournal, nil, aggs)
			default:
				err = s.AppendEventsAndUpsertActorsAgg(nil, aggs)
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"journal:rewritten", "journal:annotation-only"} {
				a, err := s.GetActor(id)
				if err != nil || a.Campaigns != "operator-campaign" || a.Notes != "operator note" {
					t.Errorf("%s annotations=%+v err=%v", id, a, err)
				}
			}
		})
	}
}
