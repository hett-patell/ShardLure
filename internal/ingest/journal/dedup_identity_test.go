package journal

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func TestBatchDedupPreservesParallelJournalAttempts(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "dedup.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := models.Event{TS: time.Now(), Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: "8.8.8.8", Username: "root", SrcPort: 123, Raw: "port 123"}
	second := base
	second.SrcPort = 124
	second.Raw = "port 124"
	third := base
	third.Raw = "port 123 repeated pid"
	fresh, _, err := batchDedupJournal(s, []*models.Event{&base, &second, &third, &base})
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != 3 {
		t.Fatalf("fresh=%d, want 3 distinct parallel attempts", len(fresh))
	}
	if err := s.AppendEventsAndUpsertActorsAgg(fresh, nil); err != nil {
		t.Fatal(err)
	}
	fresh, _, err = batchDedupJournal(s, []*models.Event{&base, &second, &third})
	if err != nil || len(fresh) != 0 {
		t.Fatalf("replay fresh=%d error=%v", len(fresh), err)
	}
}
